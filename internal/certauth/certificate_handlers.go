package certauth

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"regexp"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/jpath"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"

	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

const (
	certLoginEndpoint                    = "/cert/login"
	CertificateBackEndpoint              = "/certificate-back"
	sendEmailVerificationEndpoint        = "/request-email-verification"
	verifyEmailCodeEndpoint              = "/verify-email-code"
	presentContractForAcceptanceEndpoint = "/present-contract-for-acceptance"
	contractAcceptedEndpoint             = "/contract-accepted"
)

func (s *Server) registerCertificateHandlers() {

	// Presents a screen informing the user that a certificate will be requested.
	s.httpServer.Get(certLoginEndpoint, s.pageCertLogin)

	// Redirected from CertSec after the user has provided a certificate.
	// Presents a screen with the certificate data and requests the email from the user.
	s.httpServer.Get(CertificateBackEndpoint, s.pageRequestEmail)

	// Receives the email address and sends an email to the user to verify if the email is correct.
	// Presents a screen to allow the user to enter the verification code sent to its email.
	s.httpServer.Post(sendEmailVerificationEndpoint, s.sendEmailVerification)

	// Receives the email verification code and verifies it.
	// Presents the contract text with an embedded form so the user can fill missing data.
	s.httpServer.Post(verifyEmailCodeEndpoint, s.verifyEmailCodeAndPresentContractForm)
	s.httpServer.Post(presentContractForAcceptanceEndpoint, s.pagePresentContractForAcceptance)

	// Handle consent received, generation of SSO cookie and redirection to Relying Party
	s.httpServer.Post(contractAcceptedEndpoint, s.handleContractAccepted)

}

// pageCertLogin shows the certificate selection screen
func (s *Server) pageCertLogin(c *fiber.Ctx) error {
	slog.Info("CertLoginPage", "from", c.Hostname(), "to", c.IP())

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("code"))
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Present the screen informing the user about the next step
	return s.htmlRender.Render(c, "cert_1_select", fiber.Map{
		"authCode":   authProcess.Code,
		"certsecURL": s.certSecURL,
	})

}

// pageRequestEmail is invoked from CertSec via HTTP redirection.
// When CertSec receives the certificate from the user's browser, it sets the CertificateData field in the AuthProcess entry
// corresponding to the current authentication process.
// Then CerSec redirects back to us (CertAuth) with the 'code' and possibly an 'error' parameter in the URL
func (s *Server) pageRequestEmail(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}
	slog.Info("Certificate received entry", "auth_code", authCode)

	// Check if CertSec returned some error
	certError := c.Query("error")
	if certError != "" || authProcess.ErrorInProcess != nil {
		err := authProcess.ErrorInProcess
		slog.Error("Error:", "error", err)
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": err,
		})
	}

	// Get the certificate data that was set by the certificate authentication process
	certData := authProcess.CertificateData

	// Validate the certificate data
	if certData == nil {
		return errl.Errorf("certificate data is nil")
	}

	_, err = VerifyCertificate(certData.CertificateDER, s.euDSSURL)
	if err == nil {
		certData.EIDASCertificate = true
	}

	// Check if the organization is already registered
	email, contractForm, _, err := s.db.GetRegistration(certData.OrganizationID)
	if err != nil {
		return errl.Errorf("error retrieving registration email: %w", err)
	}

	if email != "" {

		// The organization is already registered, bypass certificate and email validation

		// Bypass certificate selection and return directly to caller
		slog.Debug("bypass certificate selection", "code", authProcess.Code, "redirect_uri", authProcess.RedirectURI)

		// Store email of the user in the authProcess struct
		authProcess.Email = email
		authProcess.SignedAnnex = contractForm.Annex

		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}

		return c.Redirect(redirectURL, fiber.StatusFound)

	}

	// Otherwise, we present the certificate data to the user and must request and validate its email
	slog.Info("Certificate received exit", "auth_code", authCode, "cert_length", len(certData.Certificate.Raw))

	// Present the screen
	return s.htmlRender.Render(c, "cert_2_received", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certData":    certData,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"postAction":  sendEmailVerificationEndpoint,
	})

}

type EUDSSVerifyCertificateRequest struct {
	Certificate struct {
		EncodedCertificate string `json:"encodedCertificate"`
	} `json:"certificate"`
	TokenExtractionStrategy string `json:"tokenExtractionStrategy"`
}

// VerifyCertificate verifies a certificate using the EUDSS service.
func VerifyCertificate(data string, url string) ([]byte, error) {
	req := EUDSSVerifyCertificateRequest{
		Certificate: struct {
			EncodedCertificate string `json:"encodedCertificate"`
		}{
			EncodedCertificate: data,
		},
		TokenExtractionStrategy: "NONE",
	}

	jsonReq, err := json.Marshal(req)
	if err != nil {
		return nil, errl.Errorf("failed to marshal EUDSS request: %w", err)
	}

	// We use a timeout of 30 seconds
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, errl.Errorf("failed to send EUDSS request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errl.Errorf("EUDSS request failed with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errl.Errorf("failed to read EUDSS response: %w", err)
	}

	// Parse response as a map[string]any
	var respMap map[string]any
	if err := json.Unmarshal(body, &respMap); err != nil {
		return nil, errl.Errorf("failed to unmarshal EUDSS response: %w", err)
	}

	// Get the simpleCertificateReport object
	simpleCertificateReport := jpath.GetMap(respMap, "simpleCertificateReport")
	if simpleCertificateReport == nil {
		return nil, errl.Errorf("simpleCertificateReport not found in EUDSS response")
	}

	// Get the ChainItem array
	chainItemArray := jpath.GetList(simpleCertificateReport, "ChainItem")
	if chainItemArray == nil {
		return nil, errl.Errorf("ChainItem not found in EUDSS response")
	}

	// All objects of the list must have a field "Indication": "PASSED"
	for _, chainItem := range chainItemArray {
		indication := jpath.GetString(chainItem, "Indication")
		if indication != "PASSED" {
			// Get the subject object
			subject := jpath.GetMap(chainItem, "subject")
			// Log the subject
			out, _ := json.Marshal(subject)
			slog.Error("Validation error for certificate", "subject", string(out))
			return nil, errl.Errorf("validation error for certificate %s", string(out))
		}
	}

	return body, nil
}

// sendEmailVerification handles the email verification form submission
func (s *Server) sendEmailVerification(c *fiber.Ctx) error {
	// Get form data
	email := utils.CopyString(c.FormValue("email"))
	authCode := c.FormValue("auth_code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	if email == "" || authCode == "" {
		err := errl.Errorf("Missing email or authorization code")
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Basic email format validation
	if !isValidEmail(email) {
		err := errl.Errorf("Invalid email format")
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	slog.Info("Email verification requested", "email", email, "auth_code", authCode)

	certData := authProcess.CertificateData
	if certData == nil {
		err := errl.Errorf("certificate data not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Generate a random 6-digit verification code
	emailVerificationCode := generateRandomCode()

	// Waiting for verification of the email address
	authProcess.Email = email
	authProcess.EmailVerificationCode = emailVerificationCode

	slog.Info("Verification code generated", "code", emailVerificationCode, "auth_code", authCode)

	// Send the actual email
	err = s.emailService.SendVerificationEmail(email, emailVerificationCode)
	if err != nil {
		err := errl.Errorf("sendVerificationEmail: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Render the confirm_email template
	return s.htmlRender.Render(c, "cert_3_confirm_email", fiber.Map{
		"email":            email,
		"authCode":         authCode,
		"verificationCode": emailVerificationCode, // For testing - remove in production
		"subject":          certData.Subject,
		"postAction":       verifyEmailCodeEndpoint,
	})
}

// isValidEmail performs basic email format validation
func isValidEmail(email string) bool {
	// Simple regex for basic email validation
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(emailRegex, email)
	return matched
}

// generateRandomCode generates a random 6-digit verification code
func generateRandomCode() string {
	// Generate a random 6-digit number
	a, _ := rand.Int(rand.Reader, big.NewInt(999999))

	return fmt.Sprintf("%06d", a.Uint64())

}

// verifyEmailCodeAndPresentContractForm handles the email verification code verification,
// and presents the contract form to the user.
func (s *Server) verifyEmailCodeAndPresentContractForm(c *fiber.Ctx) error {
	// Get form data
	emailVerificationCode := utils.CopyString(c.FormValue("verification_code"))
	authCode := utils.CopyString(c.FormValue("auth_code"))
	email := utils.CopyString(c.FormValue("email"))

	if emailVerificationCode == "" || authCode == "" || email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing verification code, authorization code, or email",
		})
	}

	slog.Info("Email verification code verification requested", "email", email, "auth_code", authCode)

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	storedEmailVerificationCode := authProcess.EmailVerificationCode
	if storedEmailVerificationCode == "" {
		err := errl.Errorf("email verification code not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Verify the code
	if emailVerificationCode != storedEmailVerificationCode {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid verification code",
		})
	}

	slog.Info("Email verification code verified successfully", "email", email, "auth_code", authCode)

	storedEmail := authProcess.Email
	if storedEmail != email {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	certData := authProcess.CertificateData

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// Get the current date
	currentDate := time.Now()
	year := currentDate.Year()
	month := currentDate.Month()
	day := currentDate.Day()

	formData := models.ContractForm{
		TodayDay:            day,
		TodayMonth:          int(month),
		TodayYear:           year,
		OrganizationName:    certData.Subject.Organization,
		OrganizationCountry: certData.Subject.Country,
		OrganizationAddress: certData.Subject.StreetAddress,
		OrganizationNif:     certData.Subject.OrganizationIdentifier,
		RepresentativeName:  certData.Subject.CommonName,
		RepresentativeEmail: storedEmail,
	}

	// Render the certificate consent template
	return s.htmlRender.Render(c, "contract", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"formData":    formData,
		"postAction":  presentContractForAcceptanceEndpoint,
	})
}

func (s *Server) pagePresentContractForAcceptance(c *fiber.Ctx) error {

	// Data for checking the form is valid, before we do anything else
	authCode := utils.CopyString(c.FormValue("auth_code"))
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Parse the formData
	formData := models.ContractForm{}
	if err := c.BodyParser(&formData); err != nil {
		slog.Error("Failed to parse form", "error", err)
		return errl.Errorf("failed to parse form: %w", err)
	}

	// Check that we have the email of the representative
	if formData.RepresentativeEmail == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing representative email",
		})
	}

	slog.Info("Email verification code verification requested", "email", formData.RepresentativeEmail, "auth_code", authCode)

	// Sanity check, we already have an email and they have to be the same
	storedEmail := authProcess.Email
	if storedEmail != formData.RepresentativeEmail {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	certData := authProcess.CertificateData

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// Render the certificate consent template
	return s.htmlRender.Render(c, "contractprint", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"formData":    formData,
		"postAction":  contractAcceptedEndpoint,
	})

}

// handleContractAccepted is the last step, after the user has given consent to proceed.
// We then generate the SSO cookie and redirect to the RP with the auth code.
// The RP will eventually exchange the auth code for ID and access tokens, which will contain user and certificate data.
func (s *Server) handleContractAccepted(c *fiber.Ctx) error {

	// Data for checking the form is valid, before we do anything else
	authCode := utils.CopyString(c.FormValue("auth_code"))
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Parse the formData
	formData := models.ContractForm{}
	if err := c.BodyParser(&formData); err != nil {
		slog.Error("Failed to parse form", "error", err)
		return errl.Errorf("failed to parse form: %w", err)
	}

	// Check that we have the email of the representative
	if formData.RepresentativeEmail == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing representative email",
		})
	}

	slog.Info("Email verification code verification requested", "email", formData.RepresentativeEmail, "auth_code", authCode)

	// Sanity check, we already have an email and they have to be the same
	storedEmail := authProcess.Email
	if storedEmail != formData.RepresentativeEmail {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	// Store the company data in the registrations table
	if err := s.db.CreateRegistration(s.tsaService, authProcess.CertificateData, storedEmail, &formData); err != nil {
		err = errl.Errorf("creating registration: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})

	}

	// Update the auth process with the signed annex
	authProcess.SignedAnnex = formData.Annex

	fileToSend := []byte(contrato)

	// Notify the contract management system that the registration is complete
	if powers, err := s.notifyManagement(authProcess.CertificateData, storedEmail, &formData, fileToSend); err != nil {
		err = errl.Errorf("notifying management: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	} else {
		authProcess.Powers = powers
		slog.Info("Management notified successfully", "powers", powers)
	}

	// Generate a random unique identifier for the SSO session
	ssoSessionID := generateRandomString()

	// Create the SSO session data to be held in the server-side cache
	ssoSession := &models.SSOSession{
		SessionID:       ssoSessionID,
		Email:           storedEmail,
		CertificateData: authProcess.CertificateData,
	}

	// Store the SSO session in the cache (valid for 24 hours)
	s.cache.Set(ssoSessionID, ssoSession, 24*time.Hour)

	// Generate SSO cookie
	ssoCookie, err := s.generateSSOCookie(ssoSessionID, ssoSession.CertificateData)
	if err != nil {
		slog.Error("failed to generate sso cookie", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Set SSO cookie
	c.Cookie(ssoCookie)

	// Redirect (302) to RP with auth code
	slog.Info("User consent processed successfully", "email", storedEmail, "auth_code", authCode)
	// href="{{ .authCodeObj.RedirectURI }}?code={{ .authCode }}&state={{ .authCodeObj.State }}"
	redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authCode)
	if authProcess.State != "" {
		redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
	}

	return c.Redirect(redirectURL, fiber.StatusFound)

}

func (s *Server) notifyManagement(certData *models.CertificateData, email string, contractForm *models.ContractForm, fileToSend []byte) (string, error) {

	organizationIdentifier := contractForm.OrganizationNif

	// Structs for the data to be sent
	type Role struct {
		Principal bool `json:"principal"`
		Developer bool `json:"developer"`
		OpExec    bool `json:"op_exec"`
	}

	// OrganizationIdentifier and SelectedRole will be added as form fields.
	type requestBody struct {
		OrganizationIdentifier string `json:"organization_identifier"`
		SelectedRole           Role   `json:"selected_role"`
	}

	role := Role{
		Principal: true,
	}

	if contractForm.Annex == "developer" {
		role.Developer = true
	}

	if contractForm.Annex == "operator" {
		role.OpExec = true
	}

	// Prepare the multipart payload
	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)

	// 1. Add OrganizationIdentifier
	if err := writer.WriteField("organization_identifier", organizationIdentifier); err != nil {
		return "", fmt.Errorf("failed to write organization_identifier: %w", err)
	}

	// 2. Add SelectedRole
	// Using the example values from the comments as defaults
	roleBytes, err := json.Marshal(role)
	if err != nil {
		return "", fmt.Errorf("failed to marshal role: %w", err)
	}
	if err := writer.WriteField("selected_role", string(roleBytes)); err != nil {
		return "", fmt.Errorf("failed to write selected_role: %w", err)
	}

	// 3. Add Contract File (fileToSend). The file is an HTML file.
	// Using "contract" as the field name and "contract.html" as the filename
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "contract", "contract.html"))
	h.Set("Content-Type", "text/html")
	part, err := writer.CreatePart(h)
	if err != nil {
		return "", fmt.Errorf("failed to create form part: %w", err)
	}
	if _, err := part.Write(fileToSend); err != nil {
		return "", fmt.Errorf("failed to write file content: %w", err)
	}

	// Close the writer to finalize the boundary
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	slog.Info("Sending POST to main portal", "url", s.managementURL)

	// Do a DELETE request to delete the organization from the main portal
	deleteURL := s.managementURL + "/organization/" + organizationIdentifier
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create delete request: %w", err)
	}

	// Get the API key from the environment based on the profile
	apiKey := os.Getenv("MANAGEMENT_API_KEY")
	if apiKey == "" {
		// Try with the development API key. It is not a security exposure as the development environment is just local
		apiKey = "aa83b134-1a59-4ea3-b632-812f36d6b4c1"
	}
	deleteReq.Header.Set("X-Api-Key", apiKey)

	deleteClient := &http.Client{}
	deleteResp, err := deleteClient.Do(deleteReq)
	if err != nil {
		return "", fmt.Errorf("failed to send delete request: %w", err)
	}
	defer deleteResp.Body.Close()

	// Create and send the HTTP request
	req, err := http.NewRequest("POST", s.managementURL, bodyBuf)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("main portal returned non-success status: %d", resp.StatusCode)
	}

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse into a map[string]any
	var response map[string]any
	if err := json.Unmarshal(respBody, &response); err != nil {
		return "", fmt.Errorf("failed to parse response body: %w", err)
	}

	// Print the response map as a pretty-printed indented JSON
	jsonResponse, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response body: %w", err)
	}
	fmt.Println(string(jsonResponse))

	// Check if the response contains the proper fields

	receivedOrganizationIdentifier := jpath.GetString(response, "organization_identifier")
	if receivedOrganizationIdentifier != organizationIdentifier {
		return "", errl.Errorf("organization identifier mismatch: expected %s, got %s", organizationIdentifier, receivedOrganizationIdentifier)
	}

	receivedPowersString := jpath.GetString(response, "power")
	if receivedPowersString == "" {
		receivedPowersString = jpath.GetString(response, "powers")
	}
	if receivedPowersString == "" {
		return "", errl.Errorf("powers not received")
	}

	return receivedPowersString, nil
}
