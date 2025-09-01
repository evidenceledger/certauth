package certauth

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

// handleDiscovery handles OIDC discovery endpoint
func (s *Server) handleDiscovery(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"issuer":                                s.cfg.CertAuthURL,
		"authorization_endpoint":                s.cfg.CertAuthURL + "/oauth2/auth",
		"token_endpoint":                        s.cfg.CertAuthURL + "/oauth2/token",
		"userinfo_endpoint":                     s.cfg.CertAuthURL + "/oauth2/userinfo",
		"jwks_uri":                              s.cfg.CertAuthURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "eidas"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "given_name", "family_name", "email", "elsi_organization", "elsi_organization_identifier", "elsi_country"},
	})
}

// Authorization handles OAuth2 authorization endpoint
func (s *Server) Authorization(c *fiber.Ctx) error {
	slog.Info("Authorization request received",
		"client_id", c.Query("client_id"),
		"redirect_uri", c.Query("redirect_uri"))

	// Parse authorization request
	authReq := &models.AuthorizationRequest{
		ResponseType: c.Query("response_type"),
		ClientID:     c.Query("client_id"),
		RedirectURI:  c.Query("redirect_uri"),
		Scope:        c.Query("scope"),
		State:        c.Query("state"),
		Nonce:        c.Query("nonce"),
		CreatedAt:    time.Now(),
	}

	// Validate request
	if err := s.validateAuthorizationRequest(authReq); err != nil {
		return s.handleAuthorizationError(c, authReq, err)
	}

	// Get relying party
	rp, err := s.db.GetRelyingParty(authReq.ClientID)
	if err != nil {
		return s.handleAuthorizationError(c, authReq, errl.Errorf("database error: %w", err))
	}
	if rp == nil {
		return s.handleAuthorizationError(c, authReq, errl.Errorf("invalid client_id"))
	}

	// Validate redirect_uri matches registered RP redirect URL
	if authReq.RedirectURI != rp.RedirectURL {
		slog.Error("Redirect URI mismatch",
			"client_id", authReq.ClientID,
			"provided_redirect_uri", authReq.RedirectURI,
			"registered_redirect_url", rp.RedirectURL)
		return s.handleAuthorizationError(c, authReq, errl.Errorf("redirect_uri mismatch"))
	}

	// Check if certificate authentication is requested
	if strings.Contains(authReq.Scope, "eidas") {
		// Generate authorization code
		authCode := s.generateAuthCode(authReq, rp)

		// Store auth code
		if err := s.db.CreateAuthCode(authCode); err != nil {
			return s.handleAuthorizationError(c, authReq, errl.Errorf("failed to store auth code: %w", err))
		}

		// Redirect to certificate authentication
		redirectURL := s.cfg.CertAuthURL + "/certificate-select?code=" + authCode.Code
		return c.Status(fiber.StatusFound).Redirect(redirectURL)
	}

	// For non-eIDAS requests, return error
	return s.handleAuthorizationError(c, authReq, errl.Errorf("eidas scope required"))
}

// Token handles OAuth2 token endpoint
func (s *Server) Token(c *fiber.Ctx) error {
	slog.Info("Token request received")

	// Parse token request
	var tokenReq models.TokenRequest
	if err := c.BodyParser(&tokenReq); err != nil {
		return errl.Errorf("invalid request body: %w", err)
	}

	// Get authorization header
	auth := c.Get(fiber.HeaderAuthorization)

	// Check if the header contains content besides "basic".
	if len(auth) <= 6 || !utils.EqualFold(auth[:6], "basic ") {
		return errl.Errorf("invalid authorization header")
	}

	// Decode the header contents
	raw, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return errl.Errorf("invalid authorization header: %w", err)
	}

	// Get the credentials
	creds := utils.UnsafeString(raw)

	// Check if the credentials are in the correct form
	// which is "username:password".
	index := strings.Index(creds, ":")
	if index == -1 {
		return errl.Errorf("invalid authorization header")
	}

	// Get the username and password
	username := creds[:index]
	password := creds[index+1:]

	// Set the fields in tokenReq
	tokenReq.ClientID = username
	tokenReq.ClientSecret = password

	// Validate client credentials
	valid, err := s.db.ValidateClientSecret(username, password)
	if err != nil {
		slog.Error("Failed to validate client secret", "error", err)
		return errl.Errorf("internal error")
	}
	if !valid {
		return errl.Errorf("invalid client credentials")
	}

	// Get authorization code
	authCode, err := s.db.GetAuthCode(tokenReq.Code)
	if err != nil {
		return errl.Errorf("failed to get auth code: %w", err)
	}
	if authCode == nil {
		return errl.Errorf("invalid or expired authorization code")
	}

	// Validate auth code
	if authCode.ClientID != tokenReq.ClientID {
		return errl.Errorf("auth code client mismatch")
	}

	// Get relying party
	rp, err := s.db.GetRelyingParty(tokenReq.ClientID)
	if err != nil {
		return errl.Errorf("failed to get relying party: %w", err)
	}

	certDataAny, found := s.cache.Get(authCode.Code)
	if !found {
		return errl.Errorf("failed to get certificate data: %w", err)
	}

	certData, ok := certDataAny.(*models.CertificateData)
	if !ok {
		return errl.Errorf("invalid certificate data")
	}

	// Generate tokens with certificate data if available
	tokens, err := s.generateTokens(authCode, rp, certData)
	if err != nil {
		return errl.Errorf("failed to generate tokens: %w", err)
	}

	// Delete used auth code
	s.db.DeleteAuthCode(tokenReq.Code)

	slog.Info("Tokens generated successfully", "client_id", tokenReq.ClientID)

	return c.JSON(tokens)
}

// UserInfo handles OpenID Connect userinfo endpoint
func (s *Server) UserInfo(c *fiber.Ctx) error {
	// TODO: Implement userinfo with token validation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// Logout handles logout endpoint
func (s *Server) Logout(c *fiber.Ctx) error {
	// TODO: Implement logout (no-op for now)
	return c.JSON(fiber.Map{"status": "logged_out"})
}

// AdminDashboard handles admin dashboard
func (s *Server) AdminDashboard(c *fiber.Ctx) error {
	// TODO: Implement admin dashboard
	return c.SendStatus(fiber.StatusNotImplemented)
}

// ListRP lists all relying parties
func (s *Server) ListRP(c *fiber.Ctx) error {
	rps, err := s.db.ListRelyingParties()
	if err != nil {
		return errl.Errorf("failed to list relying parties: %w", err)
	}

	return c.JSON(rps)
}

// CreateRP creates a new relying party
func (s *Server) CreateRP(c *fiber.Ctx) error {
	// TODO: Implement RP creation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// UpdateRP updates an existing relying party
func (s *Server) UpdateRP(c *fiber.Ctx) error {
	// TODO: Implement RP update
	return c.SendStatus(fiber.StatusNotImplemented)
}

// DeleteRP deletes a relying party
func (s *Server) DeleteRP(c *fiber.Ctx) error {
	// TODO: Implement RP deletion
	return c.SendStatus(fiber.StatusNotImplemented)
}

// Helper methods

func (s *Server) validateAuthorizationRequest(req *models.AuthorizationRequest) error {
	if req.ResponseType != "code" {
		return errl.Errorf("unsupported response_type")
	}
	if req.ClientID == "" {
		return errl.Errorf("missing client_id")
	}
	if req.RedirectURI == "" {
		return errl.Errorf("missing redirect_uri")
	}
	if !strings.Contains(req.Scope, "openid") {
		return errl.Errorf("openid scope required")
	}
	if !strings.Contains(req.Scope, "eidas") {
		return errl.Errorf("eidas scope required")
	}
	return nil
}

func (s *Server) handleAuthorizationError(c *fiber.Ctx, req *models.AuthorizationRequest, err error) error {
	errorCode := "invalid_request"
	if strings.Contains(err.Error(), "client_id") {
		errorCode = "unauthorized_client"
	}

	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("error", errorCode)
	q.Set("error_description", err.Error())
	if req.State != "" {
		q.Set("state", req.State)
	}
	redirectURL.RawQuery = q.Encode()

	return c.Status(fiber.StatusFound).Redirect(redirectURL.String())
}

func (s *Server) generateAuthCode(req *models.AuthorizationRequest, rp *models.RelyingParty) *models.AuthCode {
	// Generate random code
	codeBytes := make([]byte, 32)
	rand.Read(codeBytes)
	code := base64.URLEncoding.EncodeToString(codeBytes)

	authCode := &models.AuthCode{
		Code:        code,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		State:       req.State,
		Nonce:       req.Nonce,
		Scope:       req.Scope,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	slog.Debug("Generated auth code", "code", authCode.Code, "client_id", authCode.ClientID, "redirect_uri", authCode.RedirectURI)
	return authCode
}

func (s *Server) generateTokens(authCode *models.AuthCode, rp *models.RelyingParty, certData *models.CertificateData) (map[string]interface{}, error) {
	if s.jwtService == nil {
		// Fallback to basic tokens if JWT service is not available
		accessToken := generateRandomToken()
		return map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        authCode.Scope,
			"id_token":     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...", // Placeholder
		}, nil
	}

	// If we have certificate data, generate real JWT tokens
	if certData != nil {
		// Generate ID token
		idToken, err := s.jwtService.GenerateIDToken(authCode, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate ID token: %w", err)
		}

		// Generate access token
		accessToken, err := s.jwtService.GenerateAccessToken(authCode, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate access token: %w", err)
		}

		slog.Info("Real JWT tokens generated with certificate data",
			"organization_id", certData.OrganizationID,
			"organization", certData.Subject.Organization,
		)

		return map[string]any{
			"access_token": accessToken.AccessToken,
			"token_type":   accessToken.TokenType,
			"expires_in":   accessToken.ExpiresIn,
			"scope":        accessToken.Scope,
			"id_token":     idToken,
		}, nil
	}

	// Fallback to basic tokens without certificate data
	accessToken := generateRandomToken()
	return map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   rp.TokenExpiry,
		"scope":        authCode.Scope,
		"id_token":     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...", // Placeholder for now
	}, nil
}

func generateRandomToken() string {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	return base64.URLEncoding.EncodeToString(tokenBytes)
}
