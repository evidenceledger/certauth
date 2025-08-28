package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/jwt"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/gofiber/fiber/v2"
)

// OIDCHandlers handles OIDC-related HTTP requests
type OIDCHandlers struct {
	db                    *database.Database
	jwtService            *jwt.Service
	certificateDataGetter func(string) *models.CertificateData
}

// NewOIDCHandlers creates new OIDC handlers
func NewOIDCHandlers(db *database.Database) *OIDCHandlers {
	return &OIDCHandlers{
		db: db,
	}
}

// SetJWTService sets the JWT service for token generation
func (h *OIDCHandlers) SetJWTService(jwtService *jwt.Service) {
	h.jwtService = jwtService
}

// SetCertificateDataGetter sets the function to retrieve certificate data
func (h *OIDCHandlers) SetCertificateDataGetter(getter func(string) *models.CertificateData) {
	h.certificateDataGetter = getter
}

// Discovery handles OIDC discovery endpoint
func (h *OIDCHandlers) Discovery(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"issuer":                                "https://certauth.mycredential.eu",
		"authorization_endpoint":                "https://certauth.mycredential.eu/oauth2/auth",
		"token_endpoint":                        "https://certauth.mycredential.eu/oauth2/token",
		"userinfo_endpoint":                     "https://certauth.mycredential.eu/oauth2/userinfo",
		"jwks_uri":                              "https://certauth.mycredential.eu/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "eidas"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "given_name", "family_name", "email", "elsi_organization", "elsi_organization_identifier", "elsi_country"},
	})
}

// JWKS handles JSON Web Key Set endpoint
func (h *OIDCHandlers) JWKS(c *fiber.Ctx) error {
	// TODO: Implement JWKS with JWT service
	return c.JSON(fiber.Map{"keys": []interface{}{}})
}

// Authorization handles OAuth2 authorization endpoint
func (h *OIDCHandlers) Authorization(c *fiber.Ctx) error {
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
	if err := h.validateAuthorizationRequest(authReq); err != nil {
		return h.handleAuthorizationError(c, authReq, err)
	}

	// Get relying party
	rp, err := h.db.GetRelyingParty(authReq.ClientID)
	if err != nil {
		return h.handleAuthorizationError(c, authReq, errl.Errorf("database error: %w", err))
	}
	if rp == nil {
		return h.handleAuthorizationError(c, authReq, errl.Errorf("invalid client_id"))
	}

	// Validate redirect_uri matches registered RP redirect URL
	if authReq.RedirectURI != rp.RedirectURL {
		slog.Error("Redirect URI mismatch",
			"client_id", authReq.ClientID,
			"provided_redirect_uri", authReq.RedirectURI,
			"registered_redirect_url", rp.RedirectURL)
		return h.handleAuthorizationError(c, authReq, errl.Errorf("redirect_uri mismatch"))
	}

	// Check if certificate authentication is requested
	if strings.Contains(authReq.Scope, "eidas") {
		// Generate authorization code
		authCode := h.generateAuthCode(authReq, rp)

		// Store auth code
		if err := h.db.CreateAuthCode(authCode); err != nil {
			return h.handleAuthorizationError(c, authReq, errl.Errorf("failed to store auth code: %w", err))
		}

		// Redirect to certificate authentication
		redirectURL := "https://certauth.mycredential.eu/certificate-select?code=" + authCode.Code
		return c.Status(fiber.StatusFound).Redirect(redirectURL)
	}

	// For non-eIDAS requests, return error
	return h.handleAuthorizationError(c, authReq, errl.Errorf("eidas scope required"))
}

// Token handles OAuth2 token endpoint
func (h *OIDCHandlers) Token(c *fiber.Ctx) error {
	slog.Info("Token request received")

	// Parse token request
	var tokenReq models.TokenRequest
	if err := c.BodyParser(&tokenReq); err != nil {
		return errl.Errorf("invalid request body: %w", err)
	}

	// Validate client credentials
	valid, err := h.db.ValidateClientSecret(tokenReq.ClientID, tokenReq.ClientSecret)
	if err != nil {
		slog.Error("Failed to validate client secret", "error", err)
		return errl.Errorf("internal error")
	}
	if !valid {
		return errl.Errorf("invalid client credentials")
	}

	// Get authorization code
	authCode, err := h.db.GetAuthCode(tokenReq.Code)
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
	rp, err := h.db.GetRelyingParty(tokenReq.ClientID)
	if err != nil {
		return errl.Errorf("failed to get relying party: %w", err)
	}

	// Get certificate data if available
	var certData *models.CertificateData
	if h.certificateDataGetter != nil {
		certData = h.certificateDataGetter(tokenReq.Code)
	}

	// Generate tokens with certificate data if available
	tokens, err := h.generateTokens(authCode, rp, certData)
	if err != nil {
		return errl.Errorf("failed to generate tokens: %w", err)
	}

	// Delete used auth code
	h.db.DeleteAuthCode(tokenReq.Code)

	slog.Info("Tokens generated successfully", "client_id", tokenReq.ClientID)

	return c.JSON(tokens)
}

// UserInfo handles OpenID Connect userinfo endpoint
func (h *OIDCHandlers) UserInfo(c *fiber.Ctx) error {
	// TODO: Implement userinfo with token validation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// Logout handles logout endpoint
func (h *OIDCHandlers) Logout(c *fiber.Ctx) error {
	// TODO: Implement logout (no-op for now)
	return c.JSON(fiber.Map{"status": "logged_out"})
}

// AdminDashboard handles admin dashboard
func (h *OIDCHandlers) AdminDashboard(c *fiber.Ctx) error {
	// TODO: Implement admin dashboard
	return c.SendStatus(fiber.StatusNotImplemented)
}

// ListRP lists all relying parties
func (h *OIDCHandlers) ListRP(c *fiber.Ctx) error {
	rps, err := h.db.ListRelyingParties()
	if err != nil {
		return errl.Errorf("failed to list relying parties: %w", err)
	}

	return c.JSON(rps)
}

// CreateRP creates a new relying party
func (h *OIDCHandlers) CreateRP(c *fiber.Ctx) error {
	// TODO: Implement RP creation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// UpdateRP updates an existing relying party
func (h *OIDCHandlers) UpdateRP(c *fiber.Ctx) error {
	// TODO: Implement RP update
	return c.SendStatus(fiber.StatusNotImplemented)
}

// DeleteRP deletes a relying party
func (h *OIDCHandlers) DeleteRP(c *fiber.Ctx) error {
	// TODO: Implement RP deletion
	return c.SendStatus(fiber.StatusNotImplemented)
}

// Helper methods

func (h *OIDCHandlers) validateAuthorizationRequest(req *models.AuthorizationRequest) error {
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

func (h *OIDCHandlers) handleAuthorizationError(c *fiber.Ctx, req *models.AuthorizationRequest, err error) error {
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

func (h *OIDCHandlers) generateAuthCode(req *models.AuthorizationRequest, rp *models.RelyingParty) *models.AuthCode {
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

func (h *OIDCHandlers) generateTokens(authCode *models.AuthCode, rp *models.RelyingParty, certData *models.CertificateData) (map[string]interface{}, error) {
	if h.jwtService == nil {
		// Fallback to basic tokens if JWT service is not available
		accessToken := generateRandomToken()
		return map[string]interface{}{
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
		idToken, err := h.jwtService.GenerateIDToken(authCode, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate ID token: %w", err)
		}

		// Generate access token
		accessToken, err := h.jwtService.GenerateAccessToken(authCode, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate access token: %w", err)
		}

		slog.Info("Real JWT tokens generated with certificate data",
			"organization_id", certData.OrganizationID,
			"organization", certData.Subject.Organization,
		)

		return map[string]interface{}{
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
