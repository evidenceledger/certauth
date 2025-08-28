package certauth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/handlers"
	"github.com/evidenceledger/certauth/internal/jwt"
	"github.com/evidenceledger/certauth/internal/middleware"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/internal/templates"
	"github.com/evidenceledger/certauth/x509util"
)

// Server represents the CertAuth OpenID Provider server
type Server struct {
	app        *fiber.App
	db         *database.Database
	adminPW    string
	handlers   *handlers.OIDCHandlers
	adminAuth  *middleware.AdminAuth
	jwtService *jwt.Service
	renderer   *templates.Renderer

	// Certificate data storage (in a real implementation, this would be persistent)
	certificateData map[string]*models.CertificateData // auth_code -> certificate_data
}

// New creates a new CertAuth server
func New(db *database.Database, adminPassword string) *Server {
	app := fiber.New(fiber.Config{
		AppName:                 "CertAuth OP",
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New())

	// Initialize JWT service
	jwtService, err := jwt.NewService("https://certauth.mycredential.eu")
	if err != nil {
		slog.Error("Failed to initialize JWT service", "error", err)
		panic(err)
	}

	// Initialize template renderer
	renderer, err := templates.NewRenderer()
	if err != nil {
		slog.Error("Failed to initialize template renderer", "error", err)
		panic(err)
	}

	handlers := handlers.NewOIDCHandlers(db)
	adminAuth := middleware.NewAdminAuth(adminPassword)

	server := &Server{
		app:             app,
		db:              db,
		adminPW:         adminPassword,
		handlers:        handlers,
		adminAuth:       adminAuth,
		jwtService:      jwtService,
		renderer:        renderer,
		certificateData: make(map[string]*models.CertificateData),
	}

	// Set the JWT service and certificate data getter in handlers
	handlers.SetJWTService(jwtService)
	handlers.SetCertificateDataGetter(server.GetCertificateData)

	server.setupRoutes()
	return server
}

// setupRoutes sets up all the server routes
func (s *Server) setupRoutes() {
	// Health check
	s.app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// OIDC Discovery endpoints
	s.app.Get("/.well-known/openid_configuration", s.handlers.Discovery)
	s.app.Get("/.well-known/jwks.json", s.handleJWKS)

	// OIDC endpoints
	s.app.Get("/oauth2/auth", s.handlers.Authorization)
	s.app.Post("/oauth2/token", s.handlers.Token)
	s.app.Get("/oauth2/userinfo", s.handlers.UserInfo)
	s.app.Get("/logout", s.handlers.Logout)

	// Certificate selection screen - shows before redirecting to CertSec
	s.app.Get("/certificate-select", s.handleCertificateSelect)

	// Test callback endpoint for testing the complete flow
	s.app.Get("/callback", s.handleTestCallback)

	// Internal endpoints for back-channel communication
	s.app.Post("/internal/consent", s.handleInternalConsent)
	s.app.Post("/internal/certificate", s.handleInternalCertificate)

	// Test endpoints for JWT token generation
	s.app.Post("/test/token", s.handleTestToken)
	s.app.Post("/test/token/personal", s.handleTestPersonalToken)
	s.app.Get("/test/callback", s.handleTestCallback) // Add this line

	// Admin routes (protected)
	admin := s.app.Group("/admin")
	admin.Use(s.adminAuth.AuthMiddleware())

	admin.Get("/rp", s.handlers.ListRP)
	admin.Post("/rp", s.handlers.CreateRP)
	admin.Put("/rp/:id", s.handlers.UpdateRP)
	admin.Delete("/rp/:id", s.handlers.DeleteRP)
}

// handleCertificateSelect handles the certificate selection screen
func (s *Server) handleCertificateSelect(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	slog.Info("Certificate selection requested", "auth_code", authCode)

	// Return a proper HTML page for certificate selection
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Certificate Selection Required</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 10px; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Certificate Selection Required</h1>
        <p>The application requires you to select a certificate for authentication.</p>
        
        <div class="warning">
            <strong>Note:</strong> Clicking the button below will redirect you to a secure domain where your browser will prompt you to select a certificate from your certificate store.
        </div>
        
        <p>Click the button below to proceed with certificate selection:</p>
        
        <button class="button" onclick="proceedWithCertificate()">Proceed with Certificate</button>
        
        <script>
        function proceedWithCertificate() {
            // Redirect to CertSec where the browser will prompt for certificate selection
            window.location.href = 'https://certsec.mycredential.eu/auth?code=` + authCode + `';
        }
        </script>
    </div>
</body>
</html>`

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send([]byte(html))
}

// handleJWKS handles the JSON Web Key Set endpoint
func (s *Server) handleJWKS(c *fiber.Ctx) error {
	jwks := s.jwtService.GetJWKS()
	return c.JSON(jwks)
}

// handleInternalConsent handles consent data from CertSec
func (s *Server) handleInternalConsent(c *fiber.Ctx) error {
	slog.Debug("Internal consent request received")

	// Parse the consent response
	var consentReq models.CertificateConsentRequest
	if err := c.BodyParser(&consentReq); err != nil {
		slog.Error("Failed to parse consent request", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	authCode := consentReq.AuthCode
	if authCode == "" {
		slog.Error("Missing or invalid auth_code in consent request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the AuthorizationRequest associated with the authCode
	authCodeObj, err := s.db.GetAuthCode(authCode)
	if err != nil {
		slog.Error("Failed to retrieve authorization code from DB", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}
	if authCodeObj == nil {
		slog.Error("Authorization code not found in DB", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid authorization code",
		})
	}

	if !consentReq.ConsentGranted {
		slog.Info("Consent denied by user", "auth_code", authCode)
		// Return JSON response for denied consent
		return c.JSON(fiber.Map{
			"success":  true,
			"redirect": authCodeObj.RedirectURI + "?error=access_denied&state=" + authCodeObj.State,
		})
	}

	// Store the certificate data for later token generation
	if consentReq.CertificateData != nil {
		s.certificateData[authCode] = consentReq.CertificateData
		slog.Info("Consent received and certificate data stored",
			"auth_code", authCode,
			"certificate_type", consentReq.CertificateData.CertificateType,
			"organization_id", consentReq.CertificateData.OrganizationID,
			"organization", consentReq.CertificateData.Subject.Organization,
			"country", consentReq.CertificateData.Subject.Country,
		)
	}

	// Return JSON response with success and redirect URL
	slog.Info("**** handleInternalConsent: Consent received and certificate data stored", "Method", c.Method(), "auth_code", authCode, "redirect", authCodeObj.RedirectURI+"?code="+authCode+"&state="+authCodeObj.State)
	return c.JSON(fiber.Map{
		"success":  true,
		"redirect": authCodeObj.RedirectURI + "?code=" + authCode + "&state=" + authCodeObj.State,
	})

}

// handleInternalCertificate handles certificate data from CertSec
func (s *Server) handleInternalCertificate(c *fiber.Ctx) error {
	slog.Debug("Internal certificate data request received")

	// Parse the certificate exchange request
	var certExchange models.CertificateExchange
	if err := c.BodyParser(&certExchange); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Store the certificate data for later token generation
	if certExchange.CertificateData != nil {
		s.certificateData[certExchange.AuthCode] = certExchange.CertificateData
		slog.Info("Certificate data stored for auth code",
			"auth_code", certExchange.AuthCode,
			"organization_id", certExchange.CertificateData.OrganizationID,
			"certificate_type", certExchange.CertificateData.CertificateType,
		)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Certificate data stored successfully",
	})
}

// handleTestToken creates a test token with organizational certificate data
func (s *Server) handleTestToken(c *fiber.Ctx) error {
	slog.Debug("Test organizational token generation requested")

	// Create test organizational certificate data
	testCertData := &models.CertificateData{
		Subject: &x509util.ELSIName{
			Country:                "ES",
			Organization:           "Test Organization",
			OrganizationalUnit:     "IT Department",
			CommonName:             "Test User",
			GivenName:              "Test",
			Surname:                "User",
			EmailAddress:           "test@example.com",
			OrganizationIdentifier: "ES-123456789",
			Locality:               "Madrid",
			Province:               "Madrid",
			StreetAddress:          "Calle Test 123",
			PostalCode:             "28001",
			SerialNumber:           "123456789ABC",
		},
		Issuer: &x509util.ELSIName{
			Country:                "ES",
			Organization:           "Test Organization",
			OrganizationIdentifier: "ES-123456789",
		},
		ValidFrom:       time.Now(),
		ValidTo:         time.Now().Add(365 * 24 * time.Hour),
		OrganizationID:  "ES-123456789",
		CertificateType: "organizational",
	}

	return s.generateTestTokens(c, testCertData)
}

// handleTestPersonalToken creates a test token with personal certificate data
func (s *Server) handleTestPersonalToken(c *fiber.Ctx) error {
	slog.Debug("Test personal token generation requested")

	// Create test personal certificate data
	testCertData := &models.CertificateData{
		Subject: &x509util.ELSIName{
			Country:       "ES",
			CommonName:    "Juan Pérez García",
			GivenName:     "Juan",
			Surname:       "Pérez García",
			EmailAddress:  "juan.perez@example.com",
			Locality:      "Barcelona",
			Province:      "Barcelona",
			StreetAddress: "Carrer de Test 456",
			PostalCode:    "08001",
			SerialNumber:  "PERS123456789",
		},
		Issuer: &x509util.ELSIName{
			Country: "ES",
		},
		ValidFrom:       time.Now(),
		ValidTo:         time.Now().Add(365 * 24 * time.Hour),
		OrganizationID:  "", // Empty for personal certificates
		CertificateType: "personal",
	}

	return s.generateTestTokens(c, testCertData)
}

// handleTestCallback handles the test callback endpoint to display the received authorization code
func (s *Server) handleTestCallback(c *fiber.Ctx) error {
	authCode := c.Query("code")
	state := c.Query("state")
	error := c.Query("error")
	errorDescription := c.Query("error_description")

	slog.Info("Test callback received", "auth_code", authCode, "state", state, "error", error)

	// Return a simple HTML page showing the callback parameters
	html := `<!DOCTYPE html>
<html>
<head>
    <title>OIDC Callback Test</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OIDC Callback Test</h1>`

	if error != "" {
		html += `
        <div class="error">
            <h2>Error Received</h2>
            <p><strong>Error:</strong> ` + error + `</p>
            <p><strong>Description:</strong> ` + errorDescription + `</p>
            <p><strong>State:</strong> ` + state + `</p>
        </div>`
	} else {
		html += `
        <div class="success">
            <h2>Success!</h2>
            <p>The OIDC authorization code flow completed successfully.</p>
            <p><strong>Authorization Code:</strong></p>
            <div class="code">` + authCode + `</div>
            <p><strong>State:</strong> ` + state + `</p>
            <p><em>Note: This is a test callback. In a real application, the RP would exchange this authorization code for tokens.</em></p>
        </div>`
	}

	html += `
    </div>
</body>
</html>`

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send([]byte(html))
}

// generateTestTokens generates test JWT tokens with the provided certificate data
func (s *Server) generateTestTokens(c *fiber.Ctx, certData *models.CertificateData) error {
	// Create test auth code and RP
	testAuthCode := &models.AuthCode{
		Code:        "test-code-123",
		ClientID:    "test-client",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid eidas",
		CreatedAt:   time.Now(),
	}

	testRP := &models.RelyingParty{
		ID:          1,
		Name:        "Test Application",
		Description: "Test application for development",
		ClientID:    "test-client",
		RedirectURL: "http://localhost:3000/callback",
		OriginURL:   "http://localhost:3000",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	// Generate ID token
	idToken, err := s.jwtService.GenerateIDToken(testAuthCode, certData, testRP)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate ID token",
		})
	}

	// Generate access token
	accessToken, err := s.jwtService.GenerateAccessToken(testAuthCode, certData, testRP)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate access token",
		})
	}

	slog.Info("Test tokens generated successfully",
		"certificate_type", certData.CertificateType,
		"subject", certData.Subject.CommonName,
		"organization_id", certData.OrganizationID,
	)

	return c.JSON(fiber.Map{
		"access_token":     accessToken.AccessToken,
		"token_type":       accessToken.TokenType,
		"expires_in":       accessToken.ExpiresIn,
		"scope":            accessToken.Scope,
		"id_token":         idToken,
		"certificate_type": certData.CertificateType,
		"organization_id":  certData.OrganizationID,
	})
}

// GetCertificateData retrieves certificate data for an auth code
func (s *Server) GetCertificateData(authCode string) *models.CertificateData {
	certData := s.certificateData[authCode]
	if certData != nil {
		// Remove the data after retrieval (one-time use)
		delete(s.certificateData, authCode)
	}
	return certData
}

// Start starts the server
func (s *Server) Start(ctx context.Context, addr string) error {
	slog.Info("Starting CertAuth server", "addr", addr)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.app.Listen(addr); err != nil {
			errChan <- fmt.Errorf("failed to start server: %w", err)
		}
	}()

	// Wait for context cancellation or error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.app.Shutdown()
	}
}
