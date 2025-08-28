package certsec

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/handlers"
	"github.com/evidenceledger/certauth/x509util"
)

// Server represents the CertSec certificate authentication server
type Server struct {
	app      *fiber.App
	db       *database.Database
	handlers *handlers.CertHandlers
}

// New creates a new CertSec server
func New(db *database.Database) *Server {
	app := fiber.New(fiber.Config{
		AppName: "CertSec Certificate Authentication",
	})

	app.Use(recover.New())
	app.Use(logger.New())

	handlers := handlers.NewCertHandlers(db)

	server := &Server{
		app:      app,
		db:       db,
		handlers: handlers,
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures all the routes
func (s *Server) setupRoutes() {
	// Health check
	s.app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// Certificate authentication endpoint
	s.app.Get("/auth", s.handleCertificateAuth)

	// Consent screen - simplified version
	s.app.Get("/consent", func(c *fiber.Ctx) error {
		// Get auth code from query parameter
		authCode := c.Query("code")
		if authCode == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Missing authorization code",
			})
		}

		slog.Info("Consent screen requested", "auth_code", authCode)

		// Return a simple HTML page for consent
		html := `<!DOCTYPE html>
<html>
<head>
    <title>Consent Required</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 10px; }
        .button.danger { background: #dc3545; }
        .info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Consent Required</h1>
        <p>The application <strong>Test Application</strong> is requesting access to your certificate information.</p>
        
        <div class="info">
            <h3>Information to be shared:</h3>
            <ul>
                <li><strong>Organization:</strong> Test Organization</li>
                <li><strong>Organization ID:</strong> ES-123456789</li>
                <li><strong>Country:</strong> ES</li>
                <li><strong>Unit:</strong> IT Department</li>
                <li><strong>Location:</strong> Madrid, Madrid</li>
            </ul>
        </div>
        
        <p>Do you want to proceed with the authentication?</p>
        
        <button class="button" onclick="grantConsent()">Grant Access</button>
        <button class="button danger" onclick="denyConsent()">Deny Access</button>
        
        <script>
        function grantConsent() {
            // In a real implementation, this would send the consent to the server
            alert('Consent granted! You would be redirected to the application.');
        }
        
        function denyConsent() {
            // In a real implementation, this would deny consent and redirect with error
            alert('Consent denied! You would be redirected with an error.');
        }
        </script>
    </div>
</body>
</html>`

		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Send([]byte(html))
	})
}

// handleCertificateAuth handles the certificate authentication endpoint
// This endpoint receives the certificate from the browser and shows the consent screen
func (s *Server) handleCertificateAuth(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")
	if authCode == "" {
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

	slog.Info("Certificate authentication requested", "auth_code", authCode)

	// Get the certificate from the TLS connection
	certHeader := c.Get("tls-client-certificate")
	if certHeader == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No certificate provided",
		})
	}

	slog.Info("Certificate received", "auth_code", authCode, "cert_length", len(certHeader))

	// Process the certificate using the existing certificate parsing logic
	// Decode the certificate
	certDataBytes, err := base64.StdEncoding.DecodeString(certHeader)
	if err != nil {
		slog.Error("Failed to decode certificate", "error", err, "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid certificate encoding",
		})
	}

	// Parse the certificate using the existing x509util function
	cert, _, subject, err := x509util.ParseEIDASCertDer(certDataBytes)
	if err != nil {
		slog.Error("Failed to parse certificate", "error", err, "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid certificate format",
		})
	}

	// Check certificate expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		slog.Error("Certificate not yet valid", "not_before", cert.NotBefore, "current_time", now, "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Certificate not yet valid",
		})
	}
	if now.After(cert.NotAfter) {
		slog.Error("Certificate expired", "not_after", cert.NotAfter, "current_time", now, "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Certificate is expired",
		})
	}

	// Determine certificate type
	certType := "personal"
	if subject.OrganizationIdentifier != "" {
		certType = "organizational"
	}

	// Log successful processing (Info level with organizational data only)
	logFields := []interface{}{
		"auth_code", authCode,
		"certificate_type", certType,
		"valid_from", cert.NotBefore,
		"valid_to", cert.NotAfter,
	}

	// Only log organizational fields for privacy (exclude personal identifiers)
	if subject.Organization != "" {
		logFields = append(logFields, "organization", subject.Organization)
	}
	if subject.OrganizationIdentifier != "" {
		logFields = append(logFields, "organization_identifier", subject.OrganizationIdentifier)
	}
	if subject.Country != "" {
		logFields = append(logFields, "country", subject.Country)
	}

	slog.Info("Certificate processed successfully", logFields...)

	// Generate consent screen with parsed certificate information
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Consent Required</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 10px; }
        .button.danger { background: #dc3545; }
        .info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .cert-info { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 4px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Consent Required</h1>
        <p>The application <strong>Test Application</strong> is requesting access to your certificate information.</p>
        
        <div class="info">
            <h3>Certificate Information:</h3>
            <ul>
                <li><strong>Certificate Type:</strong> ` + certType + `</li>
                <li><strong>Common Name:</strong> ` + subject.CommonName + `</li>
                <li><strong>Organization:</strong> ` + subject.Organization + `</li>
                <li><strong>Organizational Unit:</strong> ` + subject.OrganizationalUnit + `</li>
                <li><strong>Country:</strong> ` + subject.Country + `</li>
                <li><strong>Email:</strong> ` + subject.EmailAddress + `</li>
                <li><strong>Valid From:</strong> ` + cert.NotBefore.Format("2006-01-02 15:04:05") + `</li>
                <li><strong>Valid To:</strong> ` + cert.NotAfter.Format("2006-01-02 15:04:05") + `</li>
            </ul>
        </div>`

	// Add organization identifier if present
	if subject.OrganizationIdentifier != "" {
		html += `
        <div class="cert-info">
            <h4>Organization Details:</h4>
            <ul>
                <li><strong>Organization Identifier:</strong> ` + subject.OrganizationIdentifier + `</li>
                <li><strong>Locality:</strong> ` + subject.Locality + `</li>
                <li><strong>Province:</strong> ` + subject.Province + `</li>
                <li><strong>Street Address:</strong> ` + subject.StreetAddress + `</li>
                <li><strong>Postal Code:</strong> ` + subject.PostalCode + `</li>
            </ul>
        </div>`
	}

	// Add warning for personal certificates
	if certType == "personal" {
		html += `
        <div class="warning">
            <strong>Warning:</strong> This is a personal certificate (does not contain organization identifier). 
            The relying party may have specific requirements for organizational certificates.
        </div>`
	}

	// Create a JSON object with certificate data for JavaScript
	certDataJSON := fmt.Sprintf(`{
		"authCode": "%s",
		"redirectURI": "%s",
		"state": "%s",
		"nonce": "%s",
		"scope": "%s",
		"certType": "%s",
		"organization": "%s",
		"organizationID": "%s",
		"country": "%s",
		"organizationalUnit": "%s",
		"commonName": "%s",
		"email": "%s",
		"locality": "%s",
		"province": "%s",
		"streetAddress": "%s",
		"postalCode": "%s",
		"serialNumber": "%s"
	}`, authCode, authCodeObj.RedirectURI, authCodeObj.State, authCodeObj.Nonce, authCodeObj.Scope,
		certType, subject.Organization, subject.OrganizationIdentifier, subject.Country,
		subject.OrganizationalUnit, subject.CommonName, subject.EmailAddress, subject.Locality,
		subject.Province, subject.StreetAddress, subject.PostalCode, subject.SerialNumber)

	html += `
        <p>Do you want to proceed with the authentication?</p>
        
        <button class="button" onclick="grantConsent()">Grant Access</button>
        <button class="button danger" onclick="denyConsent()">Deny Access</button>
        
        <script>
        var certData = ` + certDataJSON + `;
        
        function grantConsent() {
            // Send consent to CertAuth and redirect back to RP
            fetch('https://certauth.mycredential.eu/internal/consent', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    auth_code: certData.authCode,
                    consent_granted: true,
                    certificate_data: {
                        certificate_type: certData.certType,
                        organization_identifier: certData.organizationID,
                        subject: {
                            common_name: certData.commonName,
                            organization: certData.organization,
                            organizational_unit: certData.organizationalUnit,
                            country: certData.country,
                            email_address: certData.email,
                            locality: certData.locality,
                            province: certData.province,
                            street_address: certData.streetAddress,
                            postal_code: certData.postalCode,
                            serial_number: certData.serialNumber
                        }
                    },
                    state: certData.state
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.redirect) {
                    // Redirect to the provided URL from the response
                    window.location.href = data.redirect;
                } else {
                    alert('Failed to process consent');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to process consent');
            });
        }
        
        function denyConsent() {
            // Send denial to CertAuth and redirect back to RP
            fetch('https://certauth.mycredential.eu/internal/consent', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    auth_code: certData.authCode,
                    consent_granted: false,
                    state: certData.state
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.redirect) {
                    // Redirect to the provided URL from the response
                    window.location.href = data.redirect;
                } else {
                    alert('Failed to process consent denial');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to process consent denial');
            });
        }
        </script>
    </div>
</body>
</html>`

	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send([]byte(html))
}

// Start starts the server
func (s *Server) Start(ctx context.Context, addr string) error {
	slog.Info("Starting CertSec server", "addr", addr)

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
