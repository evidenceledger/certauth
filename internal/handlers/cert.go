package handlers

import (
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/x509util"
	"github.com/gofiber/fiber/v2"
)

// CertHandlers handles certificate-related HTTP requests
type CertHandlers struct {
	db *database.Database
}

// NewCertHandlers creates new certificate handlers
func NewCertHandlers(db *database.Database) *CertHandlers {
	return &CertHandlers{
		db: db,
	}
}

// Authenticate handles certificate authentication
func (h *CertHandlers) Authenticate(c *fiber.Ctx) error {
	slog.Debug("Certificate authentication request received")

	// Extract certificate from header
	certHeader := c.Get("tls-client-certificate")
	if certHeader == "" {
		slog.Error("No certificate provided in tls-client-certificate header")
		return errl.Errorf("missing certificate: certificate not provided")
	}

	// Decode the certificate
	certData, err := base64.StdEncoding.DecodeString(certHeader)
	if err != nil {
		slog.Error("Failed to decode certificate", "error", err)
		return errl.Errorf("invalid certificate encoding: %w", err)
	}

	// Parse the certificate using the existing x509util function
	cert, issuer, subject, err := x509util.ParseEIDASCertDer(certData)
	if err != nil {
		slog.Error("Failed to parse certificate", "error", err)
		return errl.Errorf("invalid certificate format: %w", err)
	}

	// Check certificate expiration (only validation required)
	now := time.Now()
	if now.Before(cert.NotBefore) {
		slog.Error("Certificate not yet valid",
			"not_before", cert.NotBefore, "current_time", now)
		return errl.Errorf("certificate validation failed: certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		slog.Error("Certificate expired",
			"not_after", cert.NotAfter, "current_time", now)
		return errl.Errorf("certificate validation failed: certificate is expired")
	}

	// Determine certificate type and prepare response
	certType := "personal"
	if subject.OrganizationIdentifier != "" {
		certType = "organizational"
	}

	// Log successful authentication (Info level with organizational data only)
	logFields := []interface{}{
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

	slog.Info("Certificate authentication successful", logFields...)

	// Prepare certificate data for response
	certDataResp := models.CertificateData{
		Subject:         subject,
		Issuer:          issuer,
		ValidFrom:       cert.NotBefore,
		ValidTo:         cert.NotAfter,
		OrganizationID:  subject.OrganizationIdentifier, // May be empty for personal certificates
		CertificateType: certType,
	}

	// Return the certificate data
	return c.JSON(fiber.Map{
		"success":          true,
		"data":             certDataResp,
		"certificate_type": certType,
	})
}
