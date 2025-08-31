package database

import (
	"fmt"
	"log/slog"

	"github.com/evidenceledger/certauth/internal/models"
)

// initializeTestData adds some test data if the database is empty
func (d *Database) initializeTestData() error {
	// Check if we already have test data
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM relying_parties").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing data: %w", err)
	}

	if count > 0 {
		slog.Debug("Database already contains data, skipping test data initialization")
		return nil
	}

	// Add test relying party
	testRP := &models.RelyingParty{
		Name:        "Test Application",
		Description: "A test application for development",
		ClientID:    "test-client",
		RedirectURL: "https://certauth.mycredential.eu/callback",
		OriginURL:   "http://localhost:3000",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	if err := d.CreateRelyingParty(testRP, "test-secret"); err != nil {
		return fmt.Errorf("failed to create test RP: %w", err)
	}

	// Add example RP
	exampleRP := &models.RelyingParty{
		Name:        "Example RP Application",
		Description: "Example Relying Party application demonstrating certificate authentication",
		ClientID:    "example-rp",
		RedirectURL: "http://localhost:8092/callback",
		OriginURL:   "http://localhost:8092",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	if err := d.CreateRelyingParty(exampleRP, "example-secret"); err != nil {
		return fmt.Errorf("failed to create example RP: %w", err)
	}

	slog.Info("Test data initialized", "rp_count", 2)
	return nil
}
