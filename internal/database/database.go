package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/evidenceledger/certauth/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// Database manages SQLite operations
type Database struct {
	db *sql.DB
}

// New creates a new database instance
func New() *Database {
	return &Database{}
}

// Initialize creates tables and initializes the database
func (d *Database) Initialize() error {
	db, err := sql.Open("sqlite3", "./data/certauth.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	d.db = db

	// Create tables
	if err := d.createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Initialize with test data if empty
	if err := d.initializeTestData(); err != nil {
		return fmt.Errorf("failed to initialize test data: %w", err)
	}

	slog.Info("Database initialized")
	return nil
}

// createTables creates all necessary tables
func (d *Database) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS relying_parties (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			client_id TEXT UNIQUE NOT NULL,
			client_secret_hash TEXT NOT NULL,
			redirect_url TEXT NOT NULL,
			origin_url TEXT NOT NULL,
			scopes TEXT DEFAULT 'openid eidas',
			token_expiry INTEGER DEFAULT 3600,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS authentication_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			auth_code TEXT UNIQUE NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			state TEXT NOT NULL,
			nonce TEXT,
			scope TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %w", err)
		}
	}

	return nil
}

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

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
