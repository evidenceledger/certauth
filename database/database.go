// Package database provides an interface for interacting with the SQLite database used by the application.
package database

import (
	"database/sql"

	"github.com/evidenceledger/certauth/internal/errl"
	_ "github.com/mattn/go-sqlite3"
)

// Database manages SQLite operations
type Database struct {
	db *sql.DB
}

var tableCreateQueries = []string{
	`CREATE TABLE IF NOT EXISTS relying_parties (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		client_id TEXT UNIQUE NOT NULL,
		client_secret_hash TEXT NOT NULL,
		redirect_url TEXT NOT NULL,
		scopes TEXT DEFAULT 'openid eidas',
		token_expiry INTEGER DEFAULT 3600,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS registrations (
	    organization_identifier TEXT UNIQUE NOT NULL,
		organization TEXT,
		email TEXT,
		country TEXT,
		contract_form BLOB,
		eidas_cert TEXT,
		signed_annex TEXT,
		timestamp BLOB,
		contract_document TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`,
}

// New creates a new database instance
func New(dbname string) (*Database, error) {
	d := &Database{}

	if dbname == "" {
		dbname = "./data/onboard.db"
	}

	db, err := sql.Open("sqlite3", dbname)
	if err != nil {
		return nil, errl.Errorf("failed to open database: %w", err)
	}
	d.db = db

	// Create tables
	for _, query := range tableCreateQueries {
		if _, err := d.db.Exec(query); err != nil {
			return nil, errl.Errorf("failed to execute query: %w", err)
		}
	}

	// Run the migrations
	if err := RunMigrationsUp(d.db); err != nil {
		return nil, errl.Errorf("failed to run migrations: %w", err)
	}

	// // Initialize with test data if empty
	// if err := d.initializePredefinedRPs(); err != nil {
	// 	return nil, errl.Errorf("failed to initialize test data: %w", err)
	// }

	return d, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
