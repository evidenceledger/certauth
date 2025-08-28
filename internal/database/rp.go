package database

import (
	"database/sql"
	"log/slog"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// GetRelyingParty retrieves a relying party by client ID
func (d *Database) GetRelyingParty(clientID string) (*models.RelyingParty, error) {
	query := `
		SELECT id, name, description, client_id, client_secret_hash, 
		       redirect_url, origin_url, scopes, token_expiry, 
		       created_at, updated_at
		FROM relying_parties 
		WHERE client_id = ?
	`

	var rp models.RelyingParty
	err := d.db.QueryRow(query, clientID).Scan(
		&rp.ID, &rp.Name, &rp.Description, &rp.ClientID, &rp.ClientSecretHash,
		&rp.RedirectURL, &rp.OriginURL, &rp.Scopes, &rp.TokenExpiry,
		&rp.CreatedAt, &rp.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errl.Errorf("failed to get relying party: %w", err)
	}

	return &rp, nil
}

// ListRelyingParties retrieves all relying parties
func (d *Database) ListRelyingParties() ([]models.RelyingParty, error) {
	query := `
		SELECT id, name, description, client_id, redirect_url, 
		       origin_url, scopes, token_expiry, created_at, updated_at
		FROM relying_parties 
		ORDER BY name
	`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, errl.Errorf("failed to list relying parties: %w", err)
	}
	defer rows.Close()

	var rps []models.RelyingParty
	for rows.Next() {
		var rp models.RelyingParty
		err := rows.Scan(
			&rp.ID, &rp.Name, &rp.Description, &rp.ClientID,
			&rp.RedirectURL, &rp.OriginURL, &rp.Scopes, &rp.TokenExpiry,
			&rp.CreatedAt, &rp.UpdatedAt,
		)
		if err != nil {
			return nil, errl.Errorf("failed to scan relying party: %w", err)
		}
		rps = append(rps, rp)
	}

	return rps, nil
}

// CreateRelyingParty creates a new relying party
func (d *Database) CreateRelyingParty(rp *models.RelyingParty, clientSecret string) error {
	// Hash the client secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return errl.Errorf("failed to hash client secret: %w", err)
	}

	query := `
		INSERT INTO relying_parties (
			name, description, client_id, client_secret_hash, 
			redirect_url, origin_url, scopes, token_expiry
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = d.db.Exec(query,
		rp.Name, rp.Description, rp.ClientID, hashedSecret,
		rp.RedirectURL, rp.OriginURL, rp.Scopes, rp.TokenExpiry,
	)

	if err != nil {
		return errl.Errorf("failed to create relying party: %w", err)
	}

	slog.Info("Created relying party", "client_id", rp.ClientID, "name", rp.Name)
	return nil
}

// UpdateRelyingParty updates an existing relying party
func (d *Database) UpdateRelyingParty(rp *models.RelyingParty, clientSecret string) error {
	var query string
	var args []interface{}

	if clientSecret != "" {
		// Hash the new client secret
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return errl.Errorf("failed to hash client secret: %w", err)
		}

		query = `
			UPDATE relying_parties 
			SET name = ?, description = ?, redirect_url = ?, origin_url = ?, 
			    scopes = ?, token_expiry = ?, client_secret_hash = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`
		args = []interface{}{
			rp.Name, rp.Description, rp.RedirectURL, rp.OriginURL,
			rp.Scopes, rp.TokenExpiry, hashedSecret, rp.ID,
		}
	} else {
		query = `
			UPDATE relying_parties 
			SET name = ?, description = ?, redirect_url = ?, origin_url = ?, 
			    scopes = ?, token_expiry = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`
		args = []interface{}{
			rp.Name, rp.Description, rp.RedirectURL, rp.OriginURL,
			rp.Scopes, rp.TokenExpiry, rp.ID,
		}
	}

	_, err := d.db.Exec(query, args...)
	if err != nil {
		return errl.Errorf("failed to update relying party: %w", err)
	}

	slog.Info("Updated relying party", "client_id", rp.ClientID, "name", rp.Name)
	return nil
}

// DeleteRelyingParty deletes a relying party
func (d *Database) DeleteRelyingParty(id int) error {
	query := `DELETE FROM relying_parties WHERE id = ?`

	_, err := d.db.Exec(query, id)
	if err != nil {
		return errl.Errorf("failed to delete relying party: %w", err)
	}

	slog.Info("Deleted relying party", "id", id)
	return nil
}

// ValidateClientSecret validates a client secret against the stored hash
func (d *Database) ValidateClientSecret(clientID, clientSecret string) (bool, error) {
	rp, err := d.GetRelyingParty(clientID)
	if err != nil {
		return false, err
	}
	if rp == nil {
		return false, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(rp.ClientSecretHash), []byte(clientSecret))
	return err == nil, nil
}
