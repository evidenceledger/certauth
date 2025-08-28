package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

// Service handles JWT token generation
type Service struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
}

// NewService creates a new JWT service
func NewService(issuer string) (*Service, error) {
	// Generate RSA key pair for token signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	slog.Info("JWT service initialized", "issuer", issuer)
	return &Service{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
	}, nil
}

// GenerateIDToken generates an OpenID Connect ID token
func (s *Service) GenerateIDToken(authCode *models.AuthCode, certData *models.CertificateData, rp *models.RelyingParty) (string, error) {
	now := time.Now()

	// Determine the subject identifier based on certificate type
	var subject string
	if certData.CertificateType == "organizational" && certData.Subject.OrganizationIdentifier != "" {
		subject = certData.Subject.OrganizationIdentifier
	} else {
		// For personal certificates, use serial number or generate a unique identifier
		if certData.Subject.SerialNumber != "" {
			subject = certData.Subject.SerialNumber
		} else if certData.Subject.CommonName != "" {
			subject = certData.Subject.CommonName + "_" + certData.Subject.SerialNumber
		} else {
			// Fallback: generate a hash based on certificate data
			subject = fmt.Sprintf("%s_%s_%s",
				certData.Subject.GivenName,
				certData.Subject.Surname,
				certData.Subject.SerialNumber)
		}
	}

	// Standard OIDC claims
	claims := jwt.MapClaims{
		// Standard claims
		"iss":   s.issuer,                                                    // Issuer
		"sub":   subject,                                                     // Subject (org ID or personal identifier)
		"aud":   rp.ClientID,                                                 // Audience
		"exp":   now.Add(time.Duration(rp.TokenExpiry) * time.Second).Unix(), // Expiration
		"iat":   now.Unix(),                                                  // Issued at
		"nonce": authCode.Nonce,                                              // Nonce (if provided)
	}

	// Add standard claims from certificate if available
	if certData.Subject.CommonName != "" {
		claims["name"] = certData.Subject.CommonName
	}
	if certData.Subject.GivenName != "" {
		claims["given_name"] = certData.Subject.GivenName
	}
	if certData.Subject.Surname != "" {
		claims["family_name"] = certData.Subject.Surname
	}
	if certData.Subject.EmailAddress != "" {
		claims["email"] = certData.Subject.EmailAddress
	}

	// Add custom elsi_ claims for ETSI standardized fields
	elsiClaims := s.generateELSIClaims(certData)
	for key, value := range elsiClaims {
		claims[key] = value
	}

	// Add certificate type information
	claims["elsi_certificate_type"] = certData.CertificateType

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	slog.Debug("ID token generated",
		"subject", claims["sub"],
		"audience", claims["aud"],
		"expiration", claims["exp"],
	)

	return tokenString, nil
}

// GenerateAccessToken generates an OAuth2 access token
func (s *Service) GenerateAccessToken(authCode *models.AuthCode, certData *models.CertificateData, rp *models.RelyingParty) (*models.AccessToken, error) {
	expiresIn := rp.TokenExpiry

	// Generate random token string
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random token: %w", err)
	}

	tokenString := fmt.Sprintf("%x", tokenBytes)

	// Create access token
	accessToken := &models.AccessToken{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       authCode.Scope,
		Claims:      s.generateELSIClaims(certData), // Same claims as ID token
	}

	slog.Debug("Access token generated",
		"subject", certData.Subject.OrganizationIdentifier,
		"expires_in", expiresIn,
	)

	return accessToken, nil
}

// generateELSIClaims generates custom elsi_ claims for ETSI standardized fields
func (s *Service) generateELSIClaims(certData *models.CertificateData) map[string]interface{} {
	claims := make(map[string]interface{})

	// Map certificate fields to elsi_ claims
	if certData.Subject.Organization != "" {
		claims["elsi_organization"] = certData.Subject.Organization
	}
	if certData.Subject.OrganizationalUnit != "" {
		claims["elsi_organizational_unit"] = certData.Subject.OrganizationalUnit
	}
	if certData.Subject.Locality != "" {
		claims["elsi_locality"] = certData.Subject.Locality
	}
	if certData.Subject.Province != "" {
		claims["elsi_province"] = certData.Subject.Province
	}
	if certData.Subject.StreetAddress != "" {
		claims["elsi_street_address"] = certData.Subject.StreetAddress
	}
	if certData.Subject.PostalCode != "" {
		claims["elsi_postal_code"] = certData.Subject.PostalCode
	}
	if certData.Subject.SerialNumber != "" {
		claims["elsi_serial_number"] = certData.Subject.SerialNumber
	}
	if certData.Subject.Country != "" {
		claims["elsi_country"] = certData.Subject.Country
	}
	// Always include the organization identifier
	claims["elsi_organization_identifier"] = certData.Subject.OrganizationIdentifier

	return claims
}

// GetPublicKey returns the public key in PEM format for JWKS
func (s *Service) GetPublicKey() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// GetJWKS returns the JSON Web Key Set
func (s *Service) GetJWKS() map[string]interface{} {
	// For now, return a simple JWKS structure
	// In production, you might want to include more metadata
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "certauth-key", // Key ID
				// Note: In a real implementation, you would include the actual public key
				// components (n, e) here
			},
		},
	}
}

// ValidateIDToken validates an ID token (for future use)
func (s *Service) ValidateIDToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}
