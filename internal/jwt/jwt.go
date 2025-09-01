package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"time"

	"github.com/evidenceledger/certauth/internal/models"
	"github.com/golang-jwt/jwt/v5"

	"github.com/lestrrat-go/jwx/v3/jwk"
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

	// Determine the sub identifier based on certificate type
	var sub string
	if certData.Subject.OrganizationIdentifier != "" {
		sub = certData.Subject.OrganizationIdentifier
	} else {
		// For personal certificates, use serial number or generate a unique identifier
		if certData.Subject.SerialNumber != "" {
			sub = certData.Subject.SerialNumber
		} else if certData.Subject.CommonName != "" {
			sub = certData.Subject.CommonName + "_" + certData.Subject.SerialNumber
		} else {
			// Fallback: generate a hash based on certificate data
			sub = fmt.Sprintf("%s_%s_%s",
				certData.Subject.GivenName,
				certData.Subject.Surname,
				certData.Subject.SerialNumber)
		}
	}

	// Standard OIDC claims
	claims := jwt.MapClaims{
		// Standard claims
		"iss":   s.issuer,                                                    // Issuer
		"sub":   sub,                                                         // Subject (org ID or personal identifier)
		"aud":   rp.ClientID,                                                 // Audience
		"exp":   now.Add(time.Duration(rp.TokenExpiry) * time.Second).Unix(), // Expiration
		"iat":   now.Unix(),                                                  // Issued at
		"nonce": authCode.Nonce,                                              // Nonce (if provided)
	}

	// Add standard claims from certificate if available
	if certData.Subject.Organization != "" {
		claims["name"] = certData.Subject.CommonName
	} else if certData.Subject.CommonName != "" {
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
	maps.Copy(claims, elsiClaims)

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
func (s *Service) generateELSIClaims(certData *models.CertificateData) map[string]any {
	claims := make(map[string]any)

	// Map certificate fields to elsi_ claims
	if certData.Subject.Organization != "" {
		claims["organization"] = certData.Subject.Organization
	}
	if certData.Subject.OrganizationalUnit != "" {
		claims["organizational_unit"] = certData.Subject.OrganizationalUnit
	}
	if certData.Subject.CommonName != "" {
		claims["common_name"] = certData.Subject.CommonName
	}
	if certData.Subject.Locality != "" {
		claims["locality"] = certData.Subject.Locality
	}
	if certData.Subject.Province != "" {
		claims["province"] = certData.Subject.Province
	}
	if certData.Subject.StreetAddress != "" {
		claims["street_address"] = certData.Subject.StreetAddress
	}
	if certData.Subject.PostalCode != "" {
		claims["postal_code"] = certData.Subject.PostalCode
	}
	if certData.Subject.SerialNumber != "" {
		claims["serial_number"] = certData.Subject.SerialNumber
	}
	if certData.Subject.Country != "" {
		claims["country"] = certData.Subject.Country
	}
	// Always include the organization identifier
	claims["organization_identifier"] = certData.Subject.OrganizationIdentifier

	claims["valid_from"] = certData.ValidFrom.Unix()
	claims["valid_to"] = certData.ValidTo.Unix()

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
func (s *Service) GetJWKS() map[string]any {

	jk, err := jwk.Import(s.publicKey)
	if err != nil {
		return nil
	}

	jk.Set("use", "sig")
	jk.Set(jwk.KeyIDKey, "certauth-key")
	jk.Set(jwk.AlgorithmKey, "RS256")

	jwks := map[string]any{
		"keys": []any{jk},
	}
	return jwks
}
