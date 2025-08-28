package models

import (
	"time"
)

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ResponseType string `json:"response_type"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	Nonce        string `json:"nonce,omitempty"`
	CreatedAt    time.Time
}

// TokenRequest represents a token exchange request
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// RelyingParty represents a registered OIDC relying party
type RelyingParty struct {
	ID               int       `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"` // Never expose in JSON
	RedirectURL      string    `json:"redirect_url"`
	OriginURL        string    `json:"origin_url"`
	Scopes           string    `json:"scopes"`
	TokenExpiry      int       `json:"token_expiry"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// AuthCode represents an authorization code
type AuthCode struct {
	Code        string    `json:"code"`
	ClientID    string    `json:"client_id"`
	RedirectURI string    `json:"redirect_uri"`
	State       string    `json:"state"`
	Nonce       string    `json:"nonce"`
	Scope       string    `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// IDToken represents an OpenID Connect ID token
type IDToken struct {
	Issuer          string                 `json:"iss"`
	Subject         string                 `json:"sub"`
	Audience        string                 `json:"aud"`
	Expiration      int64                  `json:"exp"`
	IssuedAt        int64                  `json:"iat"`
	Nonce           string                 `json:"nonce,omitempty"`
	AccessTokenHash string                 `json:"at_hash,omitempty"`
	CustomClaims    map[string]interface{} `json:"custom_claims"`
}

// AccessToken represents an OAuth2 access token
type AccessToken struct {
	AccessToken string                 `json:"access_token"`
	TokenType   string                 `json:"token_type"`
	ExpiresIn   int                    `json:"expires_in"`
	Scope       string                 `json:"scope"`
	Claims      map[string]interface{} `json:"claims"`
}

// RPSession represents a user session in the example RP
type RPSession struct {
	SessionID    string           `json:"session_id"`
	UserID       string           `json:"user_id"`
	UserInfo     *CertificateData `json:"user_info"`
	AccessToken  string           `json:"access_token"`
	IDToken      string           `json:"id_token"`
	CreatedAt    time.Time        `json:"created_at"`
	LastAccessed time.Time        `json:"last_accessed"`
}
