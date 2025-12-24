// Package mainserver implements the main entry point logic for the server, managing CertAuth, CertSec, and Onboard services.
package mainserver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	certauth "github.com/evidenceledger/certauth/certauthserver"
	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/certsec"
	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
	onboard "github.com/evidenceledger/certauth/onboard"
)

// We define several profiles, to facilitate configuration if an environment matches one of the profiles.
// To run the server in a specific profile, use the -profile flag or the PROFILE environment variable,
// with the value of the profile you want to use.
// No other environment variables are required when using a profile, except for the TSA and email server credentials.
const (
	ALTIA_LOCAL = "local"
	ALTIA_DEV   = "altia-dev"
	ISBE_DEV    = "isbe-dev"
	ISBE_PRE    = "isbe-pre"
	ISBE_PRO    = "isbe-pro"
)

// Config is the configuration for the server.
// It contains the configuration for CertAuth, CertSec and Onboard servers.
type Config struct {
	Development    bool
	OnboardURL     string
	OnboardPort    string
	PrivateArea    string
	TMFServerURL   string
	CertAuthConfig *certauth.Config
}

// Server manages the CertAuth, CertSec and Onboard servers
type Server struct {
	cfg            Config
	certauthServer *certauth.Server
	certsecServer  *certsec.Server
	onboardServer  *onboard.Server
	db             *database.Database
	adminPW        string
}

// New creates a new server instance.
// It initializes the database, cache, CertAuth, CertSec and Onboard servers.
func New(adminPassword string, cfg Config, profile string) (*Server, error) {

	// Create a global in-memory cache with a default expiration time of 10 minutes
	// TODO(hesusruiz): make this configurable
	cache := cache.New(10 * time.Minute)

	// Initialize database
	db, err := database.New("")
	if err != nil {
		slog.Error("Failed to initialize database", "error", err)
		return nil, errl.Errorf("failed to initialize database: %w", err)
	}

	// Initialize predefined Relying Parties
	if err := initializePredefinedRPs(profile, db, cfg.OnboardURL); err != nil {
		return nil, errl.Errorf("failed to initialize predefined Relying Parties: %w", err)
	}

	// Create the authentication and authorization servers.
	// They share the same database and cache.

	certauthServer, err := certauth.New(db, cache, adminPassword, cfg.CertAuthConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create certauth server: %w", err)
	}

	// CertSec server requests the certificate from the user browser and passes it to the CerAuth server.
	// It also implements admin functionalities, using a client certificate as authentication mechanism.
	newCertSecConfig := &certsec.Config{
		Development:             cfg.Development,
		CertAuthURL:             cfg.CertAuthConfig.CertAuthURL,
		CertificateBackEndpoint: certauth.CertificateBackEndpoint,
		CertSecURL:              cfg.CertAuthConfig.CertSecURL,
		CertSecPort:             cfg.CertAuthConfig.CertSecPort,
	}
	certsecServer, err := certsec.New(db, cache, newCertSecConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create certsec server: %w", err)
	}

	// If in development mode, create the Onboard application server.
	// It uses the CertAuth server as the OP.

	var onboardServer *onboard.Server
	if cfg.OnboardURL != "" {
		onboardServer = onboard.New(cfg.OnboardPort, cfg.OnboardURL, cfg.CertAuthConfig.CertAuthURL, "isbeonboard", "isbesecret", cfg.PrivateArea)
	}

	return &Server{
		certauthServer: certauthServer,
		certsecServer:  certsecServer,
		onboardServer:  onboardServer,
		db:             db,
		adminPW:        adminPassword,
		cfg:            cfg,
	}, nil

}

// Start starts both servers: CertAuth and CertSec. It also starts the Onboarding test server if enabled
func (s *Server) Start(ctx context.Context) error {

	if s.db == nil {
		return errl.Errorf("server not initialized")
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	// Start CertAuth server (default port 8090)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certauthServer.Start(ctx); err != nil {
			errChan <- fmt.Errorf("certauth server failed: %w", err)
		}
	}()

	// Start CertSec server (default port 8091)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certsecServer.Start(ctx); err != nil {
			errChan <- fmt.Errorf("certsec server failed: %w", err)
		}
	}()

	// Start Onboard server (default port 8092)
	if s.onboardServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.onboardServer.Start(); err != nil {
				errChan <- fmt.Errorf("onboard server failed: %w", err)
			}
		}()
	}

	// Wait for either server to fail or context to be cancelled
	select {
	case err := <-errChan:
		s.db.Close()
		return err
	case <-ctx.Done():
		slog.Info("Shutting down servers")
		s.db.Close()
		return nil
	}
}

// initializePredefinedRPs adds some predefined Relying Parties to the database
func initializePredefinedRPs(profile string, db *database.Database, onboardURL string) error {

	switch profile {
	case ALTIA_LOCAL:

		// ISBE Onboarding page in localhost (for local development)
		// Use the configured ONBOARD_URL for the redirect
		if onboardURL != "" {
			db.UpsertRelyingParty(&models.RelyingParty{
				Name:        "ISBE Onboarding localhost",
				Description: "The ISBE Onboarding Application in localhost",
				ClientID:    "isbeonboard",
				RedirectURL: onboardURL + "/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			}, "isbesecret")
		}

		// ISBE Issuer for test
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Issuer for test",
			Description: "The ISBE Credential Issuer Application",
			ClientID:    "https://issuer.mycredential.eu",
			RedirectURL: "https://issuer.mycredential.eu/lear/auth/callback",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

	case ALTIA_DEV:

		// ISBE Catalog in netlify
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Catalog Netlify",
			Description: "The ISBE Catalog application in Netlify",
			ClientID:    "https://catalog.isbeonboard.com",
			RedirectURL: "https://isbecatalog.netlify.app/",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Onboarding page in DEV
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Onboarding DEV",
			Description: "The ISBE Onboarding Application in DEV",
			ClientID:    "isbeonboard",
			RedirectURL: "https://onboard-dev.redisbe.com/callback",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Keycloak in DEV
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Keycloak in DEV",
			Description: "The ISBE Keycloak in DEV application",
			ClientID:    "https://idp.dev.cloud-w.envs.redisbe.com",
			RedirectURL: "https://idp.dev.cloud-w.envs.redisbe.com/auth/realms/dev-isbe/broker/certificado-representante/endpoint",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

	case ISBE_DEV:

		// ISBE Keycloak in DEV
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Keycloak in DEV",
			Description: "The ISBE Keycloak in DEV application",
			ClientID:    "https://idp.dev.cloud-w.envs.redisbe.com",
			RedirectURL: "https://idp.dev.cloud-w.envs.redisbe.com/auth/realms/dev-isbe/broker/certificado-representante/endpoint",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Catalog in DEV
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Catalog DEV",
			Description: "The ISBE Catalog application in DEV",
			ClientID:    "https://catalog.isbeonboard.com",
			RedirectURL: "https://catalog.dev.cloud-w.envs.redisbe.com/",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Onboarding page in DEV
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Onboarding DEV",
			Description: "The ISBE Onboarding Application in DEV",
			ClientID:    "isbeonboard",
			RedirectURL: "https://onboard-dev.redisbe.com/callback",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

	case ISBE_PRE:

		// ISBE Keycloak in PRE
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Keycloak in PRE",
			Description: "The ISBE Keycloak in PRE application",
			ClientID:    "https://idp.pre.cloud-w.envs.redisbe.com",
			RedirectURL: "https://idp.pre.cloud-w.envs.redisbe.com/auth/realms/pre-isbe/broker/certificado-representante/endpoint",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Catalog in PRE
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Catalog PRE",
			Description: "The ISBE Catalog application in PRE",
			ClientID:    "https://catalog.isbeonboard.com",
			RedirectURL: "https://catalog.pre.cloud-w.envs.redisbe.com/",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Onboarding page in PRE
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Onboarding PRE",
			Description: "The ISBE Onboarding Application in PRE",
			ClientID:    "isbeonboard",
			RedirectURL: "https://onboard-pre.evidenceledger.eu/callback",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

	case ISBE_PRO:

		// ISBE Keycloak in PRO
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Keycloak in PRO",
			Description: "The ISBE Keycloak in PRO application",
			ClientID:    "https://idp.pro.cloud-w.envs.redisbe.com",
			RedirectURL: "https://idp.portal.redisbe.com/auth/realms/pro-isbe/broker/certificado-representante/endpoint",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Catalog in PRO
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Catalog PRO",
			Description: "The ISBE Catalog application in PRO",
			ClientID:    "https://catalog.isbeonboard.com",
			RedirectURL: "https://catalog.pro.cloud-w.envs.redisbe.com/",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

		// ISBE Onboarding page in PRO
		db.UpsertRelyingParty(&models.RelyingParty{
			Name:        "ISBE Onboarding PRO",
			Description: "The ISBE Onboarding Application in PRO",
			ClientID:    "isbeonboard",
			RedirectURL: "https://onboard.portal.redisbe.com/callback",
			Scopes:      "openid eidas",
			TokenExpiry: 3600,
		}, "isbesecret")

	}

	slog.Info("Test data initialized", "rp_count", 3)
	return nil
}
