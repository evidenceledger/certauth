// Package mainserver implements the main entry point logic for the server, managing CertAuth, CertSec, and Onboard services.
package mainserver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	certauth "github.com/evidenceledger/certauth/certauthserver"
	certsec "github.com/evidenceledger/certauth/certsecserver"
	"github.com/evidenceledger/certauth/database"
	"github.com/evidenceledger/certauth/internal/cache"
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

// Server manages the CertAuth, CertSec and Onboard servers
type Server struct {
	cfg            Config
	certauthServer *certauth.CertAuthServer
	certsecServer  *certsec.CertSecServer
	onboardServer  *onboard.Server
	db             *database.Database
	adminPW        string
}

// New creates a new server instance.
// It initializes the database, cache, CertAuth, CertSec and Onboard servers.
func New(adminPassword string, cfg Config) (*Server, error) {

	// Create a global in-memory cache for authentication processes with a default expiration time of 10 minutes
	// TODO(hesusruiz): make this configurable
	authprocCache := cache.NewGeneric[string, *models.AuthProcess](10 * time.Minute)

	// Create a global in-memory cache for SSO sessions with a default expiration time of 10 minutes
	// TODO(hesusruiz): make this configurable
	ssoCache := cache.NewGeneric[string, *models.SSOSession](10 * time.Minute)

	// Initialize database with the default name
	db, err := database.New("")
	if err != nil {
		slog.Error("Failed to initialize database", "error", err)
		return nil, errl.Errorf("failed to initialize database: %w", err)
	}

	// Initialize predefined Relying Parties
	for _, rp := range cfg.PredefinedRPs {
		if err := db.UpsertRelyingParty(rp.RelyingParty, rp.ClientSecret); err != nil {
			return nil, errl.Errorf("failed to initialize RP %s: %w", rp.RelyingParty.Name, err)
		}
	}

	// Create the authentication and authorization servers.
	// They share the same database and authentication process cache.

	certauthServer, err := certauth.New(db, authprocCache, ssoCache, adminPassword, cfg.CertAuthConfig)
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
	certsecServer, err := certsec.New(db, authprocCache, ssoCache, newCertSecConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create certsec server: %w", err)
	}

	// If the Onboard URL is configured, create the Onboard application server.
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
