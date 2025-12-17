package mainserver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/certauth"
	"github.com/evidenceledger/certauth/internal/certsec"
	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/errl"
	onboard "github.com/evidenceledger/certauth/internal/onboard"
)

// Config is the configuration for the server.
// It contains the configuration for CertAuth, CertSec and Onboard servers.
type Config struct {
	Development    bool
	OnboardURL     string
	OnboardPort    string
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
func New(adminPassword string, cfg Config) (*Server, error) {

	// Create a global in-memory cache with expiration time of 10 minutes
	cache := cache.New(10 * time.Minute)

	// Initialize database
	db, err := database.New("")
	if err != nil {
		slog.Error("Failed to initialize database", "error", err)
		return nil, errl.Errorf("failed to initialize database: %w", err)
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
		CertSecURL:              cfg.CertAuthConfig.CertAuthURL,
		CertSecPort:             cfg.CertAuthConfig.CertAuthPort,
	}
	certsecServer, err := certsec.New(db, cache, newCertSecConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create certsec server: %w", err)
	}

	// If in development mode, create the Onboard application server.
	// It uses the CertAuth server as the OP.

	var onboardServer *onboard.Server
	if cfg.OnboardURL != "" {
		clientid := "isbeonboard"
		clientsecret := "isbesecret"
		if cfg.Development {
			clientid = "testonboard"
			clientsecret = "isbesecret"
		}
		onboardServer = onboard.New(cfg.OnboardPort, cfg.OnboardURL, cfg.CertAuthConfig.CertAuthURL, clientid, clientsecret)
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
