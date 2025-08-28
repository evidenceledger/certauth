package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/evidenceledger/certauth/internal/certauth"
	"github.com/evidenceledger/certauth/internal/certsec"
	"github.com/evidenceledger/certauth/internal/database"
	"github.com/evidenceledger/certauth/internal/examplerp"
)

// Server manages both CertAuth and CertSec servers
type Server struct {
	certauth  *certauth.Server
	certsec   *certsec.Server
	examplerp *examplerp.Server
	db        *database.Database
	adminPW   string
}

// New creates a new server instance
func New(adminPassword string) *Server {
	// Initialize database
	db := database.New()

	// Create servers
	ca := certauth.New(db, adminPassword)
	cs := certsec.New(db)
	erp := examplerp.New("8092", "https://certauth.mycredential.eu", "example-rp", "example-secret")

	return &Server{
		certauth:  ca,
		certsec:   cs,
		examplerp: erp,
		db:        db,
		adminPW:   adminPassword,
	}
}

// Start starts both servers
func (s *Server) Start(ctx context.Context) error {
	// Initialize database
	if err := s.db.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	// Start CertAuth server (port 8090)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certauth.Start(ctx, ":8090"); err != nil {
			errChan <- fmt.Errorf("certauth server failed: %w", err)
		}
	}()

	// Start CertSec server (port 8091)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certsec.Start(ctx, ":8091"); err != nil {
			errChan <- fmt.Errorf("certsec server failed: %w", err)
		}
	}()

	// Start Example RP server (port 8092)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.examplerp.Start(); err != nil {
			errChan <- fmt.Errorf("example rp server failed: %w", err)
		}
	}()

	slog.Info("Servers started",
		"certauth_port", 8090,
		"certsec_port", 8091,
		"examplerp_port", 8092,
		"certauth_domain", "certauth.mycredential.eu",
		"certsec_domain", "certsec.mycredential.eu",
		"examplerp_url", "https://certauth.mycredential.eu/rp")

	// Wait for either server to fail or context to be cancelled
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		slog.Info("Shutting down servers")
		return nil
	}
}
