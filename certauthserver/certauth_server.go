// Package certauth implements the main server logic for the CertAuth OpenID Provider and OID4VP Relying Party.
package certauth

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/evidenceledger/certauth/database"
	"github.com/evidenceledger/certauth/internal/cache"
	"github.com/evidenceledger/certauth/internal/email"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/html"
	"github.com/evidenceledger/certauth/internal/jwtservice"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/evidenceledger/certauth/internal/tmfservice"
	"github.com/evidenceledger/certauth/tsaservice"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

type Profile string

const (
	ALTIA_LOCAL Profile = "local"
	ALTIA_DEV   Profile = "altia-dev"
	ISBE_DEV    Profile = "isbe-dev"
	ISBE_PRE    Profile = "isbe-pre"
	ISBE_PRO    Profile = "isbe-pro"
)

// Configuration for the CertAuth server
type ConfigCertAuth struct {
	// If Development is true, we log more and use some default configuration options
	Development bool

	// The profile that we are running with
	Profile Profile

	// The URL and internal port for the CertAuth server, the one acting as an IdP
	CertAuthURL  string
	CertAuthPort string

	// The URL and internal port for the CertSec server, the one receiving directly the certificate from the user browser
	CertSecURL  string
	CertSecPort string

	// The Qualified Timestamping Authority configuration, to use for timestamping
	TSAConfig *tsaservice.TSAConfig

	// The email configuration, to use for sending emails to the user
	EmailConfig *email.EmailConfig

	// The URL for the management system where onboardings are reqistered
	ManagementURL string

	// The URL for the Digital Signature Services. We use it now for verification of certificates only.
	EUDSSURL string

	// The URL for the TM Forum server
	TMFServerURL string
}

// CertAuthServer represents the CertAuth server
// It acts as an OpenID Provider with the Relying Parties, and as an OID4VP Relying Party for the Wallet.
// In this way it insulates the OID4VP protocol from the Relying Parties, which just use standard OIDC to
// authenticate users and get an ID Token and an Access Token.
type CertAuthServer struct {
	// The HTTP server (using Fiber)
	httpServer *fiber.App

	// Configuration flags
	development bool
	profile     Profile

	// The URL and internal port for the CertAuth server, the one acting as an IdP
	certAuthURL  string
	certAuthPort string

	// The URL for the CertSec server, we will use it to obtain the certificate from the user browser
	certSecURL string

	// The URL for the management system where onboardings are reqistered
	managementURL string

	// The URL for the Digital Signature Services. We use it now for verification of certificates only.
	euDSSURL string

	// The database service
	db *database.Database

	// The JWT service to generate ID and access tokens
	jwtService *jwtservice.JWTService

	// The HTML renderer
	htmlRender *html.RendererFiber

	// The single session cache
	ssoCache *cache.GenericCache[string, *models.SSOSession]
	// The authentication process cache
	authprocCache *cache.GenericCache[string, *models.AuthProcess]

	// The TSA service
	tsaService *tsaservice.TSAService

	// The email service
	emailService *email.Service

	// The TMF service
	tmfService *tmfservice.TMFService
}

const templateDebug = true
const templateDirectory = "certauthserver/views"
const templateExtension = ".hbs"
const templateStaticResources = "certauthserver/views/assets"

//go:embed views/*
var viewsfs embed.FS

// NewCertAuth creates a new CertAuth server
func NewCertAuth(
	db *database.Database,
	authprocCache *cache.GenericCache[string, *models.AuthProcess],
	ssoCache *cache.GenericCache[string, *models.SSOSession],
	adminPassword string,
	cfg *ConfigCertAuth) (*CertAuthServer, error) {

	// The engine to display the screens HTML screens to the users
	htmlrender, err := html.NewRendererFiber(templateDebug, viewsfs, templateDirectory, templateExtension)
	if err != nil {
		return nil, errl.Errorf("failed to initialize template engine: %w", err)
	}

	httpServer := fiber.New(fiber.Config{
		AppName:                 "CertAuth OP",
		ServerHeader:            "CertAuth",
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Observability
	prometheus := fiberprometheus.New("certauth")
	prometheus.RegisterAt(httpServer, "/metrics")
	httpServer.Use(prometheus.Middleware)

	// Recover middleware recovers from panics anywhere in the stack chain and handles the control to the centralized ErrorHandler
	httpServer.Use(recover.New())

	// Helmet middleware helps secure your apps by setting various HTTP headers.
	httpServer.Use(helmet.New())

	// Ignores favicon requests
	httpServer.Use(favicon.New())

	// Logs HTTP request/response details
	httpServer.Use(logger.New())

	// Enable CORS for all origins
	httpServer.Use(cors.New())

	httpServer.Static("/static", templateStaticResources)

	// Initialize JWT service, with us as the JWT Issuer
	jwtService, err := jwtservice.New(cfg.CertAuthURL)
	if err != nil {
		return nil, errl.Errorf("failed to initialize JWT service: %w", err)
	}

	// Initialize timestamping service
	tsaService, err := tsaservice.NewTSAService(cfg.TSAConfig)
	if err != nil {
		return nil, errl.Errorf("failed to initialize TSA service: %w", err)
	}

	// Initialize the email service
	emailService, err := email.NewService(cfg.EmailConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create email service: %v", err)
	}

	// Initialize the tmfservice
	slog.Info("TMF server URL", "url", cfg.TMFServerURL)
	tmfservice, err := tmfservice.NewTMFService(&tmfservice.TMFClientConfig{
		BaseURL: cfg.TMFServerURL,
		Timeout: 30,
	})
	if err != nil {
		return nil, errl.Errorf("failed to create tmfservice: %v", err)
	}

	// Put everything together in a server
	s := &CertAuthServer{
		development:   cfg.Development,
		profile:       cfg.Profile,
		certAuthURL:   cfg.CertAuthURL,
		certAuthPort:  cfg.CertAuthPort,
		certSecURL:    cfg.CertSecURL,
		managementURL: cfg.ManagementURL,
		euDSSURL:      cfg.EUDSSURL,
		httpServer:    httpServer,
		db:            db,
		jwtService:    jwtService,
		htmlRender:    htmlrender,
		authprocCache: authprocCache,
		ssoCache:      ssoCache,
		tsaService:    tsaService,
		emailService:  emailService,
		tmfService:    tmfservice,
	}

	// Register the health check endpoint
	s.httpServer.Get("/health", func(c *fiber.Ctx) error {
		slog.Info("Health check", "from", c.Hostname())
		return c.JSON(fiber.Map{"status": "healthy", "hostname": c.Hostname()})
	})

	// Register the OpenID Provider (OP) endpoints to support Relying Parties
	s.registerOIDCHandlers()

	// Register the endpoints for OIDVP with the Wallet
	s.registerWalletHandlers()

	// Register the eIDAS certificate endpoints to talk with CertSec (requesting the certificate from the browser)
	s.registerCertificateHandlers()

	// Register the admin endpoints (protected)
	s.registerAdminHandlers(adminPassword)

	return s, nil
}

// Start starts the server
func (s *CertAuthServer) Start(ctx context.Context) error {

	if s.httpServer == nil {
		return errors.New("server not initialized")
	}

	addr := net.JoinHostPort("0.0.0.0", s.certAuthPort)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.Listen(addr); err != nil {
			errChan <- fmt.Errorf("failed to start server: %w", err)
		}
	}()
	slog.Info("CertAuth server started", "addr", addr)

	// Wait for context cancellation or error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.httpServer.Shutdown()
	}

}
