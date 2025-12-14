package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/mainserver"
	"github.com/evidenceledger/certauth/internal/sqlogger"
)

var (
	development bool

	adminPassword string
	certauthPort  string
	certsecPort   string
	certauthURL   string
	certsecURL    string
	onboardURL    string
	onboardPort   string
)

var logLevel slog.Level = slog.LevelInfo

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	// If we are in development environment or not
	flag.BoolVar(&development, "dev", false, "Development mode")

	// The password for admin screens
	flag.StringVar(&adminPassword, "admin-password", "", "Admin password for the server")

	// The URL and port for the CertAuth server, which is the OP url also
	flag.StringVar(&certauthPort, "certauth-port", "8010", "Port for the main OP server")
	flag.StringVar(&certauthURL, "certauth-url", "https://certauth.mycredential.eu", "URL for the CertAuth server")

	// The URL and port for the CertSec server, the one asking for the certificate via TLS client authentication
	flag.StringVar(&certsecPort, "certsec-port", "8011", "Port for the CertSec server")
	flag.StringVar(&certsecURL, "certsec-url", "https://certsec.mycredential.eu", "URL for the CertSec server")

	// The URL and port for the Onboard server, the example RP
	flag.StringVar(&onboardPort, "onboard-port", "8012", "Port for the Onboard server")
	flag.StringVar(&onboardURL, "onboard-url", "", "URL for the Onboard server")

	flag.Parse()

	// Check if we are in development or production.
	// The environment variable takes precedence over the flag
	if strings.ToLower(os.Getenv("CERTAUTH_DEVELOPMENT")) == "true" {
		development = true
	}

	// Initialize the custom SQLogHandler
	logOptions := &sqlogger.Options{
		Level:  &logLevel,
		LogDir: "data/logs",
	}

	// Check if the logs should be colored:
	// - If the process is running in a container (pid=1) then do not color the logs
	// - If the environment variable CERTAUTH_LOGS_NOCOLOR is set to "true" then do not color the logs
	ourpid := os.Getpid()
	if ourpid == 1 || os.Getenv("CERTAUTH_LOGS_NOCOLOR") == "true" {
		logOptions.NoColor = true
	}

	// Initialize the logging system
	sqlog, err := sqlogger.NewSQLogHandler(logOptions)
	if err != nil {
		return errl.Errorf("failed to initialize SQLogHandler: %v", err)
	}
	defer sqlog.Close()

	// And set the default logging system for all components
	slog.SetDefault(slog.New(sqlog))

	// Say if we are in development or not
	if development {
		slog.Info("Running in development mode")
	} else {
		slog.Info("Running in production mode")
	}

	// Get admin password from command line (priority) or environment variable
	if adminPassword == "" {
		adminPassword = os.Getenv("CERTAUTH_ADMIN_PASSWORD")
		if adminPassword == "" {
			if development {
				adminPassword = "pepe"
			} else {
				return errl.Errorf("admin password required")
			}
		}
	}

	certauthURL = getEnvOrDefault("CERTAUTH_URL", certauthURL)
	certauthPort = getEnvOrDefault("CERTAUTH_PORT", certauthPort)
	certsecURL = getEnvOrDefault("CERTSEC_URL", certsecURL)
	certsecPort = getEnvOrDefault("CERTSEC_PORT", certsecPort)

	// The Onboard application/server will be started only if explicitly stated in the environment or flag, or in development mode
	if os.Getenv("ONBOARD_URL") != "" {
		onboardURL = os.Getenv("ONBOARD_URL")
	}
	if development && onboardURL == "" {
		onboardURL = "https://onboard.mycredential.eu"
	}

	// Create the configuration
	cfg := mainserver.Config{
		Development:  development,
		CertAuthPort: certauthPort,
		CertAuthURL:  certauthURL,
		CertSecPort:  certsecPort,
		CertSecURL:   certsecURL,
		OnboardPort:  onboardPort,
		OnboardURL:   onboardURL,
	}

	// Create the main server. This will initialize the individual HTTP services and the database.
	srv, err := mainserver.New(adminPassword, cfg)
	if err != nil {
		return errl.Errorf("failed to create server: %v", err)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutdown signal received")
		cancel()
	}()

	// Start server
	if err := srv.Start(ctx); err != nil {
		return errl.Errorf("server failed: %v", err)
	}

	return nil
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
