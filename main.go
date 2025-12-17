package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/evidenceledger/certauth/internal/certauth"
	"github.com/evidenceledger/certauth/internal/email"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/mainserver"
	"github.com/evidenceledger/certauth/internal/sqlogger"
	"github.com/evidenceledger/certauth/tsaservice"
	"github.com/goccy/go-yaml"
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

const (
	defaultCaCertURL     = "http://pki.digitelts.es/DIGITELTSCAROOT01.pem"
	defaultTsaURL        = "https://timestamp-service.pre-api.digitelts.com/tsa"
	defaultEUDSSURL      = "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate"
	defaultManagementURL = "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements"
)

var logLevel slog.Level = slog.LevelInfo

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {

	// Environment values have precedence over CLI flags or default values

	// If we are in development environment or not
	flag.BoolVar(&development, "dev", false, "Development mode")

	// The password for admin screens
	flag.StringVar(&adminPassword, "admin-password", "", "Admin password for the server")

	// The URL and port for the CertAuth server, which is the OP url also
	flag.StringVar(&certauthURL, "certauth-url", "https://certauth.mycredential.eu", "URL for the CertAuth server")
	flag.StringVar(&certauthPort, "certauth-port", "8010", "Port for the main OP server")

	// The URL and port for the CertSec server, the one asking for the certificate via TLS client authentication
	flag.StringVar(&certsecURL, "certsec-url", "https://certsec.mycredential.eu", "URL for the CertSec server")
	flag.StringVar(&certsecPort, "certsec-port", "8011", "Port for the CertSec server")

	// The URL and port for the Onboard server, the example RP
	flag.StringVar(&onboardURL, "onboard-url", "", "URL for the Onboard server")
	flag.StringVar(&onboardPort, "onboard-port", "8012", "Port for the Onboard server")

	flag.Parse()

	// Check if we are in development or production.
	// The environment variable takes precedence over the flag
	development = getBoolEnvOrDefault("CERTAUTH_DEVELOPMENT", development)

	// Initialize soon the custom SQLogHandler, so we can log the rest of the initialization process
	logOptions := &sqlogger.Options{
		Level:  &logLevel,
		LogDir: "data/logs",
	}

	// Check if the logs should be colored:
	// - If the process is running in a container (pid=1) then do not color the logs.
	// - Otherwise, if the environment variable CERTAUTH_LOGS_NOCOLOR is set to "true" then do not color the logs.
	ourpid := os.Getpid()
	if ourpid == 1 || getBoolEnvOrDefault("CERTAUTH_LOGS_NOCOLOR", false) {
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

	// Get admin password from command line or environment variable.
	// In any environment except development, the admin password is required.
	// In development, the admin password is optional, and if not provided, it will have a default value.
	adminPassword = getStringEnvOrDefault("CERTAUTH_ADMIN_PASSWORD", adminPassword)
	if development && adminPassword == "" {
		adminPassword = "pepe"
	} else if adminPassword == "" {
		return errl.Errorf("admin password required")
	}

	// Get the URL and port for the CertAuth server, which is the OP url also
	certauthURL = getStringEnvOrDefault("CERTAUTH_URL", certauthURL)
	certauthPort = getStringEnvOrDefault("CERTAUTH_PORT", certauthPort)

	// Get the URL and port for the CertSec server
	certsecURL = getStringEnvOrDefault("CERTSEC_URL", certsecURL)
	certsecPort = getStringEnvOrDefault("CERTSEC_PORT", certsecPort)

	// The Onboard application/server will be started only if explicitly stated in the environment or flag,
	// or in development mode
	onboardURL = getStringEnvOrDefault("ONBOARD_URL", onboardURL)
	onboardPort = getStringEnvOrDefault("ONBOARD_PORT", onboardPort)
	if development && onboardURL == "" {
		onboardURL = "https://onboard.mycredential.eu"
	}

	// Get the config for the secrets.
	// If the file does not exist, is empty or not parseable, we will use the environment variables.
	secretConfig := ParseYamlConfig("secrets/config.yaml")

	// Get the config for the TSA (Timestamping Authority)
	tsaURL := getStringEnvOrDefault("TSA_URL", defaultTsaURL)
	tsaCaCertURL := getStringEnvOrDefault("TSA_CA_CERT_URL", defaultCaCertURL)

	// The TSA credentials are secret
	tsaUser := getStringEnvOrDefault("TSA_USER", secretConfig.TSACreds.User)
	tsaPassword := getStringEnvOrDefault("TSA_PASSWORD", secretConfig.TSACreds.Password)
	// There is no default for the TSA user and password
	if tsaUser == "" || tsaPassword == "" {
		return errl.Errorf("TSA user and password required")
	}

	// Get the DSS (Digital Signature Services) URL
	dssURL := getStringEnvOrDefault("DSS_URL", defaultEUDSSURL)

	tsaCfg := &tsaservice.TSAConfig{
		TSAURL:      tsaURL,
		TSAUser:     tsaUser,
		TSAPassword: tsaPassword,
		CACertURL:   tsaCaCertURL,
		EUDSSURL:    dssURL,
	}

	// Get the config for the email service
	emailIMAP := getStringEnvOrDefault("EMAIL_IMAP", "imap.serviciodecorreo.es")
	emailSMTP := getStringEnvOrDefault("EMAIL_SMTP", "smtp.serviciodecorreo.es")
	emailSMTPPort := getStringEnvOrDefault("EMAIL_SMTP_PORT", "465")

	// The email credentials are secret
	emailUser := getStringEnvOrDefault("EMAIL_USER", secretConfig.EmailCreds.User)
	emailPassword := getStringEnvOrDefault("EMAIL_PASSWORD", secretConfig.EmailCreds.Password)
	// There is no default for the email user and password
	if emailUser == "" || emailPassword == "" {
		return errl.Errorf("email user and password required")
	}

	emailCfg := &email.EmailConfig{
		User:     emailUser,
		Password: emailPassword,
		Email:    emailUser,
		IMAP:     emailIMAP,
		SMTP:     emailSMTP,
		SMTPPort: emailSMTPPort,
	}

	// Get the URL for the management service
	managementURL := getStringEnvOrDefault("MANAGEMENT_URL", defaultManagementURL)

	// Configuration for the CertAuth server
	certauthConfig := &certauth.Config{
		Development:   development,
		CertAuthURL:   certauthURL,
		CertAuthPort:  certauthPort,
		CertSecURL:    certsecURL,
		CertSecPort:   certsecPort,
		TSAConfig:     tsaCfg,
		EmailConfig:   emailCfg,
		ManagementURL: managementURL,
		EUDSSURL:      dssURL,
	}

	// Configuration for the main server, including the CertAuth server config and Onboard server config
	cfg := mainserver.Config{
		Development:    development,
		OnboardURL:     onboardURL,
		OnboardPort:    onboardPort,
		CertAuthConfig: certauthConfig,
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

// getStringEnvOrDefault gets an environment variable or returns a default value
// The environment variable is expected to be a string value
func getStringEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getBoolEnvOrDefault gets an environment variable or returns a default value.
// The environment variable is expected to be a boolean value.
// If the environment variable is set, only "true" (case insensitive) will return true,
// and any other value will return false.
// If the environment variable is not set, the default value will be returned.
func getBoolEnvOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if strings.ToLower(value) == "true" {
			return true
		} else {
			return false
		}
	}
	return defaultValue
}

type SecretConfig struct {
	AgeRecipient string     `yaml:"age_recipient"`
	TSACreds     TSACreds   `yaml:"tsa"`
	EmailCreds   EmailCreds `yaml:"email"`
}

type TSACreds struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type EmailCreds struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

// ParseYamlConfig reads a YAML configuration from the given filename.
func ParseYamlConfig(filename string) SecretConfig {
	var out SecretConfig
	src, err := os.ReadFile(filename)
	if err != nil {
		// We just return the empty struct if the file is not found
		return out
	}
	if err = yaml.Unmarshal(src, &out); err != nil {
		// We just return the empty struct if the file can not be parsed
		return out
	}
	return out
}
