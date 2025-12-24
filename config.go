package main

import (
	"flag"
	"log/slog"
	"os"
	"strings"

	certauth "github.com/evidenceledger/certauth/certauthserver"
	"github.com/evidenceledger/certauth/internal/email"
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/mainserver"
	"github.com/evidenceledger/certauth/tsaservice"
	"github.com/goccy/go-yaml"
)

// Profiles for different environments
const (
	LOCAL     = "local"
	ALTIA_DEV = "altia-dev"
	ISBE_DEV  = "isbe-dev"
	ISBE_PRE  = "isbe-pre"
	ISBE_PRO  = "isbe-pro"
)

// Default Configuration Constants
const (
	defaultCaCertURL     = "http://pki.digitelts.es/DIGITELTSCAROOT01.pem"
	defaultTsaURL        = "https://timestamp-service.pre-api.digitelts.com/tsa"
	defaultEUDSSURL      = "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate"
	defaultManagementURL = "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements"
)

// --- Secret Configuration Structures ---

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

// --- Predefined Configurations ---

var defaultTsaConfig = &tsaservice.TSAConfig{
	TSAURL:    defaultTsaURL,
	CACertURL: defaultCaCertURL,
	EUDSSURL:  defaultEUDSSURL,
}

var defaultEmailConfig = &email.EmailConfig{
	IMAP:     "imap.serviciodecorreo.es",
	SMTP:     "smtp.serviciodecorreo.es",
	SMTPPort: "465",
}

var LOCAL_CFG = mainserver.Config{
	Development:  true,
	OnboardURL:   "https://onboard.mycredential.eu",
	OnboardPort:  "8012",
	PrivateArea:  "/",
	TMFServerURL: "https://tmf.evidenceledger.eu/",
	CertAuthConfig: &certauth.Config{
		Development:   true,
		CertAuthURL:   "https://certauth.mycredential.eu",
		CertAuthPort:  "8010",
		CertSecURL:    "https://certsec.mycredential.eu",
		CertSecPort:   "8011",
		TSAConfig:     defaultTsaConfig,
		EmailConfig:   defaultEmailConfig,
		ManagementURL: defaultManagementURL,
		EUDSSURL:      defaultEUDSSURL,
	},
}

var ALTIA_DEV_CFG = mainserver.Config{
	Development:  true,
	OnboardURL:   "https://onboard-dev.redisbe.com",
	OnboardPort:  "8012",
	PrivateArea:  "https://poc-front.dev.cloud-w.envs.redisbe.com/",
	TMFServerURL: "https://tmf.evidenceledger.eu/",
	CertAuthConfig: &certauth.Config{
		Development:   true,
		CertAuthURL:   "https://certauth-dev.redisbe.com",
		CertAuthPort:  "8010",
		CertSecURL:    "https://certsec.evidenceledger.eu",
		CertSecPort:   "8011",
		TSAConfig:     defaultTsaConfig,
		EmailConfig:   defaultEmailConfig,
		ManagementURL: "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      defaultEUDSSURL,
	},
}

var ISBE_DEV_CFG = mainserver.Config{
	Development:  true,
	OnboardURL:   "https://onboard.dev.cloud-w.envs.redisbe.com",
	OnboardPort:  "8012",
	PrivateArea:  "https://poc-front.dev.cloud-w.envs.redisbe.com/",
	TMFServerURL: "https://tmf.dev.cloud-w.envs.redisbe.com/tmf-api",
	CertAuthConfig: &certauth.Config{
		Development:   true,
		CertAuthURL:   "https://certauth.dev.cloud-w.envs.redisbe.com",
		CertAuthPort:  "8010",
		CertSecURL:    "https://certsec.dev.cloud-w.envs.redisbe.com",
		CertSecPort:   "8011",
		TSAConfig:     defaultTsaConfig,
		EmailConfig:   defaultEmailConfig,
		ManagementURL: "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      defaultEUDSSURL,
	},
}

var ISBE_PRE_CFG = mainserver.Config{
	Development:  true,
	OnboardURL:   "https://pre.onboard.portal.redisbe.com",
	OnboardPort:  "8012",
	PrivateArea:  "https://pre.portal.redisbe.com/",
	TMFServerURL: "https://tmf-pre.evidenceledger.eu",
	CertAuthConfig: &certauth.Config{
		Development:   true,
		CertAuthURL:   "https://pre.certauth.portal.redisbe.com",
		CertAuthPort:  "8010",
		CertSecURL:    "https://certsec-pre.evidenceledger.eu",
		CertSecPort:   "8011",
		TSAConfig:     defaultTsaConfig,
		EmailConfig:   defaultEmailConfig,
		ManagementURL: "https://poc-middleware-management.pre.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      defaultEUDSSURL,
	},
}

var ISBE_PRO_CFG = mainserver.Config{
	Development:  false,
	OnboardURL:   "https://onboard.portal.redisbe.com",
	OnboardPort:  "8012",
	PrivateArea:  "https://portal.redisbe.com/",
	TMFServerURL: "https://tmf-pro.evidenceledger.eu",
	CertAuthConfig: &certauth.Config{
		Development:   false,
		CertAuthURL:   "https://certauth.portal.redisbe.com",
		CertAuthPort:  "8010",
		CertSecURL:    "https://certsec-pro.evidenceledger.eu",
		CertSecPort:   "8011",
		TSAConfig:     defaultTsaConfig,
		EmailConfig:   defaultEmailConfig,
		ManagementURL: "https://poc-middleware-management.pro.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      defaultEUDSSURL,
	},
}

// LoadConfig parses flags, environment variables, and config files to return the server configuration.
func LoadConfig() (*mainserver.Config, string, error) {
	var (
		development   bool
		adminPassword string
	)

	// If we are in development environment or not
	flag.BoolVar(&development, "dev", false, "Development mode")

	// The password for admin screens
	flag.StringVar(&adminPassword, "admin-password", "", "Admin password for the server")

	flag.Parse()

	// By default, we get the local profile, and maybe we override it with environment variables
	profile := LOCAL
	cfg := LOCAL_CFG

	// If a profile was specified, use it
	if profile = getStringEnvOrDefault("PROFILE", profile); profile != "" {
		profile = strings.ToLower(profile)

		switch profile {
		case LOCAL:
			cfg = LOCAL_CFG
		case ALTIA_DEV:
			cfg = ALTIA_DEV_CFG
		case ISBE_DEV:
			cfg = ISBE_DEV_CFG
		case ISBE_PRE:
			cfg = ISBE_PRE_CFG
		case ISBE_PRO:
			cfg = ISBE_PRO_CFG
		default:
			return nil, "", errl.Errorf("unknown profile: %s", profile)
		}

	}

	// Override with the environment variable if it is set
	cfg.Development = getBoolEnvOrDefault("CERTAUTH_DEVELOPMENT", cfg.Development)

	// Say if we are in development or not
	if cfg.Development {
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
		return nil, "", errl.Errorf("admin password required")
	}

	// Check for override of the CertAuth server URL and port
	cfg.CertAuthConfig.CertAuthURL = getStringEnvOrDefault("CERTAUTH_URL", cfg.CertAuthConfig.CertAuthURL)
	cfg.CertAuthConfig.CertAuthPort = getStringEnvOrDefault("CERTAUTH_PORT", cfg.CertAuthConfig.CertAuthPort)

	// Check for override of the CertSec server URL and port
	cfg.CertAuthConfig.CertSecURL = getStringEnvOrDefault("CERTSEC_URL", cfg.CertAuthConfig.CertSecURL)
	cfg.CertAuthConfig.CertSecPort = getStringEnvOrDefault("CERTSEC_PORT", cfg.CertAuthConfig.CertSecPort)

	// Check for override of the Onboard server URL and port
	cfg.OnboardURL = getStringEnvOrDefault("ONBOARD_URL", cfg.OnboardURL)
	cfg.OnboardPort = getStringEnvOrDefault("ONBOARD_PORT", cfg.OnboardPort)

	// Check for override of the TSA (Timestamping Authority) config
	cfg.CertAuthConfig.TSAConfig.TSAURL = getStringEnvOrDefault("TSA_URL", cfg.CertAuthConfig.TSAConfig.TSAURL)
	cfg.CertAuthConfig.TSAConfig.CACertURL = getStringEnvOrDefault("TSA_CA_CERT_URL", cfg.CertAuthConfig.TSAConfig.CACertURL)

	// Check for override of the DSS (Digital Signature Services) URL
	cfg.CertAuthConfig.EUDSSURL = getStringEnvOrDefault("DSS_URL", cfg.CertAuthConfig.EUDSSURL)

	// Check for override of the email service config
	cfg.CertAuthConfig.EmailConfig.IMAP = getStringEnvOrDefault("EMAIL_IMAP", cfg.CertAuthConfig.EmailConfig.IMAP)
	cfg.CertAuthConfig.EmailConfig.SMTP = getStringEnvOrDefault("EMAIL_SMTP", cfg.CertAuthConfig.EmailConfig.SMTP)
	cfg.CertAuthConfig.EmailConfig.SMTPPort = getStringEnvOrDefault("EMAIL_SMTP_PORT", cfg.CertAuthConfig.EmailConfig.SMTPPort)

	// Check for override of the management service URL
	cfg.CertAuthConfig.ManagementURL = getStringEnvOrDefault("MANAGEMENT_URL", cfg.CertAuthConfig.ManagementURL)

	// Set the profile in the CertAuth config
	cfg.CertAuthConfig.Profile = profile

	// The secrets are either in a file which is not in the Git repo or in the environment variables.
	secretConfig := parseYamlConfig("secrets/config.yaml")

	// The TSA credentials are secret and compulsory
	tsaUser := getStringEnvOrDefault("TSA_USER", secretConfig.TSACreds.User)
	tsaPassword := getStringEnvOrDefault("TSA_PASSWORD", secretConfig.TSACreds.Password)
	if tsaUser == "" || tsaPassword == "" {
		return nil, "", errl.Errorf("TSA user and password required")
	}

	// The email credentials are secret and compulsory
	emailUser := getStringEnvOrDefault("SMTP_USERNAME", secretConfig.EmailCreds.User)
	emailPassword := getStringEnvOrDefault("SMTP_PASSWORD", secretConfig.EmailCreds.Password)
	if emailUser == "" || emailPassword == "" {
		return nil, "", errl.Errorf("email user and password required")
	}

	// Update the config with the secrets
	cfg.CertAuthConfig.TSAConfig.TSAUser = tsaUser
	cfg.CertAuthConfig.TSAConfig.TSAPassword = tsaPassword
	cfg.CertAuthConfig.EmailConfig.User = emailUser
	cfg.CertAuthConfig.EmailConfig.Email = emailUser
	cfg.CertAuthConfig.EmailConfig.Password = emailPassword

	return &cfg, adminPassword, nil
}

// getStringEnvOrDefault gets an environment variable or returns a default value
func getStringEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getBoolEnvOrDefault gets an environment variable or returns a default value.
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

// parseYamlConfig reads a YAML configuration from the given filename.
func parseYamlConfig(filename string) SecretConfig {
	var out SecretConfig
	src, err := os.ReadFile(filename)
	if err != nil {
		return out
	}
	if err = yaml.Unmarshal(src, &out); err != nil {
		return out
	}
	return out
}
