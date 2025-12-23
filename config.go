package main

import (
	"github.com/evidenceledger/certauth/internal/certauth"
	"github.com/evidenceledger/certauth/internal/email"
	"github.com/evidenceledger/certauth/internal/mainserver"
	"github.com/evidenceledger/certauth/tsaservice"
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

// The TSA is the same for all environments.
// We do not specify here the credentials, as they must be specified in the environment variables
var tsaConfig = &tsaservice.TSAConfig{
	TSAURL:    "https://timestamp-service.pre-api.digitelts.com/tsa",
	CACertURL: "http://pki.digitelts.es/DIGITELTSCAROOT01.pem",
	EUDSSURL:  "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate",
}

// The email server configuration is the same for all environments.
// We do not specify here the credentials, as they must be specified in the environment variables
var emailConfig = &email.EmailConfig{
	IMAP:     "imap.serviciodecorreo.es",
	SMTP:     "smtp.serviciodecorreo.es",
	SMTPPort: "465",
}

var ALTIA_LOCAL_CFG = mainserver.Config{
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
		TSAConfig:     tsaConfig,
		EmailConfig:   emailConfig,
		ManagementURL: "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate",
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
		TSAConfig:     tsaConfig,
		EmailConfig:   emailConfig,
		ManagementURL: "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate",
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
		TSAConfig:     tsaConfig,
		EmailConfig:   emailConfig,
		ManagementURL: "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate",
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
		TSAConfig:     tsaConfig,
		EmailConfig:   emailConfig,
		ManagementURL: "https://poc-middleware-management.pre.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate",
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
		TSAConfig:     tsaConfig,
		EmailConfig:   emailConfig,
		ManagementURL: "https://poc-middleware-management.pro.cloud-w.envs.redisbe.com/api/managements",
		EUDSSURL:      "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate",
	},
}

var profiles = map[string]mainserver.Config{
	ALTIA_LOCAL: ALTIA_LOCAL_CFG,
	ALTIA_DEV:   ALTIA_DEV_CFG,
	ISBE_DEV:    ISBE_DEV_CFG,
	ISBE_PRE:    ISBE_PRE_CFG,
	ISBE_PRO:    ISBE_PRO_CFG,
}
