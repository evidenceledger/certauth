package database

import (
	"log/slog"

	"github.com/evidenceledger/certauth/internal/models"
)

// initializePredefinedRPs adds some predefined Relying Parties to the database
func (d *Database) initializePredefinedRPs() error {

	// ISBE Keycloak in DEV
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Keycloak in DEV",
		Description: "The ISBE Keycloak in DEV application",
		ClientID:    "https://idp.dev.cloud-w.envs.redisbe.com",
		RedirectURL: "https://idp.dev.cloud-w.envs.redisbe.com/auth/realms/dev-isbe/broker/certificado-representante/endpoint",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Keycloak in PRE
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Keycloak in PRE",
		Description: "The ISBE Keycloak in PRE application",
		ClientID:    "https://idp.pre.cloud-w.envs.redisbe.com",
		RedirectURL: "https://idp.pre.cloud-w.envs.redisbe.com/auth/realms/pre-isbe/broker/certificado/endpoint",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// // Add Private Area as RP
	// portalRP := &models.RelyingParty{
	// 	Name:        "ISBE Private Area",
	// 	Description: "The ISBE Private Area application",
	// 	ClientID:    "https://idp-isbe.digitelts.com",
	// 	RedirectURL: "https://idp-isbe.digitelts.com/realms/portal/broker/certificates-idp/endpoint",
	// 	Scopes:      "openid eidas",
	// 	TokenExpiry: 3600,
	// }
	// d.UpsertRelyingParty(portalRP, "isbesecret")

	// ISBE Catalog in netlify
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Catalog Netlify",
		Description: "The ISBE Catalog application in Netlify",
		ClientID:    "https://catalog.isbeonboard.com",
		RedirectURL: "https://isbecatalog.netlify.app/",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Onboarding page in DEV
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Onboarding DEV",
		Description: "The ISBE Onboarding Application in DEV",
		ClientID:    "isbeonboard",
		RedirectURL: "https://onboard-dev.redisbe.com/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Onboarding page in mycredential.eu
	testOnboardRP := &models.RelyingParty{
		Name:        "ISBE Onboarding mycredential.eu",
		Description: "The ISBE Onboarding Application in mycredential.eu",
		ClientID:    "testonboard",
		RedirectURL: "https://onboard.mycredential.eu/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	d.UpsertRelyingParty(testOnboardRP, "isbesecret")

	// ISBE Issuer for test
	testIssuerRP := &models.RelyingParty{
		Name:        "ISBE Issuer for test",
		Description: "The ISBE Credential Issuer Application",
		ClientID:    "https://issuer.mycredential.eu",
		RedirectURL: "https://issuer.mycredential.eu/lear/auth/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}

	d.UpsertRelyingParty(testIssuerRP, "isbesecret")

	slog.Info("Test data initialized", "rp_count", 3)
	return nil
}
