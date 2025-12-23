package database

import (
	"log/slog"

	"github.com/evidenceledger/certauth/internal/models"
)

// initializePredefinedRPs adds some predefined Relying Parties to the database
func (d *Database) initializePredefinedRPs() error {

	// ************ KEYCLOAK ************
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
		ClientID:    "https://pre.idp.portal.redisbe.com",
		RedirectURL: "https://pre.idp.portal.redisbe.com/auth/realms/pre-isbe/broker/certificado-representante/endpoint",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Keycloak in PRO
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Keycloak in PRO",
		Description: "The ISBE Keycloak in PRO application",
		ClientID:    "https://idp.portal.redisbe.com",
		RedirectURL: "https://idp.portal.redisbe.com/auth/realms/pro-isbe/broker/certificado-representante/endpoint",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")


	// ************ CATALOG ************
	// ISBE Catalog in Netlify
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Catalog Netlify",
		Description: "The ISBE Catalog application in Netlify",
		ClientID:    "https://catalog.isbeonboard.com",
		RedirectURL: "https://isbecatalog.netlify.app/",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ************ ONBOARDING ************
	// ISBE Onboarding page in DEV
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Onboarding DEV",
		Description: "The ISBE Onboarding Application in DEV",
		ClientID:    "isbeonboard",
		RedirectURL: "https://onboard-dev.redisbe.com/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Onboarding page in PRE
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Onboarding PRE",
		Description: "The ISBE Onboarding Application in PRE",
		ClientID:    "isbeonboard",
		RedirectURL: "https://pre.onboard.portal.redisbe.com/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Onboarding page in PRO	d.UpsertRelyingParty(&models.RelyingParty{
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Onboarding PRO",
		Description: "The ISBE Onboarding Application in PRO",
		ClientID:    "isbeonboard",
		RedirectURL: "https://onboard.portal.redisbe.com/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Onboarding page in mycredential.eu
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Onboarding mycredential.eu",
		Description: "The ISBE Onboarding Application in mycredential.eu",
		ClientID:    "testonboard",
		RedirectURL: "https://onboard.mycredential.eu/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	// ISBE Issuer for mycredential.eu
	d.UpsertRelyingParty(&models.RelyingParty{
		Name:        "ISBE Issuer mycredential.eu",
		Description: "The ISBE Credential Issuer Application",
		ClientID:    "https://issuer.mycredential.eu",
		RedirectURL: "https://issuer.mycredential.eu/lear/auth/callback",
		Scopes:      "openid eidas",
		TokenExpiry: 3600,
	}, "isbesecret")

	slog.Info("Test data initialized", "rp_count", 3)
	return nil
}
