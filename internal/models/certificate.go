package models

import (
	"time"

	"github.com/evidenceledger/certauth/x509util"
)

// CertificateData represents certificate information for exchange between services
type CertificateData struct {
	Subject         *x509util.ELSIName `json:"subject"`
	Issuer          *x509util.ELSIName `json:"issuer"`
	ValidFrom       time.Time          `json:"valid_from"`
	ValidTo         time.Time          `json:"valid_to"`
	OrganizationID  string             `json:"organization_identifier"`
	CertificateType string             `json:"certificate_type"` // "organizational" or "personal"
}

// CertificateExchange represents the data exchanged between CertAuth and CertSec
type CertificateExchange struct {
	AuthCode        string           `json:"auth_code"`
	CertificateData *CertificateData `json:"certificate_data"`
	RPInfo          *RelyingParty    `json:"rp_info"`
	State           string           `json:"state"`
	Nonce           string           `json:"nonce"`
	Scope           string           `json:"scope"`
}

// CertificateConsentRequest represents a consent request from CertSec to CertAuth
type CertificateConsentRequest struct {
	AuthCode        string           `json:"auth_code"`
	CertificateData *CertificateData `json:"certificate_data"`
	ConsentGranted  bool             `json:"consent_granted"`
	State           string           `json:"state"`
}

// CertificateConsentResponse represents the response to a consent request
type CertificateConsentResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}
