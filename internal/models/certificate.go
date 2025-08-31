package models

import (
	"crypto/x509"
	"time"

	"github.com/evidenceledger/certauth/internal/util/x509util"
)

// CertificateData represents certificate information for exchange between services
type CertificateData struct {
	OrganizationID  string             `json:"organization_identifier"`
	Subject         *x509util.ELSIName `json:"subject"`
	Issuer          *x509util.ELSIName `json:"issuer"`
	ValidFrom       time.Time          `json:"valid_from"`
	ValidTo         time.Time          `json:"valid_to"`
	CertificateType string             `json:"certificate_type"` // "organizational" or "personal"
	Certificate     *x509.Certificate  `json:"certificate"`
}
