package certconfig

import "github.com/evidenceledger/certauth/tsaservice"

type Config struct {
	Development  bool
	CertAuthURL  string
	CertAuthPort string
	CertSecURL   string
	CertSecPort  string
	TSAConfig    *tsaservice.TSAConfig
}
