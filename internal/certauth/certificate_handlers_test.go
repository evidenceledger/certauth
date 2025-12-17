package certauth

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyCertificate(t *testing.T) {
	// 1. Read the info.txt file
	cert, err := os.ReadFile("./testdata/cert.txt")
	if err != nil {
		t.Fatalf("Failed to read cert.txt: %v", err)
	}

	// 2. Call VerifyCertificate
	resp, err := VerifyCertificate(string(cert), "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate")
	if err != nil {
		t.Fatalf("VerifyCertificate failed: %v", err)
	}

	// 3. Validate response is JSON
	if !json.Valid(resp) {
		t.Error("Response is not valid JSON")
	}
}
