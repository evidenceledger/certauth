package certauth

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNotifySimple(t *testing.T) {
	_, err := notifySimple()
	if err != nil {
		t.Fatalf("notifySimple failed: %v", err)
	}
}

func TestVerifyCertificate(t *testing.T) {
	// 1. Read the info.txt file
	cert, err := os.ReadFile("./testdata/cert.txt")
	if err != nil {
		t.Fatalf("Failed to read cert.txt: %v", err)
	}

	// 2. Call VerifyCertificate
	resp, err := VerifyCertificate(string(cert))
	if err != nil {
		t.Fatalf("VerifyCertificate failed: %v", err)
	}

	// 3. Validate response is JSON
	if !json.Valid(resp) {
		t.Error("Response is not valid JSON")
	}
}
