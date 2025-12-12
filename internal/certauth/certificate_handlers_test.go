package certauth

import (
	"testing"
)

func TestNotifySimple(t *testing.T) {
	_, err := notifySimple()
	if err != nil {
		t.Fatalf("notifySimple failed: %v", err)
	}
}
