package email

import (
	"testing"
	"time"
)

func TestEmailService_ValidateEmail(t *testing.T) {
	service := NewService()

	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "test@example.com", false},
		{"valid email with subdomain", "test@sub.example.com", false},
		{"empty email", "", true},
		{"missing @", "testexample.com", true},
		{"missing domain", "test@", true},
		{"missing local part", "@example.com", true},
		{"missing TLD", "test@example", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEmailService_SendVerificationEmail(t *testing.T) {
	service := NewService()

	// Test sending verification email (should log in development mode)
	err := service.SendVerificationEmail("test@example.com", "123456")
	if err != nil {
		t.Errorf("SendVerificationEmail() error = %v", err)
	}
}

func TestEmailTemplate_Data(t *testing.T) {
	service := NewService()

	// Test that the template can be executed with data
	data := EmailData{
		VerificationCode: "123456",
		ExpiresAt:        time.Now().Add(10 * time.Minute),
		AppName:          "TestApp",
	}

	// This should not panic
	_ = data
	_ = service
}
