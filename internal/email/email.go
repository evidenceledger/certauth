package email

import (
	"embed"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/html"
)

// Service represents an email service
type Service struct {
	smtpHost     string
	smtpPort     string
	smtpUsername string
	smtpPassword string
	fromEmail    string
	fromName     string
	htmlrender   *html.RendererStd
}

// EmailData represents the data passed to email templates
type EmailData struct {
	VerificationCode string
	ExpiresAt        time.Time
	AppName          string
}

const templateDebug = true

//go:embed views/*
var viewsfs embed.FS

// NewService creates a new email service
func NewService() (*Service, error) {
	// Parse email templates

	// The engine to display the screens HTML screens to the users
	htmlrender, err := html.NewRendererStd(templateDebug, viewsfs, "internal/certauth/views", ".hbs")
	if err != nil {
		return nil, errl.Errorf("failed to initialize template engine: %w", err)
	}

	return &Service{
		smtpHost:     getEnvOrDefault("SMTP_HOST", "localhost"),
		smtpPort:     getEnvOrDefault("SMTP_PORT", "587"),
		smtpUsername: getEnvOrDefault("SMTP_USERNAME", ""),
		smtpPassword: getEnvOrDefault("SMTP_PASSWORD", ""),
		fromEmail:    getEnvOrDefault("FROM_EMAIL", "noreply@certauth.mycredential.eu"),
		fromName:     getEnvOrDefault("FROM_NAME", "CertAuth"),
		htmlrender:   htmlrender,
	}, nil
}

// SendVerificationEmail sends a verification email with a code
func (s *Service) SendVerificationEmail(toEmail string, verificationCode string) error {
	// Validate email format
	if err := s.ValidateEmail(toEmail); err != nil {
		return errl.Errorf("invalid email: %w", err)
	}

	// Prepare email data
	data := EmailData{
		VerificationCode: verificationCode,
		ExpiresAt:        time.Now().Add(10 * time.Minute),
		AppName:          "CertAuth",
	}

	// Generate email body using template
	body, err := s.htmlrender.RenderToBuffer("email_confirmation", data)
	if err != nil {
		return errl.Errorf("failed to execute email template: %w", err)
	}

	// Send the email
	subject := "Email Verification Required - CertAuth"
	return s.sendEmail(toEmail, subject, body.String())
}

// sendEmail sends an email using SMTP
func (s *Service) sendEmail(toEmail string, subject string, body string) error {
	// For development/testing, if no SMTP credentials are provided, just log the email
	if s.smtpUsername == "" || s.smtpPassword == "" {
		slog.Info("Email would be sent (development mode)",
			"to", toEmail,
			"subject", subject,
			"body_length", len(body))
		return nil
	}

	// Create message
	message := fmt.Sprintf("From: %s <%s>\r\n", s.fromName, s.fromEmail)
	message += fmt.Sprintf("To: %s\r\n", toEmail)
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "MIME-Version: 1.0\r\n"
	message += "Content-Type: text/html; charset=UTF-8\r\n"
	message += "\r\n"
	message += body

	// Connect to SMTP server
	auth := smtp.PlainAuth("", s.smtpUsername, s.smtpPassword, s.smtpHost)
	addr := fmt.Sprintf("%s:%s", s.smtpHost, s.smtpPort)

	var err error
	if s.smtpPort == "587" {
		err = smtp.SendMail(addr, auth, s.fromEmail, []string{toEmail}, []byte(message))
	} else {
		// For port 465, use TLS
		err = smtp.SendMail(addr, auth, s.fromEmail, []string{toEmail}, []byte(message))
	}

	if err != nil {
		return errl.Errorf("failed to send email: %w", err)
	}

	slog.Info("Verification email sent", "to", toEmail)
	return nil
}

// ValidateEmail validates email format
func (s *Service) ValidateEmail(email string) error {
	if email == "" {
		return errl.Errorf("email is required")
	}

	if !strings.Contains(email, "@") {
		return errl.Errorf("invalid email format")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errl.Errorf("invalid email format")
	}

	if parts[0] == "" || parts[1] == "" {
		return errl.Errorf("invalid email format")
	}

	if !strings.Contains(parts[1], ".") {
		return errl.Errorf("invalid email format")
	}

	return nil
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
