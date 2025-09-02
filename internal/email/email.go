package email

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
)

// Service represents an email service
type Service struct {
	smtpHost     string
	smtpPort     string
	smtpUsername string
	smtpPassword string
	fromEmail    string
	fromName     string
	templates    *template.Template
}

// EmailData represents the data passed to email templates
type EmailData struct {
	VerificationCode string
	ExpiresAt        time.Time
	AppName          string
}

// NewService creates a new email service
func NewService() *Service {
	// Parse email templates
	tmpl, err := template.New("email").Parse(verificationEmailTemplate)
	if err != nil {
		slog.Error("Failed to parse email templates", "error", err)
		panic(err)
	}

	return &Service{
		smtpHost:     getEnvOrDefault("SMTP_HOST", "localhost"),
		smtpPort:     getEnvOrDefault("SMTP_PORT", "587"),
		smtpUsername: os.Getenv("SMTP_USERNAME"),
		smtpPassword: os.Getenv("SMTP_PASSWORD"),
		fromEmail:    getEnvOrDefault("FROM_EMAIL", "noreply@certauth.mycredential.eu"),
		fromName:     getEnvOrDefault("FROM_NAME", "CertAuth"),
		templates:    tmpl,
	}
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
	var body bytes.Buffer
	if err := s.templates.Execute(&body, data); err != nil {
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

// verificationEmailTemplate is the HTML template for verification emails
const verificationEmailTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - {{.AppName}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 24px;
        }
        .header p {
            color: #7f8c8d;
            margin: 10px 0 0 0;
        }
        .verification-code {
            background-color: #f8f9fa;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
        }
        .verification-code h2 {
            color: #495057;
            margin: 0;
            font-size: 32px;
            letter-spacing: 4px;
            font-family: 'Courier New', monospace;
        }
        .info {
            background-color: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 20px 0;
        }
        .info h3 {
            margin: 0 0 10px 0;
            color: #1976d2;
        }
        .info ul {
            margin: 0;
            padding-left: 20px;
        }
        .info li {
            margin: 5px 0;
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
            font-size: 12px;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Verification Required</h1>
            <p>{{.AppName}} - Certificate Authentication Service</p>
        </div>

        <p>You have requested to authenticate using your eIDAS certificate. To complete the authentication process, please enter the following verification code:</p>

        <div class="verification-code">
            <h2>{{.VerificationCode}}</h2>
        </div>

        <div class="info">
            <h3>Important Information:</h3>
            <ul>
                <li>This code is valid until {{.ExpiresAt.Format "15:04"}} ({{.ExpiresAt.Format "02/01/2006"}})</li>
                <li>Do not share this code with anyone</li>
                <li>If you did not request this verification, please ignore this email</li>
                <li>This verification ensures you control the email address associated with your certificate</li>
            </ul>
        </div>

        <div class="warning">
            <strong>Security Notice:</strong> This verification code is required to ensure that you control the email address associated with your certificate. This helps prevent unauthorized access to your account.
        </div>

        <div class="footer">
            <p>This is an automated message from {{.AppName}}. Please do not reply to this email.</p>
            <p>If you have any questions, please contact your system administrator.</p>
        </div>
    </div>
</body>
</html>`
