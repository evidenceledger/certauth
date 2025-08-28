package examplerp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/evidenceledger/certauth/internal/models"
)

// Server represents the example RP server
type Server struct {
	port          string
	opBaseURL     string
	sessions      map[string]*models.RPSession
	sessionsMutex sync.RWMutex
	clientID      string
	clientSecret  string
}

// New creates a new example RP server
func New(port, opBaseURL, clientID, clientSecret string) *Server {
	return &Server{
		port:         port,
		opBaseURL:    opBaseURL,
		sessions:     make(map[string]*models.RPSession),
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Start starts the example RP server
func (s *Server) Start() error {
	http.HandleFunc("/", s.handleHome)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/callback", s.handleCallback)
	http.HandleFunc("/logout", s.handleLogout)

	addr := ":" + s.port
	slog.Info("Starting example RP server", "port", s.port, "op_base_url", s.opBaseURL)

	return http.ListenAndServe(addr, nil)
}

// handleHome handles the home page
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user is logged in
	sessionID := s.getSessionID(r)
	if session := s.getSession(sessionID); session != nil {
		s.renderWelcomePage(w, session)
		return
	}

	// Show login page
	s.renderLoginPage(w)
}

// handleLogin initiates the OIDC flow
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state for CSRF protection
	state := s.generateRandomString(32)

	// Generate nonce for replay protection
	nonce := s.generateRandomString(32)

	// Store state in session (in a real app, you'd use proper session management)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	// Redirect to OP
	redirectURL := fmt.Sprintf("%s/oauth2/auth?response_type=code&client_id=%s&redirect_uri=http://localhost:%s/callback&scope=openid%%20eidas&state=%s&nonce=%s",
		s.opBaseURL, s.clientID, s.port, state, nonce)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleCallback handles the OIDC callback
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get parameters from callback
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	error := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Validate state
	cookieState, err := r.Cookie("oauth_state")
	if err != nil || cookieState.Value != state {
		slog.Error("Invalid state parameter", "error", err)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	if error != "" {
		slog.Error("OIDC error received", "error", error, "description", errorDescription)
		s.renderErrorPage(w, error, errorDescription)
		return
	}

	// Exchange code for tokens
	tokens, err := s.exchangeCodeForTokens(code)
	if err != nil {
		slog.Error("Failed to exchange code for tokens", "error", err)
		http.Error(w, "Failed to exchange code for tokens", http.StatusInternalServerError)
		return
	}

	// Create user session
	session := s.createSession(tokens)

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "rp_session",
		Value:    session.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout handles user logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "rp_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// Helper methods

func (s *Server) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *Server) getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("rp_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) getSession(sessionID string) *models.RPSession {
	s.sessionsMutex.RLock()
	defer s.sessionsMutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check if session is expired (1 hour)
	if time.Since(session.LastAccessed) > time.Hour {
		delete(s.sessions, sessionID)
		return nil
	}

	// Update last accessed time
	session.LastAccessed = time.Now()
	return session
}

func (s *Server) createSession(tokens map[string]interface{}) *models.RPSession {
	sessionID := s.generateRandomString(32)

	// Extract user info from tokens
	var userID string
	if sub, ok := tokens["sub"].(string); ok {
		userID = sub
	} else {
		userID = "unknown"
	}

	session := &models.RPSession{
		SessionID:    sessionID,
		UserID:       userID,
		AccessToken:  tokens["access_token"].(string),
		IDToken:      tokens["id_token"].(string),
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
	}

	s.sessionsMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionsMutex.Unlock()

	return session
}

func (s *Server) exchangeCodeForTokens(code string) (map[string]interface{}, error) {
	// In a real implementation, you would make an HTTP POST request to the token endpoint
	// For now, we'll simulate the token exchange by parsing the JWT tokens

	// This is a simplified implementation - in reality, you'd make HTTP requests
	// and validate the tokens properly

	// For demonstration, we'll create mock tokens
	tokens := map[string]interface{}{
		"access_token": "mock_access_token_" + s.generateRandomString(16),
		"id_token":     "mock_id_token_" + s.generateRandomString(16),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"sub":          "org.example.com",
	}

	return tokens, nil
}

// HTML rendering methods

func (s *Server) renderLoginPage(w http.ResponseWriter) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Example RP - Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .button { background: #007cba; color: white; padding: 15px 30px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; text-decoration: none; display: inline-block; }
        .button:hover { background: #005a87; }
        .header { text-align: center; margin-bottom: 30px; }
        .description { text-align: center; color: #666; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Example RP</h1>
        </div>
        <div class="description">
            <p>This is an example Relying Party (RP) that demonstrates certificate-based authentication using CertAuth.</p>
            <p>Click the button below to login with your eIDAS certificate.</p>
        </div>
        <div style="text-align: center;">
            <a href="/login" class="button">Login with Certificate</a>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (s *Server) renderWelcomePage(w http.ResponseWriter, session *models.RPSession) {
	// Sample certificate data for demonstration
	certInfo := map[string]string{
		"organization":     "Example Organization S.L.",
		"organization_id":  "ES-B12345678",
		"common_name":      "Juan Pérez García",
		"email":            "juan.perez@example.org",
		"country":          "ES",
		"locality":         "Madrid",
		"province":         "Madrid",
		"certificate_type": "organizational",
		"valid_from":       "2024-01-01",
		"valid_to":         "2025-01-01",
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Example RP - Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .logout { background: #dc3545; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; }
        .logout:hover { background: #c82333; }
        .user-info { background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 4px; margin: 20px 0; }
        .token-info { background: #f8f9fa; border: 1px solid #e9ecef; padding: 15px; border-radius: 4px; margin: 10px 0; font-family: monospace; font-size: 12px; }
        .cert-info { background: #e7f3ff; border: 1px solid #b3d9ff; padding: 20px; border-radius: 4px; margin: 20px 0; }
        .cert-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px; }
        .cert-item { background: white; padding: 10px; border-radius: 4px; border: 1px solid #dee2e6; }
        .cert-label { font-weight: bold; color: #495057; font-size: 12px; text-transform: uppercase; }
        .cert-value { color: #212529; margin-top: 5px; }
        .success { color: #155724; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to Example RP</h1>
            <a href="/logout" class="logout">Logout</a>
        </div>
        
        <div class="user-info">
            <h2>✅ Authentication Successful!</h2>
            <p><strong>User ID:</strong> ` + session.UserID + `</p>
            <p><strong>Session ID:</strong> ` + session.SessionID + `</p>
            <p><strong>Login Time:</strong> ` + session.CreatedAt.Format("2006-01-02 15:04:05") + `</p>
            <p><strong>Last Accessed:</strong> ` + session.LastAccessed.Format("2006-01-02 15:04:05") + `</p>
        </div>
        
        <div class="cert-info">
            <h3>📋 Certificate Information</h3>
            <p>This is the certificate data that would be available from the eIDAS certificate:</p>
            <div class="cert-grid">
                <div class="cert-item">
                    <div class="cert-label">Organization</div>
                    <div class="cert-value">` + certInfo["organization"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Organization ID</div>
                    <div class="cert-value">` + certInfo["organization_id"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Common Name</div>
                    <div class="cert-value">` + certInfo["common_name"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Email Address</div>
                    <div class="cert-value">` + certInfo["email"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Country</div>
                    <div class="cert-value">` + certInfo["country"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Locality</div>
                    <div class="cert-value">` + certInfo["locality"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Province</div>
                    <div class="cert-value">` + certInfo["province"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Certificate Type</div>
                    <div class="cert-value">` + certInfo["certificate_type"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Valid From</div>
                    <div class="cert-value">` + certInfo["valid_from"] + `</div>
                </div>
                <div class="cert-item">
                    <div class="cert-label">Valid To</div>
                    <div class="cert-value">` + certInfo["valid_to"] + `</div>
                </div>
            </div>
        </div>
        
        <div class="token-info">
            <h3>Access Token:</h3>
            <div style="word-break: break-all;">` + session.AccessToken + `</div>
        </div>
        
        <div class="token-info">
            <h3>ID Token:</h3>
            <div style="word-break: break-all;">` + session.IDToken + `</div>
        </div>
        
        <div style="margin-top: 30px; padding: 20px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px;">
            <h3>ℹ️ How This Works</h3>
            <p>In a real implementation:</p>
            <ul>
                <li>The ID Token would be a JWT containing the certificate information</li>
                <li>The RP would validate the JWT signature</li>
                <li>The certificate data would be extracted from the JWT claims</li>
                <li>This data can be used to identify the user and their organization</li>
            </ul>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (s *Server) renderErrorPage(w http.ResponseWriter, error, description string) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Example RP - Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 4px; margin: 20px 0; }
        .button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ Authentication Error</h1>
        <div class="error">
            <h2>Error: ` + error + `</h2>
            <p>` + description + `</p>
        </div>
        <a href="/" class="button">Back to Login</a>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
