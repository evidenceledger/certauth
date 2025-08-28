package templates

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"time"

	"github.com/evidenceledger/certauth/internal/models"
)

// Renderer handles template loading and rendering
type Renderer struct {
	consentTemplate           *template.Template
	certificateSelectTemplate *template.Template
	errorTemplate             *template.Template
}

// NewRenderer creates a new template renderer
func NewRenderer() (*Renderer, error) {
	// Parse consent template with functions
	consentTmpl, err := template.New("consent").Funcs(template.FuncMap{
		"formatDate": formatDate,
	}).Parse(consentTemplateHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse consent template: %w", err)
	}

	// Parse certificate select template
	certSelectTmpl, err := template.New("certificate_select").Parse(certificateSelectTemplateHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate select template: %w", err)
	}

	// Parse error template
	errorTmpl, err := template.New("error").Parse(errorTemplateHTML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse error template: %w", err)
	}

	slog.Debug("Templates loaded successfully")
	return &Renderer{
		consentTemplate:           consentTmpl,
		certificateSelectTemplate: certSelectTmpl,
		errorTemplate:             errorTmpl,
	}, nil
}

// RenderConsent renders the consent screen
func (r *Renderer) RenderConsent(data *ConsentData) ([]byte, error) {
	var buf bytes.Buffer

	err := r.consentTemplate.Execute(&buf, data)
	if err != nil {
		return nil, fmt.Errorf("failed to render consent template: %w", err)
	}

	return buf.Bytes(), nil
}

// RenderCertificateSelect renders the certificate selection screen
func (r *Renderer) RenderCertificateSelect(data *CertificateSelectData) ([]byte, error) {
	var buf bytes.Buffer

	err := r.certificateSelectTemplate.Execute(&buf, data)
	if err != nil {
		return nil, fmt.Errorf("failed to render certificate select template: %w", err)
	}

	return buf.Bytes(), nil
}

// RenderError renders the error screen
func (r *Renderer) RenderError(data *ErrorData) ([]byte, error) {
	var buf bytes.Buffer

	err := r.errorTemplate.Execute(&buf, data)
	if err != nil {
		return nil, fmt.Errorf("failed to render error template: %w", err)
	}

	return buf.Bytes(), nil
}

// Template data structures

// ConsentData represents data for the consent screen
type ConsentData struct {
	Title           string
	RPName          string
	RPDescription   string
	RPOrigin        string
	AuthCode        string
	State           string
	CertificateData *models.CertificateData
}

// CertificateSelectData represents data for the certificate selection screen
type CertificateSelectData struct {
	Title    string
	RPName   string
	AuthCode string
	RPInfo   *models.RelyingParty
}

// ErrorData represents data for the error screen
type ErrorData struct {
	Title        string
	ErrorTitle   string
	ErrorMessage string
	ErrorCode    string
}

// Template functions
func formatDate(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// Template HTML strings

const consentTemplateHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - ISBE CertAuth</title>
    
    <!-- Fomantic UI CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.4/dist/semantic.min.css">
    
    <!-- Custom styles -->
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Lato', sans-serif;
        }
        
        .main-container {
            padding: 2rem 0;
        }
        
        .consent-card {
            max-width: 700px;
            margin: 0 auto;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border-radius: 12px;
            overflow: hidden;
        }
        
        .consent-header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            text-align: center;
            padding: 2rem;
        }
        
        .consent-content {
            padding: 2rem;
            background: white;
        }
        
        .certificate-info {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
            border-left: 4px solid #28a745;
        }
        
        .certificate-info h4 {
            color: #2c3e50;
            margin-bottom: 1rem;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }
        
        .info-item {
            display: flex;
            flex-direction: column;
        }
        
        .info-label {
            font-weight: bold;
            color: #6c757d;
            font-size: 0.9rem;
            margin-bottom: 0.25rem;
        }
        
        .info-value {
            color: #2c3e50;
            font-size: 1rem;
        }
        
        .footer {
            text-align: center;
            margin-top: 2rem;
            color: rgba(255,255,255,0.8);
            font-size: 0.9rem;
        }
        
        .button-group {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-top: 2rem;
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="ui container">
            <div class="consent-card">
                <div class="consent-header">
                    <h2 class="ui header" style="color: white;">
                        <i class="shield alternate icon"></i>
                        <div class="content">
                            Consent Required
                            <div class="sub header" style="color: rgba(255,255,255,0.8);">
                                {{.RPName}} requests access to your certificate information
                            </div>
                        </div>
                    </h2>
                </div>
                
                <div class="consent-content">
                    <div class="ui segment">
                        <h3 class="ui header">
                            <i class="info circle icon"></i>
                            <div class="content">
                                Application Information
                                <div class="sub header">Details about the requesting application</div>
                            </div>
                        </h3>
                        
                        <div class="ui list">
                            <div class="item">
                                <i class="building icon"></i>
                                <div class="content">
                                    <div class="header">Application Name</div>
                                    <div class="description">{{.RPName}}</div>
                                </div>
                            </div>
                            {{if .RPDescription}}
                            <div class="item">
                                <i class="file text icon"></i>
                                <div class="content">
                                    <div class="header">Description</div>
                                    <div class="description">{{.RPDescription}}</div>
                                </div>
                            </div>
                            {{end}}
                            <div class="item">
                                <i class="globe icon"></i>
                                <div class="content">
                                    <div class="header">Origin</div>
                                    <div class="description">{{.RPOrigin}}</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {{if .CertificateData}}
                    <div class="certificate-info">
                        <h4 class="ui header">
                            <i class="certificate icon"></i>
                            <div class="content">
                                Certificate Information
                                <div class="sub header">The following information will be shared</div>
                            </div>
                        </h4>
                        
                        <div class="info-grid">
                            {{if .CertificateData.Subject.Organization}}
                            <div class="info-item">
                                <div class="info-label">Organization</div>
                                <div class="info-value">{{.CertificateData.Subject.Organization}}</div>
                            </div>
                            {{end}}
                            
                            {{if .CertificateData.Subject.OrganizationIdentifier}}
                            <div class="info-item">
                                <div class="info-label">Organization ID</div>
                                <div class="info-value">{{.CertificateData.Subject.OrganizationIdentifier}}</div>
                            </div>
                            {{end}}
                            
                            {{if .CertificateData.Subject.Country}}
                            <div class="info-item">
                                <div class="info-label">Country</div>
                                <div class="info-value">{{.CertificateData.Subject.Country}}</div>
                            </div>
                            {{end}}
                            
                            {{if .CertificateData.Subject.OrganizationalUnit}}
                            <div class="info-item">
                                <div class="info-label">Organizational Unit</div>
                                <div class="info-value">{{.CertificateData.Subject.OrganizationalUnit}}</div>
                            </div>
                            {{end}}
                            
                            {{if .CertificateData.Subject.CommonName}}
                            <div class="info-item">
                                <div class="info-label">Common Name</div>
                                <div class="info-value">{{.CertificateData.Subject.CommonName}}</div>
                            </div>
                            {{end}}
                            
                            {{if .CertificateData.Subject.GivenName}}
                            <div class="info-item">
                                <div class="info-label">Given Name</div>
                                <div class="info-value">{{.CertificateData.Subject.GivenName}}</div>
                            </div>
                            {{end}}
                            
                            {{if .CertificateData.Subject.Surname}}
                            <div class="info-item">
                                <div class="info-label">Surname</div>
                                <div class="info-value">{{.CertificateData.Subject.Surname}}</div>
                            </div>
                            {{end}}
                            
                            {{if .CertificateData.Subject.EmailAddress}}
                            <div class="info-item">
                                <div class="info-label">Email</div>
                                <div class="info-value">{{.CertificateData.Subject.EmailAddress}}</div>
                            </div>
                            {{end}}
                        </div>
                        
                        <div class="ui segment" style="margin-top: 1rem; background: #fff3cd; border-color: #ffeaa7;">
                            <h5 class="ui header" style="color: #856404;">
                                <i class="clock icon"></i>
                                <div class="content">
                                    Certificate Validity
                                    <div class="sub header" style="color: #856404;">
                                        Valid from {{formatDate .CertificateData.ValidFrom}} to {{formatDate .CertificateData.ValidTo}}
                                    </div>
                                </div>
                            </h5>
                        </div>
                    </div>
                    {{end}}

                                               {{if eq .CertificateData.CertificateType "personal"}}
                           <div class="ui orange warning message">
                               <div class="header">
                                   <i class="exclamation triangle icon"></i>
                                   Personal Certificate Detected
                               </div>
                               <p>You are using a <strong>personal certificate</strong>. This means the certificate does not contain organizational affiliation information. The relying party may have different access restrictions for personal certificates.</p>
                           </div>
                           {{end}}

                           <div class="ui warning message">
                               <div class="header">
                                   <i class="exclamation triangle icon"></i>
                                   Important Notice
                               </div>
                               <p>By granting consent, you authorize <strong>{{.RPName}}</strong> to access the certificate information shown above. This action cannot be undone.</p>
                           </div>

                    <form id="consent-form" method="POST" action="/consent">
                        <input type="hidden" name="auth_code" value="{{.AuthCode}}">
                        <input type="hidden" name="state" value="{{.State}}">
                        <input type="hidden" name="consent_granted" id="consent-granted" value="false">
                        
                        {{if .CertificateData}}
                        <input type="hidden" name="organization_identifier" value="{{.CertificateData.OrganizationID}}">
                        {{end}}
                        
                        <div class="button-group">
                            <button type="button" class="ui red button large" onclick="denyConsent()">
                                <i class="times icon"></i>
                                Deny Access
                            </button>
                            <button type="button" class="ui green button large" onclick="grantConsent()">
                                <i class="check icon"></i>
                                Grant Access
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Fomantic UI JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.4/dist/semantic.min.js"></script>
    
    <script>
        function grantConsent() {
            document.getElementById('consent-granted').value = 'true';
            document.getElementById('consent-form').submit();
        }
        
        function denyConsent() {
            document.getElementById('consent-granted').value = 'false';
            document.getElementById('consent-form').submit();
        }
    </script>
</body>
</html>`

const certificateSelectTemplateHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - ISBE CertAuth</title>
    
    <!-- Fomantic UI CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.4/dist/semantic.min.css">
    
    <!-- Custom styles -->
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Lato', sans-serif;
        }
        
        .main-container {
            padding: 2rem 0;
        }
        
        .auth-card {
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border-radius: 12px;
            overflow: hidden;
        }
        
        .auth-header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            text-align: center;
            padding: 2rem;
        }
        
        .auth-content {
            padding: 2rem;
            background: white;
        }
        
        .footer {
            text-align: center;
            margin-top: 2rem;
            color: rgba(255,255,255,0.8);
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="ui container">
            <div class="auth-card">
                <div class="auth-header">
                    <h2 class="ui header" style="color: white;">
                        <i class="certificate icon"></i>
                        <div class="content">
                            Certificate Selection Required
                            <div class="sub header" style="color: rgba(255,255,255,0.8);">
                                Please select your eIDAS certificate to continue
                            </div>
                        </div>
                    </h2>
                </div>
                
                <div class="auth-content">
                    <div class="ui info message">
                        <i class="info circle icon"></i>
                        <div class="content">
                            <div class="header">Browser Certificate Selection</div>
                            <p>Your browser will now present a certificate selection dialog. Please choose your eIDAS certificate to proceed with the authentication.</p>
                        </div>
                    </div>

                    <div class="ui segment">
                        <h4 class="ui header">
                            <i class="shield alternate icon"></i>
                            <div class="content">
                                Application Information
                                <div class="sub header">Details about the requesting application</div>
                            </div>
                        </h4>
                        
                        <div class="ui list">
                            <div class="item">
                                <i class="building icon"></i>
                                <div class="content">
                                    <div class="header">Application Name</div>
                                    <div class="description">{{.RPName}}</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="ui warning message">
                        <div class="header">
                            <i class="exclamation triangle icon"></i>
                            Important Notice
                        </div>
                        <p>By proceeding, you authorize <strong>{{.RPName}}</strong> to access your certificate information. This action cannot be undone.</p>
                    </div>

                    <div class="ui two buttons" style="margin-top: 2rem;">
                        <button class="ui red button large" onclick="window.history.back()">
                            <i class="times icon"></i>
                            Cancel
                        </button>
                        <button class="ui green button large" onclick="proceedWithCertificate()">
                            <i class="check icon"></i>
                            Proceed
                        </button>
                    </div>

                    <!-- Hidden form for certificate processing -->
                    <form id="cert-form" method="POST" action="/exchange" style="display: none;">
                        <input type="hidden" name="auth_code" value="{{.AuthCode}}">
                        <input type="hidden" name="certificate_data" id="certificate-data">
                        <input type="hidden" name="state" value="">
                        <input type="hidden" name="nonce" value="">
                        <input type="hidden" name="scope" value="openid eidas">
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Fomantic UI JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.4/dist/semantic.min.js"></script>
    
    <script>
        function proceedWithCertificate() {
            // For testing purposes, we'll simulate certificate selection
            // In a real implementation, this would trigger browser certificate selection
            
            // Show loading message
            const proceedBtn = document.querySelector('.ui.green.button');
            const originalText = proceedBtn.innerHTML;
            proceedBtn.innerHTML = '<i class="spinner loading icon"></i> Processing...';
            proceedBtn.disabled = true;
            
            // Simulate certificate processing
            setTimeout(function() {
                // Create test certificate data
                const testCertData = {
                    auth_code: "{{.AuthCode}}",
                    certificate_data: {
                        subject: {
                            country: "ES",
                            organization: "{{.RPInfo.Name}}",
                            organizational_unit: "IT Department",
                            common_name: "Test User",
                            given_name: "Test",
                            surname: "User",
                            email_address: "test@example.com",
                            organization_identifier: "ES-123456789",
                            locality: "Madrid",
                            province: "Madrid",
                            street_address: "Calle Test 123",
                            postal_code: "28001",
                            serial_number: "123456789ABC"
                        },
                        issuer: {
                            country: "ES",
                            organization: "{{.RPInfo.Name}}",
                            organization_identifier: "ES-123456789"
                        },
                        valid_from: new Date().toISOString(),
                        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
                        organization_identifier: "ES-123456789"
                    },
                    rp_info: {
                        id: "{{.RPInfo.ID}}",
                        name: "{{.RPInfo.Name}}",
                        description: "{{.RPInfo.Description}}",
                        client_id: "{{.RPInfo.ClientID}}",
                        redirect_url: "{{.RPInfo.RedirectURL}}"
                    },
                    state: "",
                    nonce: "",
                    scope: "openid eidas"
                };
                
                // Submit the certificate data
                fetch('/exchange', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(testCertData)
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Redirect to consent screen
                        window.location.href = '/consent?code={{.AuthCode}}';
                    } else {
                        alert('Failed to process certificate: ' + data.error);
                        proceedBtn.innerHTML = originalText;
                        proceedBtn.disabled = false;
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error processing certificate');
                    proceedBtn.innerHTML = originalText;
                    proceedBtn.disabled = false;
                });
            }, 1000);
        }
        
        // Auto-redirect after 15 seconds for testing
        setTimeout(function() {
            if (confirm('Would you like to proceed with certificate authentication?')) {
                proceedWithCertificate();
            }
        }, 15000);
    </script>
</body>
</html>`

const errorTemplateHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - ISBE CertAuth</title>
    
    <!-- Fomantic UI CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.4/dist/semantic.min.css">
    
    <!-- Custom styles -->
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Lato', sans-serif;
        }
        
        .main-container {
            padding: 2rem 0;
        }
        
        .error-card {
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border-radius: 12px;
            overflow: hidden;
        }
        
        .error-header {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            text-align: center;
            padding: 2rem;
        }
        
        .error-content {
            padding: 2rem;
            background: white;
        }
        
        .footer {
            text-align: center;
            margin-top: 2rem;
            color: rgba(255,255,255,0.8);
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="main-container">
        <div class="ui container">
            <div class="error-card">
                <div class="error-header">
                    <h2 class="ui header" style="color: white;">
                        <i class="exclamation triangle icon"></i>
                        <div class="content">
                            {{.ErrorTitle}}
                            <div class="sub header" style="color: rgba(255,255,255,0.8);">
                                An error occurred during authentication
                            </div>
                        </div>
                    </h2>
                </div>
                
                <div class="error-content">
                    <div class="ui negative message">
                        <i class="close icon"></i>
                        <div class="content">
                            <div class="header">{{.ErrorTitle}}</div>
                            <p>{{.ErrorMessage}}</p>
                        </div>
                    </div>

                    <div class="ui segment">
                        <h4 class="ui header">
                            <i class="info circle icon"></i>
                            <div class="content">
                                Error Code
                                <div class="sub header">Technical reference for this error</div>
                            </div>
                        </h4>
                        
                        <div class="ui list">
                            <div class="item">
                                <i class="code icon"></i>
                                <div class="content">
                                    <div class="header">Error Code</div>
                                    <div class="description">{{.ErrorCode}}</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="ui two buttons" style="margin-top: 2rem;">
                        <button class="ui button large" onclick="window.history.back()">
                            <i class="arrow left icon"></i>
                            Go Back
                        </button>
                        <button class="ui primary button large" onclick="window.location.href='/'">
                            <i class="home icon"></i>
                            Home
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Fomantic UI JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.4/dist/semantic.min.js"></script>
    
    <script>
        // Auto-redirect after 30 seconds
        setTimeout(function() {
            if (confirm('Would you like to return to the previous page?')) {
                window.history.back();
            }
        }, 30000);
    </script>
</body>
</html>`
