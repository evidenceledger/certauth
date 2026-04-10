package contract

import (
	"bytes"
	"embed"
	_ "embed"
	"html/template"
	"log"
	"os/exec"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
)

// Use embed to process the templates

//go:embed html/templates/*.hbs
var templates embed.FS

var tmpl *template.Template

func init() {
	var err error
	tmpl, err = template.New("contract").ParseFS(templates, "html/templates/*.hbs")
	if err != nil {
		log.Fatalf("error parsing templates: %v", err)
	}

}

func Generate(contractForm *models.ContractForm) ([]byte, error) {

	contractData := map[string]any{
		"formData": contractForm,
	}

	// Execute the template, passing an empty data object and receiving the HTML
	var renderedHTML bytes.Buffer
	err := tmpl.ExecuteTemplate(&renderedHTML, "contract_main", contractData)
	if err != nil {
		return nil, errl.Errorf("error executing template: %v", err)
	}
	htmlStr := renderedHTML.String()

	// Run WeasyPrint as external process to generate PDF, using stdin and stdout
	cmd := exec.Command("weasyprint", "-", "-")

	// Set up stdin to send the HTML
	cmd.Stdin = bytes.NewReader([]byte(htmlStr))

	// Create a buffer or file to capture the PDF output
	var pdfBuffer bytes.Buffer
	cmd.Stdout = &pdfBuffer

	// Run the command
	if err := cmd.Run(); err != nil {
		return nil, errl.Errorf("error running weasyprint: %v", err)
	}

	return pdfBuffer.Bytes(), nil
}
