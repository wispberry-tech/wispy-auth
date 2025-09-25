package verifyemail

import (
	"bytes"
	"fmt"
	"text/template"
)

// TemplateEngine handles email template rendering
type TemplateEngine struct {
	funcMap template.FuncMap
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine() *TemplateEngine {
	return &TemplateEngine{
		funcMap: template.FuncMap{
			// Add custom template functions here if needed
		},
	}
}

// RenderTemplate renders an email template with the provided data
func (te *TemplateEngine) RenderTemplate(emailTemplate *EmailTemplate, data *EmailData) (*EmailMessage, error) {
	message := &EmailMessage{
		To:        data.User.Email,
		FromEmail: emailTemplate.FromEmail,
		FromName:  emailTemplate.FromName,
	}

	// Render subject
	subject, err := te.renderString(emailTemplate.Subject, data)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to render subject: %v", ErrTemplateRender, err)
	}
	message.Subject = subject

	// Render text body
	textBody, err := te.renderString(emailTemplate.TextBody, data)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to render text body: %v", ErrTemplateRender, err)
	}
	message.TextBody = textBody

	// Render HTML body if present
	if emailTemplate.HTMLBody != "" {
		htmlBody, err := te.renderString(emailTemplate.HTMLBody, data)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to render HTML body: %v", ErrTemplateRender, err)
		}
		message.HTMLBody = htmlBody
	}

	return message, nil
}

// renderString renders a template string with the provided data
func (te *TemplateEngine) renderString(templateStr string, data interface{}) (string, error) {
	tmpl, err := template.New("email").Funcs(te.funcMap).Parse(templateStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// AddTemplateFunc adds a custom function to the template engine
func (te *TemplateEngine) AddTemplateFunc(name string, fn interface{}) {
	te.funcMap[name] = fn
}
