package verifyemail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// ResendProvider implements email sending via Resend API
type ResendProvider struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

// ResendRequest represents a request to the Resend API
type ResendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html,omitempty"`
	Text    string   `json:"text,omitempty"`
	ReplyTo string   `json:"reply_to,omitempty"`
}

// ResendResponse represents a response from the Resend API
type ResendResponse struct {
	ID    string `json:"id"`
	Error string `json:"message,omitempty"`
}

// NewResendProvider creates a new Resend email provider
func NewResendProvider(config map[string]interface{}) (EmailProvider, error) {
	apiKey, ok := config["api_key"].(string)
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("%w: api_key is required for Resend provider", ErrProviderConfig)
	}

	baseURL := "https://api.resend.com"
	if url, ok := config["base_url"].(string); ok && url != "" {
		baseURL = url
	}

	timeout := 30 * time.Second
	if t, ok := config["timeout"].(time.Duration); ok {
		timeout = t
	}

	return &ResendProvider{
		apiKey:  apiKey,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Name returns the provider name
func (r *ResendProvider) Name() string {
	return "resend"
}

// SendEmail sends an email via Resend API
func (r *ResendProvider) SendEmail(ctx context.Context, message *EmailMessage) error {
	reqBody := ResendRequest{
		From:    fmt.Sprintf("%s <%s>", message.FromName, message.FromEmail),
		To:      []string{message.To},
		Subject: message.Subject,
		Text:    message.TextBody,
	}

	if message.HTMLBody != "" {
		reqBody.HTML = message.HTMLBody
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal request: %v", ErrEmailSendFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.baseURL+"/emails", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("%w: failed to create request: %v", ErrEmailSendFailed, err)
	}

	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: request failed: %v", ErrEmailSendFailed, err)
	}
	defer resp.Body.Close()

	var resendResp ResendResponse
	if err := json.NewDecoder(resp.Body).Decode(&resendResp); err != nil {
		return fmt.Errorf("%w: failed to decode response: %v", ErrEmailSendFailed, err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("%w: Resend API error (%d): %s", ErrEmailSendFailed, resp.StatusCode, resendResp.Error)
	}

	return nil
}

// ValidateConfig validates the Resend provider configuration
func (r *ResendProvider) ValidateConfig(config map[string]interface{}) error {
	if apiKey, ok := config["api_key"].(string); !ok || apiKey == "" {
		return fmt.Errorf("%w: api_key is required", ErrProviderConfig)
	}
	return nil
}

// Close cleans up resources
func (r *ResendProvider) Close() error {
	return nil
}

// SendGridProvider implements email sending via SendGrid API
type SendGridProvider struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

// NewSendGridProvider creates a new SendGrid email provider
func NewSendGridProvider(config map[string]interface{}) (EmailProvider, error) {
	apiKey, ok := config["api_key"].(string)
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("%w: api_key is required for SendGrid provider", ErrProviderConfig)
	}

	baseURL := "https://api.sendgrid.com/v3"
	if url, ok := config["base_url"].(string); ok && url != "" {
		baseURL = url
	}

	timeout := 30 * time.Second
	if t, ok := config["timeout"].(time.Duration); ok {
		timeout = t
	}

	return &SendGridProvider{
		apiKey:  apiKey,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Name returns the provider name
func (s *SendGridProvider) Name() string {
	return "sendgrid"
}

// SendEmail sends an email via SendGrid API
func (s *SendGridProvider) SendEmail(ctx context.Context, message *EmailMessage) error {
	// SendGrid API request structure
	reqBody := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{"email": message.To},
				},
				"subject": message.Subject,
			},
		},
		"from": map[string]string{
			"email": message.FromEmail,
			"name":  message.FromName,
		},
		"content": []map[string]string{
			{"type": "text/plain", "value": message.TextBody},
		},
	}

	if message.HTMLBody != "" {
		content := reqBody["content"].([]map[string]string)
		content = append(content, map[string]string{
			"type":  "text/html",
			"value": message.HTMLBody,
		})
		reqBody["content"] = content
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal request: %v", ErrEmailSendFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.baseURL+"/mail/send", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("%w: failed to create request: %v", ErrEmailSendFailed, err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: request failed: %v", ErrEmailSendFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("%w: SendGrid API error (%d)", ErrEmailSendFailed, resp.StatusCode)
	}

	return nil
}

// ValidateConfig validates the SendGrid provider configuration
func (s *SendGridProvider) ValidateConfig(config map[string]interface{}) error {
	if apiKey, ok := config["api_key"].(string); !ok || apiKey == "" {
		return fmt.Errorf("%w: api_key is required", ErrProviderConfig)
	}
	return nil
}

// Close cleans up resources
func (s *SendGridProvider) Close() error {
	return nil
}

// PostmarkProvider implements email sending via Postmark REST API
type PostmarkProvider struct {
	apiKey string
	client *http.Client
}

// NewPostmarkProvider creates a new Postmark email provider
func NewPostmarkProvider(config map[string]interface{}) (EmailProvider, error) {
	apiKey, ok := config["api_key"].(string)
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("%w: api_key is required for Postmark provider", ErrProviderConfig)
	}

	return &PostmarkProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Name returns the provider name
func (p *PostmarkProvider) Name() string {
	return "postmark"
}

// SendEmail sends an email via Postmark REST API
func (p *PostmarkProvider) SendEmail(ctx context.Context, message *EmailMessage) error {
	url := "https://api.postmarkapp.com/email"

	// Prepare request payload
	payload := map[string]interface{}{
		"From":    message.FromEmail,
		"To":      message.To,
		"Subject": message.Subject,
	}

	// Add content based on what's available
	if message.HTMLBody != "" {
		payload["HtmlBody"] = message.HTMLBody
	}
	if message.TextBody != "" {
		payload["TextBody"] = message.TextBody
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Postmark request: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create Postmark request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Postmark-Server-Token", p.apiKey)
	req.Header.Set("Accept", "application/json")

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("Postmark API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Postmark API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ValidateConfig validates the Postmark provider configuration
func (p *PostmarkProvider) ValidateConfig(config map[string]interface{}) error {
	if apiKey, ok := config["api_key"].(string); !ok || apiKey == "" {
		return fmt.Errorf("%w: api_key is required", ErrProviderConfig)
	}
	return nil
}

// Close cleans up resources
func (p *PostmarkProvider) Close() error {
	return nil
}

// Additional REST API providers can be added here
// Examples: Amazon SES, Mailjet, ConvertKit, etc.

// MailgunProvider implements email sending via Mailgun REST API
type MailgunProvider struct {
	apiKey string
	domain string
	client *http.Client
}

// NewMailgunProvider creates a new Mailgun email provider
func NewMailgunProvider(config map[string]interface{}) (EmailProvider, error) {
	apiKey, ok := config["api_key"].(string)
	if !ok || apiKey == "" {
		return nil, fmt.Errorf("%w: api_key is required for Mailgun provider", ErrProviderConfig)
	}

	domain, ok := config["domain"].(string)
	if !ok || domain == "" {
		return nil, fmt.Errorf("%w: domain is required for Mailgun provider", ErrProviderConfig)
	}

	return &MailgunProvider{
		apiKey: apiKey,
		domain: domain,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Name returns the provider name
func (m *MailgunProvider) Name() string {
	return "mailgun"
}

// SendEmail sends an email via Mailgun REST API
func (m *MailgunProvider) SendEmail(ctx context.Context, message *EmailMessage) error {
	url := fmt.Sprintf("https://api.mailgun.net/v3/%s/messages", m.domain)

	// Prepare form data
	data := map[string]string{
		"from":    message.FromEmail,
		"to":      message.To,
		"subject": message.Subject,
	}

	// Add content based on what's available
	if message.HTMLBody != "" {
		data["html"] = message.HTMLBody
	}
	if message.TextBody != "" {
		data["text"] = message.TextBody
	}

	// Create form data
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range data {
		writer.WriteField(key, value)
	}
	writer.Close()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", url, &body)
	if err != nil {
		return fmt.Errorf("failed to create Mailgun request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth("api", m.apiKey)

	// Send request
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("Mailgun API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Mailgun API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ValidateConfig validates the Mailgun provider configuration
func (m *MailgunProvider) ValidateConfig(config map[string]interface{}) error {
	if apiKey, ok := config["api_key"].(string); !ok || apiKey == "" {
		return fmt.Errorf("%w: api_key is required", ErrProviderConfig)
	}
	if domain, ok := config["domain"].(string); !ok || domain == "" {
		return fmt.Errorf("%w: domain is required", ErrProviderConfig)
	}
	return nil
}

// Close cleans up resources
func (m *MailgunProvider) Close() error {
	return nil
}
