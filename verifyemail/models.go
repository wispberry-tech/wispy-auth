package verifyemail

import (
	"time"

	"github.com/wispberry-tech/wispy-auth/core"
)

// EmailVerificationToken represents an email verification token
type EmailVerificationToken struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token"`      // The verification token
	Email     string    `json:"email"`      // Email to verify
	ExpiresAt time.Time `json:"expires_at"` // When the token expires
	IsUsed    bool      `json:"is_used"`    // Whether token has been used
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Populated by joins
	User *core.User `json:"user,omitempty"`
}

// EmailTemplate represents an email template configuration
type EmailTemplate struct {
	Subject   string `json:"subject"`    // Email subject template
	TextBody  string `json:"text_body"`  // Plain text body template
	HTMLBody  string `json:"html_body"`  // HTML body template (optional)
	FromEmail string `json:"from_email"` // From email address
	FromName  string `json:"from_name"`  // From name
}

// EmailData contains data passed to email templates
type EmailData struct {
	User            *core.User             `json:"user"`
	Token           string                 `json:"token"`
	VerificationURL string                 `json:"verification_url"`
	ExpiresAt       time.Time              `json:"expires_at"`
	AppName         string                 `json:"app_name"`
	SupportEmail    string                 `json:"support_email"`
	CustomData      map[string]interface{} `json:"custom_data,omitempty"`
}

// EmailMessage represents a composed email ready to send
type EmailMessage struct {
	To        string `json:"to"`
	Subject   string `json:"subject"`
	TextBody  string `json:"text_body"`
	HTMLBody  string `json:"html_body"`
	FromEmail string `json:"from_email"`
	FromName  string `json:"from_name"`
}

// Config contains configuration for the email verification module
type Config struct {
	// Token settings
	TokenLength      int           `json:"token_length"`        // Length of verification tokens (default: 32)
	TokenExpiry      time.Duration `json:"token_expiry"`        // How long tokens are valid (default: 24h)
	MaxTokensPerUser int           `json:"max_tokens_per_user"` // Max active tokens per user (default: 3)

	// Email settings
	BaseURL      string `json:"base_url"`      // Base URL for verification links
	VerifyPath   string `json:"verify_path"`   // Path for verification endpoint (default: "/verify-email")
	AppName      string `json:"app_name"`      // Application name for emails
	SupportEmail string `json:"support_email"` // Support email address

	// Template settings
	DefaultTemplate EmailTemplate `json:"default_template"`  // Default email template
	UseHTMLTemplate bool          `json:"use_html_template"` // Whether to use HTML templates

	// Provider settings
	Provider       string                 `json:"provider"`        // Email provider (resend, sendgrid, etc.)
	ProviderConfig map[string]interface{} `json:"provider_config"` // Provider-specific config
}

// SendOptions contains options for sending verification emails
type SendOptions struct {
	CustomTemplate *EmailTemplate         `json:"custom_template,omitempty"` // Override default template
	CustomData     map[string]interface{} `json:"custom_data,omitempty"`     // Additional template data
	ExpiryOverride *time.Duration         `json:"expiry_override,omitempty"` // Override default expiry
}

// VerifyOptions contains options for email verification
type VerifyOptions struct {
	DeleteTokenAfterUse bool `json:"delete_token_after_use"` // Whether to delete token after successful verification
	UpdateEmailStatus   bool `json:"update_email_status"`    // Whether to update user's email verification status
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() Config {
	return Config{
		TokenLength:      32,
		TokenExpiry:      24 * time.Hour,
		MaxTokensPerUser: 3,
		VerifyPath:       "/verify-email",
		AppName:          "Your App",
		SupportEmail:     "support@yourapp.com",
		UseHTMLTemplate:  true,
		Provider:         "resend", // Default to Resend
		DefaultTemplate:  DefaultEmailTemplate(),
		ProviderConfig:   make(map[string]interface{}),
	}
}

// DefaultEmailTemplate returns a default email template
func DefaultEmailTemplate() EmailTemplate {
	return EmailTemplate{
		Subject:   "Verify your email address for {{.AppName}}",
		FromEmail: "noreply@yourapp.com",
		FromName:  "{{.AppName}}",
		TextBody: `Hi {{.User.FirstName}},

Please verify your email address by clicking the link below:

{{.VerificationURL}}

This link will expire at {{.ExpiresAt.Format "January 2, 2006 at 3:04 PM"}}.

If you didn't create an account with {{.AppName}}, you can safely ignore this email.

Best regards,
The {{.AppName}} Team

---
Need help? Contact us at {{.SupportEmail}}`,
		HTMLBody: `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Verify Your Email Address</h1>
    </div>
    
    <p>Hi {{.User.FirstName}},</p>
    
    <p>Thank you for creating an account with {{.AppName}}! Please verify your email address by clicking the button below:</p>
    
    <div style="text-align: center;">
        <a href="{{.VerificationURL}}" class="button">Verify Email Address</a>
    </div>
    
    <p>Or copy and paste this link into your browser:</p>
    <p><a href="{{.VerificationURL}}">{{.VerificationURL}}</a></p>
    
    <p>This link will expire at {{.ExpiresAt.Format "January 2, 2006 at 3:04 PM"}}.</p>
    
    <p>If you didn't create an account with {{.AppName}}, you can safely ignore this email.</p>
    
    <div class="footer">
        <p>Best regards,<br>The {{.AppName}} Team</p>
        <p>Need help? Contact us at <a href="mailto:{{.SupportEmail}}">{{.SupportEmail}}</a></p>
    </div>
</body>
</html>`,
	}
}

// IsExpired checks if a verification token has expired
func (evt *EmailVerificationToken) IsExpired() bool {
	return time.Now().After(evt.ExpiresAt)
}

// IsValid checks if a verification token is valid (not used and not expired)
func (evt *EmailVerificationToken) IsValid() bool {
	return !evt.IsUsed && !evt.IsExpired()
}
