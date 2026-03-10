package core

// EmailService defines the interface for sending emails
type EmailService interface {
	Send2FACode(email, code string) error
	SendPasswordReset(email, resetURL string) error
	SendWelcome(email string) error
	Close() error
}

// EmailServiceConfig defines email provider configuration
type EmailServiceConfig struct {
	Provider string // "smtp", "smtp_tls", "mock"
	From     string // From email address

	// SMTP Configuration
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPUseTLS   bool

	// Templates
	Template2FACode       string
	TemplatePasswordReset string
	TemplateWelcome       string
}
