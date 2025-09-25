package verifyemail

import (
	"context"
)

// EmailProvider defines the interface that all email providers must implement
type EmailProvider interface {
	// Name returns the name of the provider
	Name() string

	// SendEmail sends an email message
	SendEmail(ctx context.Context, message *EmailMessage) error

	// ValidateConfig validates the provider configuration
	ValidateConfig(config map[string]interface{}) error

	// Close cleans up any resources
	Close() error
}

// EmailProviderFactory creates email providers
type EmailProviderFactory func(config map[string]interface{}) (EmailProvider, error)

// Registry of available email providers
var emailProviders = map[string]EmailProviderFactory{
	"resend":   NewResendProvider,
	"sendgrid": NewSendGridProvider,
	"mailgun":  NewMailgunProvider,
	"postmark": NewPostmarkProvider,
}

// RegisterEmailProvider registers a new email provider
func RegisterEmailProvider(name string, factory EmailProviderFactory) {
	emailProviders[name] = factory
}

// GetEmailProvider creates a new instance of the specified email provider
func GetEmailProvider(name string, config map[string]interface{}) (EmailProvider, error) {
	factory, exists := emailProviders[name]
	if !exists {
		return nil, ErrProviderNotFound
	}

	return factory(config)
}

// ListEmailProviders returns a list of registered provider names
func ListEmailProviders() []string {
	names := make([]string, 0, len(emailProviders))
	for name := range emailProviders {
		names = append(names, name)
	}
	return names
}
