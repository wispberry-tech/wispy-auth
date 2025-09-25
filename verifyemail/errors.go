package verifyemail

import (
	"errors"
)

// Common errors returned by the email verification module
var (
	// ErrTokenNotFound is returned when a verification token cannot be found
	ErrTokenNotFound = errors.New("verification token not found")
	// ErrTokenExpired is returned when a verification token has expired
	ErrTokenExpired = errors.New("verification token has expired")
	// ErrTokenUsed is returned when a verification token has already been used
	ErrTokenUsed = errors.New("verification token has already been used")
	// ErrInvalidToken is returned when a verification token is invalid
	ErrInvalidToken = errors.New("invalid verification token")
	// ErrUserNotFound is returned when a user cannot be found
	ErrUserNotFound = errors.New("user not found")
	// ErrProviderNotFound is returned when an email provider is not found
	ErrProviderNotFound = errors.New("email provider not found")
	// ErrProviderConfig is returned when provider configuration is invalid
	ErrProviderConfig = errors.New("invalid provider configuration")
	// ErrEmailSendFailed is returned when email sending fails
	ErrEmailSendFailed = errors.New("failed to send email")
	// ErrTemplateRender is returned when template rendering fails
	ErrTemplateRender = errors.New("failed to render email template")
	// ErrTooManyTokens is returned when user has too many active tokens
	ErrTooManyTokens = errors.New("too many active verification tokens")
)
