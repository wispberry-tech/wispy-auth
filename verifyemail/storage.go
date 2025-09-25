package verifyemail

import (
	"github.com/wispberry-tech/wispy-auth/core"
)

// Storage extends the core.Storage interface with email verification-specific methods
// This allows the email verification module to work with any storage backend
// that implements both core functionality and email verification operations
type Storage interface {
	core.Storage // Embed all core storage methods

	// Email Verification Token operations
	CreateEmailVerificationToken(token *EmailVerificationToken) error
	GetEmailVerificationTokenByID(id uint) (*EmailVerificationToken, error)
	GetEmailVerificationTokenByToken(token string) (*EmailVerificationToken, error)
	GetEmailVerificationTokensByUser(userID uint) ([]*EmailVerificationToken, error)
	GetEmailVerificationTokensByEmail(email string) ([]*EmailVerificationToken, error)
	UpdateEmailVerificationToken(token *EmailVerificationToken) error
	DeleteEmailVerificationToken(tokenID uint) error

	// Token management
	MarkTokenAsUsed(tokenID uint) error
	CleanupExpiredTokens() error
	CountActiveTokensForUser(userID uint) (int, error)
	CountActiveTokensForEmail(email string) (int, error)

	// Validation
	ValidateEmailVerificationToken(token string) (*EmailVerificationToken, error)
	CheckTokenAvailability(token string) (bool, error)
}
