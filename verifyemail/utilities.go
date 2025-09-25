package verifyemail

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/wispberry-tech/wispy-auth/core"
)

// Utilities provides utility functions for email verification operations
type Utilities struct {
	storage        Storage
	config         Config
	provider       EmailProvider
	templateEngine *TemplateEngine
}

// GenerateVerificationToken creates a new email verification token for a user
func (u *Utilities) GenerateVerificationToken(userID uint, email string, options SendOptions) (*EmailVerificationToken, error) {
	// Check if user can create more tokens
	if u.config.MaxTokensPerUser > 0 {
		activeCount, err := u.storage.CountActiveTokensForUser(userID)
		if err != nil {
			return nil, fmt.Errorf("failed to count active tokens: %w", err)
		}

		if activeCount >= u.config.MaxTokensPerUser {
			return nil, fmt.Errorf("%w: user has %d active tokens (max: %d)",
				ErrTooManyTokens, activeCount, u.config.MaxTokensPerUser)
		}
	}

	// Generate random token
	token, err := u.generateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Ensure uniqueness
	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		available, err := u.storage.CheckTokenAvailability(token)
		if err != nil {
			return nil, fmt.Errorf("failed to check token availability: %w", err)
		}

		if available {
			break
		}

		// Generate new token
		token, err = u.generateRandomToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate token: %w", err)
		}

		if i == maxAttempts-1 {
			return nil, fmt.Errorf("failed to generate unique token after %d attempts", maxAttempts)
		}
	}

	// Set expiry
	expiry := u.config.TokenExpiry
	if options.ExpiryOverride != nil {
		expiry = *options.ExpiryOverride
	}

	// Create the verification token record
	verificationToken := &EmailVerificationToken{
		UserID:    userID,
		Token:     token,
		Email:     strings.ToLower(email),
		ExpiresAt: time.Now().Add(expiry),
		IsUsed:    false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Store in database
	err = u.storage.CreateEmailVerificationToken(verificationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification token: %w", err)
	}

	// Get the created token with ID populated
	return u.storage.GetEmailVerificationTokenByToken(verificationToken.Token)
}

// ValidateVerificationToken checks if a verification token is valid
func (u *Utilities) ValidateVerificationToken(token string) (*EmailVerificationToken, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidToken)
	}

	// Get the verification token
	verificationToken, err := u.storage.GetEmailVerificationTokenByToken(token)
	if err != nil {
		return nil, fmt.Errorf("%w: token not found", ErrTokenNotFound)
	}

	// Check if token is already used
	if verificationToken.IsUsed {
		return nil, fmt.Errorf("%w", ErrTokenUsed)
	}

	// Check if token has expired
	if verificationToken.IsExpired() {
		return nil, fmt.Errorf("%w", ErrTokenExpired)
	}

	return verificationToken, nil
}

// VerifyEmail processes email verification using a token
func (u *Utilities) VerifyEmail(token string, options VerifyOptions) (*EmailVerificationToken, error) {
	// Validate the token
	verificationToken, err := u.ValidateVerificationToken(token)
	if err != nil {
		return nil, err
	}

	// Mark token as used
	verificationToken.IsUsed = true
	verificationToken.UpdatedAt = time.Now()

	if err := u.storage.UpdateEmailVerificationToken(verificationToken); err != nil {
		return nil, fmt.Errorf("failed to update verification token: %w", err)
	}

	// Update user's email verification status if requested
	if options.UpdateEmailStatus {
		user, err := u.storage.GetUserByID(verificationToken.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}

		// Update user's email if it matches the verification token
		if user.Email == verificationToken.Email {
			user.EmailVerified = true
			user.UpdatedAt = time.Now()

			if err := u.storage.UpdateUser(user); err != nil {
				return nil, fmt.Errorf("failed to update user email status: %w", err)
			}
		}
	}

	// Delete token after use if requested
	if options.DeleteTokenAfterUse {
		if err := u.storage.DeleteEmailVerificationToken(verificationToken.ID); err != nil {
			// Log error but don't fail the verification
			// In production, you might want to log this properly
			fmt.Printf("Failed to delete verification token: %v\n", err)
		}
	}

	return verificationToken, nil
}

// SendVerificationEmail generates and sends a verification email
func (u *Utilities) SendVerificationEmail(user *core.User, options SendOptions) (*EmailVerificationToken, error) {
	// Generate verification token
	token, err := u.GenerateVerificationToken(user.ID, user.Email, options)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Generate verification URL
	verificationURL, err := u.generateVerificationURL(token.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification URL: %w", err)
	}

	// Prepare email data
	emailData := &EmailData{
		User:            user,
		Token:           token.Token,
		VerificationURL: verificationURL,
		ExpiresAt:       token.ExpiresAt,
		AppName:         u.config.AppName,
		SupportEmail:    u.config.SupportEmail,
		CustomData:      options.CustomData,
	}

	// Choose template
	template := &u.config.DefaultTemplate
	if options.CustomTemplate != nil {
		template = options.CustomTemplate
	}

	// Render email message
	message, err := u.templateEngine.RenderTemplate(template, emailData)
	if err != nil {
		return nil, fmt.Errorf("failed to render email template: %w", err)
	}

	// Send email
	err = u.provider.SendEmail(nil, message) // TODO: Add context
	if err != nil {
		return nil, fmt.Errorf("failed to send verification email: %w", err)
	}

	return token, nil
}

// ResendVerificationEmail resends verification email for a user
func (u *Utilities) ResendVerificationEmail(user *core.User, options SendOptions) (*EmailVerificationToken, error) {
	// Invalidate existing tokens for this user and email (optional)
	// This prevents users from having multiple active tokens

	existingTokens, err := u.storage.GetEmailVerificationTokensByUser(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing tokens: %w", err)
	}

	// Mark existing tokens for this email as used
	for _, existingToken := range existingTokens {
		if existingToken.Email == strings.ToLower(user.Email) && !existingToken.IsUsed {
			existingToken.IsUsed = true
			existingToken.UpdatedAt = time.Now()
			u.storage.UpdateEmailVerificationToken(existingToken)
		}
	}

	// Send new verification email
	return u.SendVerificationEmail(user, options)
}

// GetUserVerificationTokens retrieves all verification tokens for a user
func (u *Utilities) GetUserVerificationTokens(userID uint) ([]*EmailVerificationToken, error) {
	return u.storage.GetEmailVerificationTokensByUser(userID)
}

// CleanupExpiredTokens removes expired verification tokens
func (u *Utilities) CleanupExpiredTokens() error {
	return u.storage.CleanupExpiredTokens()
}

// generateRandomToken generates a cryptographically secure random token
func (u *Utilities) generateRandomToken() (string, error) {
	// Generate random bytes
	bytes := make([]byte, u.config.TokenLength*3/4+1) // Base64 expansion
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Encode to base64 and clean up
	token := base64.URLEncoding.EncodeToString(bytes)
	token = strings.ReplaceAll(token, "-", "")
	token = strings.ReplaceAll(token, "_", "")
	token = strings.ReplaceAll(token, "=", "")

	// Truncate to desired length
	if len(token) > u.config.TokenLength {
		token = token[:u.config.TokenLength]
	}

	return strings.ToUpper(token), nil
}

// generateVerificationURL creates the verification URL
func (u *Utilities) generateVerificationURL(token string) (string, error) {
	baseURL := strings.TrimRight(u.config.BaseURL, "/")
	verifyPath := strings.TrimLeft(u.config.VerifyPath, "/")

	// Create URL with token parameter
	verifyURL := fmt.Sprintf("%s/%s?token=%s", baseURL, verifyPath, url.QueryEscape(token))

	return verifyURL, nil
}

// IsValidEmail performs basic email validation
func (u *Utilities) IsValidEmail(email string) bool {
	// Basic email validation - you might want to use a proper email validation library
	return strings.Contains(email, "@") && len(email) > 5
}
