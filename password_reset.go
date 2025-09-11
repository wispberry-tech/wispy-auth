package auth

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Password reset functionality
func (a *AuthService) InitiatePasswordReset(email string) error {
	user, err := a.storage.GetUserByEmailAnyProvider(email)
	if err != nil {
		// Don't reveal if email exists
		return nil
	}

	// Generate secure reset token
	token := generateSecureRandomString(32)

	// Set expiration (24 hours)
	expiresAt := time.Now().Add(24 * time.Hour)

	user.PasswordResetToken = token
	user.PasswordResetExpiresAt = &expiresAt

	if err := a.storage.UpdateUser(user); err != nil {
		return fmt.Errorf("failed to save reset token: %w", err)
	}

	// Send reset email if email service is configured
	if a.emailService != nil {
		if err := a.emailService.SendPasswordResetEmail(user.Email, user.Name, token); err != nil {
			return fmt.Errorf("failed to send reset email: %w", err)
		}
	}

	return nil
}

func (a *AuthService) CompletePasswordReset(token, newPassword string) error {
	user, err := a.storage.GetUserByPasswordResetToken(token)
	if err != nil {
		return fmt.Errorf("invalid reset token")
	}

	// Check if token has expired
	if user.PasswordResetExpiresAt == nil || time.Now().After(*user.PasswordResetExpiresAt) {
		return fmt.Errorf("reset token has expired")
	}

	// Validate password strength
	if err := validatePasswordStrength(newPassword, a.securityConfig); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user
	now := time.Now()
	user.PasswordHash = string(hashedPassword)
	user.PasswordChangedAt = &now
	user.PasswordResetToken = "" // Clear the token
	user.PasswordResetExpiresAt = nil

	if err := a.storage.UpdateUser(user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Log the password change
	a.logSecurityEvent(&user.ID, nil, EventPasswordReset,
		"Password reset completed", "", "", "")

	// Invalidate all existing sessions
	if err := a.storage.InvalidateUserSessions(user.ID); err != nil {
		// Log but don't fail the reset
		fmt.Printf("Failed to invalidate sessions: %v\n", err)
	}

	return nil
}
