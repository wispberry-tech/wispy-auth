package auth

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/pquerna/otp/totp"
)

// EnableTwoFactor enables 2FA for a user and returns the secret and backup codes
func (a *AuthService) EnableTwoFactor(userID uint) (string, []string, error) {
	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		slog.Error("User not found for 2FA enable", "error", err, "user_id", userID)
		return "", nil, fmt.Errorf("user not found: %w", err)
	}

	if user.TwoFactorEnabled {
		slog.Warn("Attempt to enable 2FA when already enabled", "user_id", userID)
		return "", nil, fmt.Errorf("2FA is already enabled")
	}

	// Generate secret
	secret := base32.StdEncoding.EncodeToString([]byte(generateSecureRandomString(20)))

	// Generate backup codes
	backupCodes := make([]string, 8)
	for i := range backupCodes {
		backupCodes[i] = strings.ToUpper(generateSecureRandomString(10))
	}

	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		slog.Error("Failed to encode backup codes", "error", err, "user_id", userID)
		return "", nil, fmt.Errorf("failed to encode backup codes: %w", err)
	}

	// Update user
	user.TwoFactorSecret = secret
	user.BackupCodes = string(backupCodesJSON)
	user.TwoFactorEnabled = true

	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to enable 2FA", "error", err, "user_id", userID)
		return "", nil, fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return secret, backupCodes, nil
}

// ValidateTwoFactor validates a 2FA code or backup code
func (a *AuthService) ValidateTwoFactor(userID uint, code string) error {
	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		slog.Error("User not found for 2FA validation", "error", err, "user_id", userID)
		return fmt.Errorf("user not found: %w", err)
	}

	if !user.TwoFactorEnabled {
		slog.Warn("Attempt to validate 2FA when not enabled", "user_id", userID)
		return fmt.Errorf("2FA is not enabled")
	}

	// First try TOTP code
	valid := totp.Validate(code, user.TwoFactorSecret)
	if valid {
		return nil
	}

	// If not valid, check backup codes
	var backupCodes []string
	if err := json.Unmarshal([]byte(user.BackupCodes), &backupCodes); err != nil {
		slog.Error("Failed to decode backup codes", "error", err, "user_id", userID)
		return fmt.Errorf("failed to decode backup codes: %w", err)
	}

	// Check backup codes
	for i, backup := range backupCodes {
		if subtle.ConstantTimeCompare([]byte(backup), []byte(code)) == 1 {
			// Remove used backup code
			backupCodes = append(backupCodes[:i], backupCodes[i+1:]...)
			backupCodesJSON, _ := json.Marshal(backupCodes)
			user.BackupCodes = string(backupCodesJSON)
			a.storage.UpdateUser(user)
			return nil
		}
	}

	slog.Warn("Invalid 2FA code attempted", "user_id", userID)
	return fmt.Errorf("invalid 2FA code")
}

// DisableTwoFactor disables 2FA for a user
func (a *AuthService) DisableTwoFactor(userID uint) error {
	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		slog.Error("User not found for 2FA disable", "error", err, "user_id", userID)
		return fmt.Errorf("user not found: %w", err)
	}

	if !user.TwoFactorEnabled {
		slog.Warn("Attempt to disable 2FA when not enabled", "user_id", userID)
		return fmt.Errorf("2FA is not enabled")
	}

	user.TwoFactorEnabled = false
	user.TwoFactorSecret = ""
	user.BackupCodes = ""

	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to disable 2FA", "error", err, "user_id", userID)
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	return nil
}
