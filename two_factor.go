package auth

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/wispberry-tech/wispy-auth/storage"
	"golang.org/x/crypto/bcrypt"
)

// Type aliases to simplify type usage
type UserSecurityInfo = storage.UserSecurity
type TwoFactorCodeInfo = storage.TwoFactorCode

// TwoFactorSetup represents the 2FA setup response
type TwoFactorSetup struct {
	BackupCodes []string `json:"backup_codes"`
	Message     string   `json:"message"`
}

// Enable2FAForUser enables 2FA for a user and generates backup codes
func (a *AuthService) Enable2FAForUser(userID uint) (*TwoFactorSetup, error) {
	// Get user to ensure they exist
	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Get user security record
	userSecurity, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user security: %w", err)
	}

	// Check if 2FA is already enabled
	if userSecurity.TwoFactorEnabled {
		return nil, fmt.Errorf("2FA is already enabled for this user")
	}

	// Generate backup codes
	backupCodes, err := a.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Hash backup codes for storage
	hashedCodes, err := a.hashBackupCodes(backupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash backup codes: %w", err)
	}

	// Update user security with 2FA enabled and backup codes
	userSecurity.TwoFactorEnabled = true
	userSecurity.BackupCodes = hashedCodes
	userSecurity.UpdatedAt = time.Now()

	if err := a.storage.UpdateUserSecurity(userSecurity); err != nil {
		return nil, fmt.Errorf("failed to enable 2FA: %w", err)
	}

	// Log security event
	a.logSecurityEvent(&userID, nil, "2FA_ENABLED", "Two-factor authentication enabled", "", "", "")

	// Send notification email
	if a.emailService != nil {
		err = a.emailService.Send2FAEnabled(user.Email)
		if err != nil {
			slog.Warn("Failed to send 2FA enabled email", "error", err, "user_id", userID)
		}
	}

	return &TwoFactorSetup{
		BackupCodes: backupCodes,
		Message:     "2FA has been enabled. Save these backup codes in a secure location.",
	}, nil
}

// Send2FACode generates and sends a 2FA code via email with rate limiting
func (a *AuthService) Send2FACode(userID uint) error {
	// Get user
	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Check if 2FA is enabled
	userSecurity, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return fmt.Errorf("failed to get user security: %w", err)
	}

	if !userSecurity.TwoFactorEnabled {
		return fmt.Errorf("2FA is not enabled for this user")
	}

	// Check for existing code and rate limiting
	existingCode, err := a.storage.GetActiveTwoFactorCodeByUserID(userID)
	if err == nil && existingCode != nil {
		// Check if user is locked out
		if existingCode.LockedUntil != nil && time.Now().Before(*existingCode.LockedUntil) {
			return fmt.Errorf("2FA is temporarily locked due to too many attempts")
		}

		// Don't send new code if one was sent recently (prevent spam)
		if time.Since(existingCode.CreatedAt) < 30*time.Second {
			return fmt.Errorf("please wait 30 seconds before requesting a new code")
		}
	}

	// Generate 6-digit code
	code, err := a.generate2FACode()
	if err != nil {
		return fmt.Errorf("failed to generate 2FA code: %w", err)
	}

	// Store code with configurable expiration
	codeExpiry := a.securityConfig.TwoFactorCodeExpiry
	if codeExpiry == 0 {
		codeExpiry = 5 * time.Minute // Default fallback
	}

	twoFactorCode := &storage.TwoFactorCode{
		UserID:       userID,
		Code:         code,
		ExpiresAt:    time.Now().Add(codeExpiry),
		CreatedAt:    time.Now(),
		AttemptCount: 0,
	}

	// Save to database
	err = a.storage.CreateTwoFactorCode(twoFactorCode)
	if err != nil {
		return fmt.Errorf("failed to store 2FA code: %w", err)
	}

	// Send code via email
	if a.emailService != nil {
		err = a.emailService.Send2FACode(user.Email, code)
		if err != nil {
			return fmt.Errorf("failed to send 2FA code: %w", err)
		}
	} else {
		// For development/testing, log the code
		slog.Info("2FA Code generated", "user_id", userID, "code", code)
	}

	// Log security event
	a.logSecurityEvent(&userID, nil, "2FA_CODE_SENT", "2FA verification code sent", "", "", "")

	return nil
}

// Verify2FACode verifies a 2FA code or backup code with attempt tracking and lockout
func (a *AuthService) Verify2FACode(userID uint, code string) error {
	// Check if 2FA is enabled
	userSecurity, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return fmt.Errorf("failed to get user security: %w", err)
	}

	if !userSecurity.TwoFactorEnabled {
		return fmt.Errorf("2FA is not enabled for this user")
	}

	// Try verifying as regular 2FA code first
	storedCode, err := a.storage.GetActiveTwoFactorCodeByUserID(userID)
	if err == nil && storedCode != nil {
		// Check if user is locked out
		if storedCode.LockedUntil != nil && time.Now().Before(*storedCode.LockedUntil) {
			return fmt.Errorf("2FA is temporarily locked due to too many failed attempts")
		}

		// Check if code is expired
		if time.Now().After(storedCode.ExpiresAt) {
			return fmt.Errorf("2FA code has expired")
		}

		// Check if code is already used
		if storedCode.UsedAt != nil {
			return fmt.Errorf("2FA code has already been used")
		}

		// Verify the code
		if storedCode.Code == code {
			// Mark code as used
			now := time.Now()
			storedCode.UsedAt = &now

			// Update in database
			err = a.storage.UpdateTwoFactorCode(storedCode)
			if err != nil {
				return fmt.Errorf("failed to update 2FA code status: %w", err)
			}

			// Log successful verification
			a.logSecurityEvent(&userID, nil, "2FA_CODE_VERIFIED", "2FA code verified successfully", "", "", "")

			return nil
		}

		// Increment attempt count for failed verification
		storedCode.AttemptCount++
		maxAttempts := a.securityConfig.Max2FAAttempts
		if maxAttempts == 0 {
			maxAttempts = 3 // Default fallback
		}

		if storedCode.AttemptCount >= maxAttempts {
			// Lock out the user
			lockoutDuration := a.securityConfig.TwoFactorLockoutDuration
			if lockoutDuration == 0 {
				lockoutDuration = 15 * time.Minute // Default fallback
			}
			lockoutUntil := time.Now().Add(lockoutDuration)
			storedCode.LockedUntil = &lockoutUntil

			// Update in database
			err = a.storage.UpdateTwoFactorCode(storedCode)
			if err != nil {
				return fmt.Errorf("failed to update 2FA lockout status: %w", err)
			}

			// Log lockout
			a.logSecurityEvent(&userID, nil, "2FA_LOCKED", "2FA locked due to too many failed attempts", "", "", "")

			return fmt.Errorf("2FA locked due to too many failed attempts. Try again in %v", lockoutDuration)
		}

		// Update attempt count in database
		err = a.storage.UpdateTwoFactorCode(storedCode)
		if err != nil {
			return fmt.Errorf("failed to update 2FA attempt count: %w", err)
		}
	}

	// Try verifying as backup code
	if a.verifyBackupCode(userSecurity, code) {
		// Remove used backup code
		err = a.removeUsedBackupCode(userSecurity, code)
		if err != nil {
			slog.Error("Failed to remove used backup code", "error", err, "user_id", userID)
		}

		// Log backup code usage
		a.logSecurityEvent(&userID, nil, "2FA_BACKUP_CODE_USED", "Backup code used for 2FA verification", "", "", "")

		return nil
	}

	// Log failed verification
	a.logSecurityEvent(&userID, nil, "2FA_CODE_FAILED", "Failed 2FA verification attempt", "", "", "")

	return fmt.Errorf("invalid or expired 2FA code")
}

// Generate2FABackupCodes generates new backup codes for a user
func (a *AuthService) Generate2FABackupCodes(userID uint) ([]string, error) {
	// Check if 2FA is enabled
	userSecurity, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user security: %w", err)
	}

	if !userSecurity.TwoFactorEnabled {
		return nil, fmt.Errorf("2FA is not enabled for this user")
	}

	// Generate new backup codes
	backupCodes, err := a.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Hash backup codes for storage
	hashedCodes, err := a.hashBackupCodes(backupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash backup codes: %w", err)
	}

	// Update user security with new backup codes
	userSecurity.BackupCodes = hashedCodes
	userSecurity.UpdatedAt = time.Now()

	if err := a.storage.UpdateUserSecurity(userSecurity); err != nil {
		return nil, fmt.Errorf("failed to update backup codes: %w", err)
	}

	// Log security event
	a.logSecurityEvent(&userID, nil, "2FA_BACKUP_CODES_REGENERATED", "New backup codes generated", "", "", "")

	return backupCodes, nil
}

// Disable2FAForUser disables 2FA for a user
func (a *AuthService) Disable2FAForUser(userID uint) error {
	// Get user
	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Get user security record
	userSecurity, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return fmt.Errorf("failed to get user security: %w", err)
	}

	// Check if 2FA is enabled
	if !userSecurity.TwoFactorEnabled {
		return fmt.Errorf("2FA is not enabled for this user")
	}

	// Disable 2FA and clear secrets
	userSecurity.TwoFactorEnabled = false
	userSecurity.TwoFactorSecret = ""
	userSecurity.BackupCodes = ""
	userSecurity.UpdatedAt = time.Now()

	if err := a.storage.UpdateUserSecurity(userSecurity); err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	// Log security event
	a.logSecurityEvent(&userID, nil, "2FA_DISABLED", "Two-factor authentication disabled", "", "", "")

	// Send notification email
	if a.emailService != nil {
		err = a.emailService.Send2FADisabled(user.Email)
		if err != nil {
			slog.Warn("Failed to send 2FA disabled email", "error", err, "user_id", userID)
		}
	}

	return nil
}

// Helper functions

// generate2FACode generates a 6-digit numeric code
func (a *AuthService) generate2FACode() (string, error) {
	// Generate random 6-digit number
	max := big.NewInt(1000000) // 1,000,000
	min := big.NewInt(100000)  // 100,000

	n, err := rand.Int(rand.Reader, max.Sub(max, min))
	if err != nil {
		return "", err
	}

	code := n.Add(n, min).String()
	return code, nil
}

// generateBackupCodes generates 10 backup codes
func (a *AuthService) generateBackupCodes() ([]string, error) {
	codes := make([]string, 10)

	for i := 0; i < 10; i++ {
		// Generate 8-character alphanumeric code
		code, err := a.generateBackupCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}

	return codes, nil
}

// generateBackupCode generates a single 8-character backup code
func (a *AuthService) generateBackupCode() (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 8

	code := make([]byte, length)
	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		code[i] = charset[num.Int64()]
	}

	return string(code), nil
}

// hashBackupCodes hashes backup codes for secure storage
func (a *AuthService) hashBackupCodes(codes []string) (string, error) {
	hashedCodes := make([]string, len(codes))

	for i, code := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		hashedCodes[i] = string(hash)
	}

	// Join with newlines for storage
	result := ""
	for i, hash := range hashedCodes {
		if i > 0 {
			result += "\n"
		}
		result += hash
	}

	return result, nil
}

// verifyBackupCode verifies a backup code against stored hashes
func (a *AuthService) verifyBackupCode(userSecurity *UserSecurityInfo, code string) bool {
	if userSecurity.BackupCodes == "" {
		return false
	}

	// Split stored hashes
	hashes := []string{}
	current := ""
	for _, char := range userSecurity.BackupCodes {
		if char == '\n' {
			if current != "" {
				hashes = append(hashes, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		hashes = append(hashes, current)
	}

	// Check code against each hash
	for _, hash := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) == nil {
			return true
		}
	}

	return false
}

// removeUsedBackupCode removes a used backup code from storage
func (a *AuthService) removeUsedBackupCode(userSecurity *UserSecurityInfo, usedCode string) error {
	if userSecurity.BackupCodes == "" {
		return nil
	}

	// Split stored hashes
	hashes := []string{}
	current := ""
	for _, char := range userSecurity.BackupCodes {
		if char == '\n' {
			if current != "" {
				hashes = append(hashes, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		hashes = append(hashes, current)
	}

	// Remove the used hash
	remainingHashes := []string{}
	for _, hash := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(usedCode)) != nil {
			remainingHashes = append(remainingHashes, hash)
		}
	}

	// Rebuild backup codes string
	result := ""
	for i, hash := range remainingHashes {
		if i > 0 {
			result += "\n"
		}
		result += hash
	}

	userSecurity.BackupCodes = result
	userSecurity.UpdatedAt = time.Now()

	return a.storage.UpdateUserSecurity(userSecurity)
}

// Is2FARequired checks if 2FA is required for a user
func (a *AuthService) Is2FARequired(userID uint) (bool, error) {
	userSecurity, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return false, err
	}

	// Check global requirement or user-specific enablement
	return a.securityConfig.RequireTwoFactor || userSecurity.TwoFactorEnabled, nil
}

// Is2FAEnabled checks if 2FA is enabled for a user
func (a *AuthService) Is2FAEnabled(userID uint) (bool, error) {
	userSecurity, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return false, err
	}

	return userSecurity.TwoFactorEnabled, nil
}

// Cleanup2FACodes removes expired and used 2FA codes (should be called periodically)
func (a *AuthService) Cleanup2FACodes() {
	// Use the storage interface to delete expired codes
	err := a.storage.DeleteExpiredTwoFactorCodes()
	if err != nil {
		slog.Error("Failed to clean up expired 2FA codes", "error", err)
	}
}

// StartAutoCleanup starts a background routine to clean up expired 2FA codes
func (a *AuthService) StartAutoCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Run cleanup every 5 minutes
		defer ticker.Stop()

		for range ticker.C {
			a.Cleanup2FACodes()
		}
	}()
}
