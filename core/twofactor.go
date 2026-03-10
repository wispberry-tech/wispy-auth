package core

import (
	"fmt"
	"log/slog"
	"time"
)

const (
	TwoFactorCodeLength = 6
	BackupCodeCount     = 10
)

// Enable2FA sends a 2FA verification code to enable 2FA
func (a *AuthService) Enable2FA(userID uint) error {
	if a.emailService == nil {
		return fmt.Errorf("email service not configured")
	}

	user, err := a.storage.GetUserByID(userID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}

	security, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return err
	}

	if security.TwoFactorEnabled {
		return fmt.Errorf("2FA already enabled")
	}

	code, err := GenerateSecureToken(3)
	if err != nil {
		return fmt.Errorf("failed to generate 2FA code: %w", err)
	}

	twoFactorCode := &TwoFactorCode{
		UserID:    userID,
		Code:      code,
		CodeType:  "enable",
		ExpiresAt: time.Now().Add(a.securityConfig.TwoFactorCodeExpiry),
		CreatedAt: time.Now(),
	}

	if err := a.storage.Create2FACode(twoFactorCode); err != nil {
		return err
	}

	if err := a.emailService.Send2FACode(user.Email, code); err != nil {
		slog.Error("Failed to send 2FA code", "error", err)
		return err
	}

	a.logSecurityEvent(&userID, "2fa_enablement_code_sent", "2FA enablement code sent",
		extractIP(nil), "", true)

	slog.Info("2FA enablement code sent", "user_id", userID)
	return nil
}

// VerifyEnable2FA verifies the code and enables 2FA
func (a *AuthService) VerifyEnable2FA(userID uint, code string) error {
	twoFactorCode, err := a.storage.Get2FACode(userID, code)
	if err != nil || twoFactorCode == nil {
		return fmt.Errorf("invalid or expired code")
	}

	if twoFactorCode.CodeType != "enable" {
		return fmt.Errorf("invalid code type")
	}

	if time.Now().After(twoFactorCode.ExpiresAt) {
		return fmt.Errorf("code expired")
	}

	security, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return err
	}

	security.TwoFactorEnabled = true
	now := time.Now()
	security.TwoFactorVerifiedAt = &now

	if err := a.storage.UpdateUserSecurity(security); err != nil {
		return err
	}

	if err := a.storage.Use2FACode(userID, code); err != nil {
		slog.Error("Failed to mark 2FA code as used", "error", err)
	}

	backupCodes, err := a.generateBackupCodes(userID)
	if err != nil {
		slog.Error("Failed to generate backup codes", "error", err)
	}

	a.logSecurityEvent(&userID, "2fa_enabled", "2FA enabled successfully",
		extractIP(nil), "", true)

	slog.Info("2FA enabled", "user_id", userID, "backup_codes", len(backupCodes))
	return nil
}

// Disable2FA disables 2FA for a user
func (a *AuthService) Disable2FA(userID uint, password string) error {
	user, err := a.storage.GetUserByID(userID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}

	if !checkPasswordHash(password, user.PasswordHash) {
		return fmt.Errorf("invalid password")
	}

	security, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return err
	}

	security.TwoFactorEnabled = false
	security.TwoFactorSecret = ""
	security.TwoFactorBackupCodes = ""
	security.TwoFactorVerifiedAt = nil

	if err := a.storage.UpdateUserSecurity(security); err != nil {
		return err
	}

	a.logSecurityEvent(&userID, "2fa_disabled", "2FA disabled",
		extractIP(nil), "", true)

	slog.Info("2FA disabled", "user_id", userID)
	return nil
}

// VerifyLogin2FA verifies 2FA code during login
func (a *AuthService) VerifyLogin2FA(userID uint, code string) error {
	security, err := a.storage.GetUserSecurity(userID)
	if err != nil {
		return err
	}

	if !security.TwoFactorEnabled {
		return fmt.Errorf("2FA not enabled")
	}

	if len(code) > 10 {
		if err := a.storage.Use2FABackupCode(userID, code); err == nil {
			slog.Info("2FA backup code used", "user_id", userID)
			a.logSecurityEvent(&userID, "2fa_backup_code_used", "2FA backup code used",
				extractIP(nil), "", true)
			return nil
		}
		return fmt.Errorf("invalid 2FA backup code")
	}

	twoFactorCode, err := a.storage.Get2FACode(userID, code)
	if err != nil || twoFactorCode == nil {
		a.handleFailed2FAAttempt(userID)
		return fmt.Errorf("invalid 2FA code")
	}

	if twoFactorCode.CodeType != "login" {
		return fmt.Errorf("invalid code type")
	}

	if time.Now().After(twoFactorCode.ExpiresAt) {
		a.handleFailed2FAAttempt(userID)
		return fmt.Errorf("code expired")
	}

	if err := a.storage.Use2FACode(userID, code); err != nil {
		slog.Error("Failed to mark 2FA code as used", "error", err)
	}

	a.logSecurityEvent(&userID, "2fa_verified", "2FA verified successfully",
		extractIP(nil), "", true)

	return nil
}

// SendLogin2FACode sends a new 2FA code for login
func (a *AuthService) SendLogin2FACode(userID uint) error {
	if a.emailService == nil {
		return fmt.Errorf("email service not configured")
	}

	user, err := a.storage.GetUserByID(userID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}

	code, err := GenerateSecureToken(3)
	if err != nil {
		return fmt.Errorf("failed to generate 2FA code: %w", err)
	}

	twoFactorCode := &TwoFactorCode{
		UserID:    userID,
		Code:      code,
		CodeType:  "login",
		ExpiresAt: time.Now().Add(a.securityConfig.TwoFactorCodeExpiry),
		CreatedAt: time.Now(),
	}

	if err := a.storage.Create2FACode(twoFactorCode); err != nil {
		return err
	}

	if err := a.emailService.Send2FACode(user.Email, code); err != nil {
		slog.Error("Failed to send 2FA code", "error", err)
		return err
	}

	slog.Info("2FA login code sent", "user_id", userID)
	return nil
}

// GetBackupCodes retrieves all backup codes for a user
func (a *AuthService) GetBackupCodes(userID uint) ([]*TwoFactorBackupCode, error) {
	return a.storage.Get2FABackupCodes(userID)
}

// RegenerateBackupCodes generates new backup codes and invalidates old ones
func (a *AuthService) RegenerateBackupCodes(userID uint) ([]*TwoFactorBackupCode, error) {
	return a.storage.Regenerate2FABackupCodes(userID)
}

func (a *AuthService) generateBackupCodes(userID uint) ([]*TwoFactorBackupCode, error) {
	backupCodes := make([]*TwoFactorBackupCode, BackupCodeCount)

	for i := 0; i < BackupCodeCount; i++ {
		code, err := GenerateSecureToken(3)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}

		backupCode := &TwoFactorBackupCode{
			UserID:    userID,
			Code:      code,
			CreatedAt: time.Now(),
		}

		if err := a.storage.Create2FABackupCode(backupCode); err != nil {
			return nil, fmt.Errorf("failed to create 2FA backup code: %w", err)
		}

		backupCodes = append(backupCodes, backupCode)
	}

	return backupCodes, nil
}

func (a *AuthService) handleFailed2FAAttempt(userID uint) {
	a.logSecurityEvent(&userID, "2fa_failed", "Failed 2FA attempt",
		extractIP(nil), "", false)
}
