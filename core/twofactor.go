package core

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const (
	TwoFactorCodeLength = 6
	BackupCodeCount     = 10
)

// Enable2FA sends a 2FA verification code to enable 2FA
func (a *AuthService) Enable2FA(userID uint, ip string) error {
	if a.emailService == nil {
		return fmt.Errorf("email service not configured")
	}

	user, err := a.storage.GetUserByID(context.Background(), userID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}

	security, err := a.storage.GetUserSecurity(context.Background(), userID)
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

	if err := a.storage.Create2FACode(context.Background(), twoFactorCode); err != nil {
		return err
	}

	if err := a.emailService.Send2FACode(user.Email, code); err != nil {
		slog.Error("Failed to send 2FA code", "error", err)
		return err
	}

	a.logSecurityEvent(&userID, "2fa_enablement_code_sent", "2FA enablement code sent",
		ip, "", true)

	slog.Info("2FA enablement code sent", "user_id", userID)
	return nil
}

// SendLogin2FACode sends a new 2FA code for login
func (a *AuthService) SendLogin2FACode(userID uint) error {
	if a.emailService == nil {
		return fmt.Errorf("email service not configured")
	}

	user, err := a.storage.GetUserByID(context.Background(), userID)
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

	if err := a.storage.Create2FACode(context.Background(), twoFactorCode); err != nil {
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
	return a.storage.Get2FABackupCodes(context.Background(), userID)
}

// RegenerateBackupCodes generates new backup codes and invalidates old ones
func (a *AuthService) RegenerateBackupCodes(userID uint) ([]*TwoFactorBackupCode, error) {
	return a.storage.Regenerate2FABackupCodes(context.Background(), userID)
}

func (a *AuthService) generateBackupCodes(userID uint) ([]*TwoFactorBackupCode, error) {
	backupCodes := make([]*TwoFactorBackupCode, 0, BackupCodeCount)

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

		if err := a.storage.Create2FABackupCode(context.Background(), backupCode); err != nil {
			return nil, fmt.Errorf("failed to create 2FA backup code: %w", err)
		}

		backupCodes = append(backupCodes, backupCode)
	}

	return backupCodes, nil
}

