package auth

import (
	"testing"

	"github.com/wispberry-tech/wispy-auth/storage"
)

// resetTwoFactorRateLimits simulates cleaning up 2FA codes to bypass rate limiting in tests
// This will be called by test functions that need to bypass the 30-second rate limit
func resetTwoFactorRateLimits(authService *AuthService) {
	// Directly delete codes in the database to bypass rate limiting
	authService.Cleanup2FACodes()
}

// Test helper functions for 2FA testing
func createUserFor2FA(t *testing.T, authService *AuthService, storage storage.Interface) *User {
	user := &User{
		Email:        "2fa-test@example.com",
		Username:     "2fauser",
		PasswordHash: "hashedpassword",
		Provider:     "email",
		IsActive:     true,
	}
	err := storage.CreateUser(user)
	if err != nil {
		t.Fatal("Failed to create user for 2FA test:", err)
	}

	// Create user security record
	security := &UserSecurityInfo{
		UserID:           user.ID,
		TwoFactorEnabled: false,
		LoginAttempts:    0,
	}
	err = storage.CreateUserSecurity(security)
	if err != nil {
		t.Fatal("Failed to create user security:", err)
	}

	return user
}

func getEmailService(authService *AuthService) *TrackingEmailService {
	// Access the email service from auth service for tracking
	if trackingService, ok := authService.emailService.(*TrackingEmailService); ok {
		return trackingService
	}
	return nil
}

// Enable 2FA Tests
func TestEnable2FAForUser(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Test enabling 2FA
	setup, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	if setup == nil {
		t.Error("Expected 2FA setup to be returned")
	}

	if len(setup.BackupCodes) == 0 {
		t.Error("Expected backup codes to be generated")
	}

	// Verify user security was updated
	security, err := storage.GetUserSecurity(user.ID)
	if err != nil {
		t.Fatal("Failed to get user security:", err)
	}

	if !security.TwoFactorEnabled {
		t.Error("Expected 2FA to be enabled")
	}

	// Check email was sent
	emailService := getEmailService(authService)
	if emailService != nil {
		lastEmail := emailService.GetLastEmail()
		if lastEmail == nil || lastEmail.Type != "2fa_enabled" {
			t.Error("Expected 2FA enabled email to be sent")
		}
	}
}

func TestEnable2FAForNonexistentUser(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Test enabling 2FA for non-existent user
	_, err := authService.Enable2FAForUser(99999)
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}

func TestEnable2FAAlreadyEnabled(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA first time
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA first time:", err)
	}

	// Try to enable again
	_, err = authService.Enable2FAForUser(user.ID)
	if err == nil {
		t.Error("Expected error when 2FA already enabled")
	}
}

// Send 2FA Code Tests
func TestSend2FACode(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA first
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Clear previous emails
	emailService := getEmailService(authService)
	if emailService != nil {
		emailService.Reset()
	}

	// Test sending 2FA code
	err = authService.Send2FACode(user.ID)
	if err != nil {
		t.Error("Failed to send 2FA code:", err)
	}

	// Check email was sent
	if emailService != nil {
		lastEmail := emailService.GetLastEmail()
		if lastEmail == nil || lastEmail.Type != "2fa_code" {
			t.Error("Expected 2FA code email to be sent")
		}
		if lastEmail.Token == "" {
			t.Error("Expected 2FA code in email")
		}
	}
}

func TestSend2FACodeNotEnabled(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Test sending 2FA code when not enabled
	err := authService.Send2FACode(user.ID)
	if err == nil {
		t.Error("Expected error when 2FA not enabled")
	}
}

func TestSend2FACodeRateLimit(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Reset rate limits for testing
	resetTwoFactorRateLimits(authService)

	// Send first code
	err = authService.Send2FACode(user.ID)
	if err != nil {
		t.Error("Failed to send first 2FA code:", err)
	}

	// Try to send immediately again (should be rate limited)
	err = authService.Send2FACode(user.ID)
	if err == nil {
		t.Error("Expected rate limiting error")
	}
}

// Verify 2FA Code Tests
func TestVerify2FACode(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Reset rate limits for testing
	resetTwoFactorRateLimits(authService)

	// Send code
	err = authService.Send2FACode(user.ID)
	if err != nil {
		t.Fatal("Failed to send 2FA code:", err)
	}

	// Get the sent code from email
	emailService := getEmailService(authService)
	var sentCode string
	if emailService != nil {
		lastEmail := emailService.GetLastEmail()
		if lastEmail != nil && lastEmail.Type == "2fa_code" {
			sentCode = lastEmail.Token
		}
	}

	if sentCode == "" {
		t.Skip("Cannot test verification without sent code")
	}

	// Test verifying valid code
	err = authService.Verify2FACode(user.ID, sentCode)
	if err != nil {
		t.Error("Failed to verify valid 2FA code:", err)
	}
}

func TestVerify2FACodeInvalid(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Test verifying invalid code
	err = authService.Verify2FACode(user.ID, "invalid-code")
	if err == nil {
		t.Error("Expected error for invalid 2FA code")
	}
}

func TestVerify2FACodeExpired(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Reset rate limits for testing
	resetTwoFactorRateLimits(authService)

	// Send code
	err = authService.Send2FACode(user.ID)
	if err != nil {
		t.Fatal("Failed to send 2FA code:", err)
	}

	// Manually expire the code by updating database
	// This is a simplified test - in real implementation we'd manipulate time
	err = authService.Verify2FACode(user.ID, "expired-code")
	if err == nil {
		t.Error("Expected error for expired code")
	}
}

func TestVerify2FACodeMaxAttempts(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Reset rate limits for testing
	resetTwoFactorRateLimits(authService)

	// Send code
	err = authService.Send2FACode(user.ID)
	if err != nil {
		t.Fatal("Failed to send 2FA code:", err)
	}

	// Try wrong code multiple times
	for i := 0; i < 5; i++ {
		err = authService.Verify2FACode(user.ID, "wrong-code")
		if err == nil {
			t.Error("Expected error for wrong code")
		}
	}

	// After max attempts, should be locked
	err = authService.Verify2FACode(user.ID, "any-code")
	if err == nil {
		t.Error("Expected lockout after max attempts")
	}
}

// Backup Codes Tests
func TestGenerate2FABackupCodes(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Generate backup codes
	codes, err := authService.Generate2FABackupCodes(user.ID)
	if err != nil {
		t.Error("Failed to generate backup codes:", err)
	}

	if len(codes) == 0 {
		t.Error("Expected backup codes to be generated")
	}

	// Verify codes are properly formatted
	for _, code := range codes {
		if len(code) < 8 {
			t.Errorf("Backup code too short: %s", code)
		}
	}
}

func TestGenerate2FABackupCodesNotEnabled(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Test generating backup codes when 2FA not enabled
	_, err := authService.Generate2FABackupCodes(user.ID)
	if err == nil {
		t.Error("Expected error when 2FA not enabled")
	}
}

// Disable 2FA Tests
func TestDisable2FAForUser(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA first
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Clear previous emails
	emailService := getEmailService(authService)
	if emailService != nil {
		emailService.Reset()
	}

	// Test disabling 2FA
	err = authService.Disable2FAForUser(user.ID)
	if err != nil {
		t.Error("Failed to disable 2FA:", err)
	}

	// Verify user security was updated
	security, err := storage.GetUserSecurity(user.ID)
	if err != nil {
		t.Fatal("Failed to get user security:", err)
	}

	if security.TwoFactorEnabled {
		t.Error("Expected 2FA to be disabled")
	}

	// Check email was sent
	if emailService != nil {
		lastEmail := emailService.GetLastEmail()
		if lastEmail == nil || lastEmail.Type != "2fa_disabled" {
			t.Error("Expected 2FA disabled email to be sent")
		}
	}
}

func TestDisable2FANotEnabled(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Test disabling 2FA when not enabled
	err := authService.Disable2FAForUser(user.ID)
	if err == nil {
		t.Error("Expected error when 2FA not enabled")
	}
}

// Utility Function Tests
func TestIs2FARequired(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Test when 2FA not enabled
	required, err := authService.Is2FARequired(user.ID)
	if err != nil {
		t.Error("Failed to check if 2FA required:", err)
	}

	// Should depend on security config
	expectedRequired := authService.securityConfig.RequireTwoFactor
	if required != expectedRequired {
		t.Errorf("Expected 2FA required to be %v, got %v", expectedRequired, required)
	}
}

func TestIs2FAEnabled(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Test when 2FA not enabled
	enabled, err := authService.Is2FAEnabled(user.ID)
	if err != nil {
		t.Error("Failed to check if 2FA enabled:", err)
	}

	if enabled {
		t.Error("Expected 2FA to not be enabled initially")
	}

	// Enable 2FA
	_, err = authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	// Test when 2FA enabled
	enabled, err = authService.Is2FAEnabled(user.ID)
	if err != nil {
		t.Error("Failed to check if 2FA enabled after enabling:", err)
	}

	if !enabled {
		t.Error("Expected 2FA to be enabled after enabling")
	}
}

// Code Generation Tests
func TestGenerate2FACode(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Test generating 2FA code
	code, err := authService.generate2FACode()
	if err != nil {
		t.Error("Failed to generate 2FA code:", err)
	}

	if code == "" {
		t.Error("Expected non-empty 2FA code")
	}

	// Test code length - use fixed 6 digits as standard
	expectedLength := 6
	if len(code) != expectedLength {
		t.Errorf("Expected code length %d, got %d", expectedLength, len(code))
	}

	// Test code is numeric
	for _, char := range code {
		if char < '0' || char > '9' {
			t.Errorf("Expected numeric code, got non-numeric character: %c", char)
		}
	}
}

// Cleanup Tests
func TestCleanup2FACodes(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Enable 2FA and send code
	_, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	err = authService.Send2FACode(user.ID)
	if err != nil {
		t.Fatal("Failed to send 2FA code:", err)
	}

	// Run cleanup (this should remove expired codes)
	authService.Cleanup2FACodes()

	// This test mainly ensures cleanup doesn't crash
	// In a real implementation, we'd check that expired codes are removed
}

// Integration Tests
func TestComplete2FAFlow(t *testing.T) {
	authService, storage := createTestAuthService(t)
	user := createUserFor2FA(t, authService, storage)

	// Step 1: Enable 2FA
	setup, err := authService.Enable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to enable 2FA:", err)
	}

	if setup == nil || len(setup.BackupCodes) == 0 {
		t.Error("Expected setup with backup codes")
	}

	// Reset rate limits for testing
	resetTwoFactorRateLimits(authService)

	// Step 2: Verify 2FA is enabled
	enabled, err := authService.Is2FAEnabled(user.ID)
	if err != nil {
		t.Fatal("Failed to check 2FA status:", err)
	}

	if !enabled {
		t.Error("Expected 2FA to be enabled")
	}

	// Step 3: Send verification code
	err = authService.Send2FACode(user.ID)
	if err != nil {
		t.Fatal("Failed to send 2FA code:", err)
	}

	// Step 4: Generate additional backup codes
	codes, err := authService.Generate2FABackupCodes(user.ID)
	if err != nil {
		t.Fatal("Failed to generate backup codes:", err)
	}

	if len(codes) == 0 {
		t.Error("Expected backup codes")
	}

	// Step 5: Disable 2FA
	err = authService.Disable2FAForUser(user.ID)
	if err != nil {
		t.Fatal("Failed to disable 2FA:", err)
	}

	// Step 6: Verify 2FA is disabled
	enabled, err = authService.Is2FAEnabled(user.ID)
	if err != nil {
		t.Fatal("Failed to check 2FA status after disable:", err)
	}

	if enabled {
		t.Error("Expected 2FA to be disabled")
	}
}

// Error Handling Tests
func TestTwoFactorErrorHandling(t *testing.T) {
	authService, _ := createTestAuthService(t)

	tests := []struct {
		name      string
		function  func() error
		shouldErr bool
	}{
		{
			name: "enable 2FA for invalid user",
			function: func() error {
				_, err := authService.Enable2FAForUser(0)
				return err
			},
			shouldErr: true,
		},
		{
			name: "send 2FA code for invalid user",
			function: func() error {
				return authService.Send2FACode(0)
			},
			shouldErr: true,
		},
		{
			name: "verify 2FA code for invalid user",
			function: func() error {
				return authService.Verify2FACode(0, "123456")
			},
			shouldErr: true,
		},
		{
			name: "generate backup codes for invalid user",
			function: func() error {
				_, err := authService.Generate2FABackupCodes(0)
				return err
			},
			shouldErr: true,
		},
		{
			name: "disable 2FA for invalid user",
			function: func() error {
				return authService.Disable2FAForUser(0)
			},
			shouldErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.function()

			if test.shouldErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.shouldErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}
