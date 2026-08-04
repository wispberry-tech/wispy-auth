package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTwoFactor_Enable2FA_ValidFlow tests 2FA enablement with valid password
func TestTwoFactor_Enable2FA_ValidFlow(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	req := createTestRequest(t, "POST", "/2fa/enable", map[string]interface{}{
		"password": "TestPassword123!",
	})
	ctx := context.WithValue(req.Context(), ctxKeyUser, user)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.Enable2FAHandler(rec, req)
	var resp Enable2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusOK {
		t.Errorf("Enable2FAHandler() status = %d, expected %d: %s", rec.Code, http.StatusOK, resp.Error)
	}
}

// TestTwoFactor_Enable2FA_InvalidPassword tests invalid current password
func TestTwoFactor_Enable2FA_InvalidPassword(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	req := createTestRequest(t, "POST", "/2fa/enable", map[string]interface{}{
		"password": "WrongPassword!",
	})
	ctx := context.WithValue(req.Context(), ctxKeyUser, user)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.Enable2FAHandler(rec, req)
	var resp Enable2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid password, got %d", rec.Code)
	}
}

// TestTwoFactor_Enable2FA_NotAuthenticated tests unauthenticated request
func TestTwoFactor_Enable2FA_NotAuthenticated(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	req := createTestRequest(t, "POST", "/2fa/enable", map[string]interface{}{
		"password": "TestPassword123!",
	})

	rec := httptest.NewRecorder()
	authService.Enable2FAHandler(rec, req)
	var resp Enable2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated, got %d", rec.Code)
	}
}

// TestTwoFactor_VerifyEnable2FA_ValidCode tests successful 2FA verification
func TestTwoFactor_VerifyEnable2FA_ValidCode(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// First enable 2FA to get a code
	enableReq := createTestRequest(t, "POST", "/2fa/enable", map[string]interface{}{
		"password": "TestPassword123!",
	})
	ctx := context.WithValue(enableReq.Context(), ctxKeyUser, user)
	enableReq = enableReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.Enable2FAHandler(rec, enableReq)
	var enableResp Enable2FAResponse
	json.NewDecoder(rec.Body).Decode(&enableResp)

	// Get the 2FA code from storage
	codes, _ := mockStore.Get2FABackupCodes(context.Background(), user.ID)
	if len(codes) == 0 {
		// Try getting a regular 2FA code instead
		t.Logf("No backup codes found yet, this is expected during enable flow")
	}

	// Fetch the code Enable2FAHandler actually stored and verify with it
	var realCode string
	mockStore.mu.Lock()
	for _, c := range mockStore.twoFactorCodes {
		if c.UserID == user.ID && c.CodeType == "enable" {
			realCode = c.Code
			break
		}
	}
	mockStore.mu.Unlock()
	if realCode == "" {
		t.Fatal("no 2FA code stored after enable")
	}
	if len(realCode) != 6 {
		t.Fatalf("2FA code length = %d, want 6", len(realCode))
	}
	for _, r := range realCode {
		if r < '0' || r > '9' {
			t.Fatalf("2FA code %q is not numeric", realCode)
		}
	}

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-enable", map[string]interface{}{
		"code": realCode,
	})
	ctx = context.WithValue(verifyReq.Context(), ctxKeyUser, user)
	verifyReq = verifyReq.WithContext(ctx)

	rec2 := httptest.NewRecorder()
	authService.VerifyEnable2FAHandler(rec2, verifyReq)
	var resp VerifyEnable2FAResponse
	json.NewDecoder(rec2.Body).Decode(&resp)

	if rec2.Code != http.StatusOK {
		t.Errorf("VerifyEnable2FAHandler() status = %d, expected %d: %s", rec2.Code, http.StatusOK, resp.Error)
	}
	if len(resp.BackupCodes) == 0 {
		t.Error("Expected backup codes in response")
	}

	// Verify 2FA is enabled
	security, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
	if !security.TwoFactorEnabled {
		t.Error("2FA should be enabled after verification")
	}
}

// TestTwoFactor_VerifyEnable2FA_InvalidCode tests invalid code rejection
func TestTwoFactor_VerifyEnable2FA_InvalidCode(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-enable", map[string]interface{}{
		"code": "000000",
	})
	ctx := context.WithValue(verifyReq.Context(), ctxKeyUser, user)
	verifyReq = verifyReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.VerifyEnable2FAHandler(rec, verifyReq)
	var resp VerifyEnable2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid code, got %d", rec.Code)
	}
}

// TestTwoFactor_VerifyEnable2FA_ExpiredCode tests expired code rejection
func TestTwoFactor_VerifyEnable2FA_ExpiredCode(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Create an expired 2FA code
	expiredCode := &TwoFactorCode{
		UserID:    user.ID,
		Code:      "111111",
		CodeType:  "enable",
		ExpiresAt: time.Now().Add(-1 * time.Minute), // Expired
		CreatedAt: time.Now().Add(-2 * time.Minute),
	}
	mockStore.Create2FACode(context.Background(), expiredCode)

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-enable", map[string]interface{}{
		"code": "111111",
	})
	ctx := context.WithValue(verifyReq.Context(), ctxKeyUser, user)
	verifyReq = verifyReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.VerifyEnable2FAHandler(rec, verifyReq)
	var resp VerifyEnable2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for expired code, got %d", rec.Code)
	}
}

// TestTwoFactor_Disable2FA_ValidFlow tests 2FA disablement
func TestTwoFactor_Disable2FA_ValidFlow(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// First enable 2FA
	security, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
	security.TwoFactorEnabled = true
	mockStore.UpdateUserSecurity(context.Background(), security)

	// Now disable it
	disableReq := createTestRequest(t, "POST", "/2fa/disable", map[string]interface{}{
		"password": "TestPassword123!",
	})
	ctx := context.WithValue(disableReq.Context(), ctxKeyUser, user)
	disableReq = disableReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.Disable2FAHandler(rec, disableReq)
	var resp Disable2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusOK {
		t.Errorf("Disable2FAHandler() status = %d, expected %d: %s", rec.Code, http.StatusOK, resp.Error)
	}

	// Verify 2FA is disabled
	updatedSecurity, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
	if updatedSecurity.TwoFactorEnabled {
		t.Error("2FA should be disabled after disablement request")
	}
}

// TestTwoFactor_Disable2FA_InvalidPassword tests wrong password
func TestTwoFactor_Disable2FA_InvalidPassword(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Enable 2FA first
	security, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
	security.TwoFactorEnabled = true
	mockStore.UpdateUserSecurity(context.Background(), security)

	disableReq := createTestRequest(t, "POST", "/2fa/disable", map[string]interface{}{
		"password": "WrongPassword!",
	})
	ctx := context.WithValue(disableReq.Context(), ctxKeyUser, user)
	disableReq = disableReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.Disable2FAHandler(rec, disableReq)
	var resp Disable2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid password, got %d", rec.Code)
	}
}

// TestTwoFactor_VerifyLogin2FA_ValidCode tests login code verification
func TestTwoFactor_VerifyLogin2FA_ValidCode(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Create a valid login 2FA code
	loginCode := &TwoFactorCode{
		UserID:    user.ID,
		Code:      "222222",
		CodeType:  "login",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	mockStore.Create2FACode(context.Background(), loginCode)

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-login", map[string]interface{}{
		"code": "222222",
	})

	rec := httptest.NewRecorder()
	authService.VerifyLogin2FAHandler(rec, verifyReq)
	var resp VerifyLogin2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusOK {
		t.Errorf("VerifyLogin2FAHandler() status = %d, expected %d: %s", rec.Code, http.StatusOK, resp.Error)
	}
	if resp.Token == "" {
		t.Error("Expected token in response after 2FA verification")
	}
	if resp.User == nil {
		t.Error("Expected user in response")
	}
}

// TestTwoFactor_VerifyLogin2FA_BackupCode tests backup code usage during login
func TestTwoFactor_VerifyLogin2FA_BackupCode(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Create a backup code
	backupCode := &TwoFactorBackupCode{
		UserID:    user.ID,
		Code:      "backup-code-long-string-12345",
		CreatedAt: time.Now(),
	}
	mockStore.Create2FABackupCode(context.Background(), backupCode)

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-login", map[string]interface{}{
		"code": "backup-code-long-string-12345",
	})

	rec := httptest.NewRecorder()
	authService.VerifyLogin2FAHandler(rec, verifyReq)
	var resp VerifyLogin2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusOK {
		t.Errorf("VerifyLogin2FAHandler() with backup code status = %d, expected %d: %s", rec.Code, http.StatusOK, resp.Error)
	}
	if resp.Token == "" {
		t.Error("Expected token after backup code verification")
	}

	// Verify backup code was marked as used
	usedCode, _ := mockStore.GetBackupCodeByCode(context.Background(), "backup-code-long-string-12345")
	if usedCode != nil && usedCode.UsedAt == nil {
		t.Error("Backup code should be marked as used after verification")
	}
}

// TestTwoFactor_VerifyLogin2FA_InvalidCode tests invalid code during login
func TestTwoFactor_VerifyLogin2FA_InvalidCode(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-login", map[string]interface{}{
		"code": "invalid-code",
	})

	rec := httptest.NewRecorder()
	authService.VerifyLogin2FAHandler(rec, verifyReq)
	var resp VerifyLogin2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid code, got %d", rec.Code)
	}
}

// TestTwoFactor_VerifyLogin2FA_ExpiredCode tests expired code during login
func TestTwoFactor_VerifyLogin2FA_ExpiredCode(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Create an expired login code
	expiredLoginCode := &TwoFactorCode{
		UserID:    user.ID,
		Code:      "333333",
		CodeType:  "login",
		ExpiresAt: time.Now().Add(-5 * time.Minute), // Expired
		CreatedAt: time.Now().Add(-10 * time.Minute),
	}
	mockStore.Create2FACode(context.Background(), expiredLoginCode)

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-login", map[string]interface{}{
		"code": "333333",
	})

	rec := httptest.NewRecorder()
	authService.VerifyLogin2FAHandler(rec, verifyReq)
	var resp VerifyLogin2FAResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for expired code, got %d", rec.Code)
	}
}

// TestTwoFactor_GetBackupCodes_ValidFlow tests backup codes retrieval
func TestTwoFactor_GetBackupCodes_ValidFlow(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Create some backup codes
	for i := 0; i < 5; i++ {
		code := &TwoFactorBackupCode{
			UserID:    user.ID,
			Code:      fmt.Sprintf("backup-%d", i),
			CreatedAt: time.Now(),
		}
		mockStore.Create2FABackupCode(context.Background(), code)
	}

	req := createTestRequest(t, "POST", "/2fa/backup-codes", map[string]interface{}{
		"password": "TestPassword123!",
	})
	ctx := context.WithValue(req.Context(), ctxKeyUser, user)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.GetBackupCodesHandler(rec, req)
	var resp GetBackupCodesResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusOK {
		t.Errorf("GetBackupCodesHandler() status = %d, expected %d: %s", rec.Code, http.StatusOK, resp.Error)
	}
	if len(resp.Codes) < 5 {
		t.Errorf("Expected at least 5 backup codes, got %d", len(resp.Codes))
	}
}

// TestTwoFactor_GetBackupCodes_InvalidPassword tests wrong password
func TestTwoFactor_GetBackupCodes_InvalidPassword(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	req := createTestRequest(t, "POST", "/2fa/backup-codes", map[string]interface{}{
		"password": "WrongPassword!",
	})
	ctx := context.WithValue(req.Context(), ctxKeyUser, user)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.GetBackupCodesHandler(rec, req)
	var resp GetBackupCodesResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GetBackupCodesHandler() status = %d, expected %d: %s", rec.Code, http.StatusUnauthorized, resp.Error)
	}
}

// TestTwoFactor_GetBackupCodes_NotAuthenticated tests unauthenticated request
func TestTwoFactor_GetBackupCodes_NotAuthenticated(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	req := createTestRequest(t, "POST", "/2fa/backup-codes", map[string]interface{}{
		"password": "TestPassword123!",
	})

	rec := httptest.NewRecorder()
	authService.GetBackupCodesHandler(rec, req)
	var resp GetBackupCodesResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated, got %d", rec.Code)
	}
}

// TestTwoFactor_RegenerateBackupCodes_ValidFlow tests backup code regeneration
func TestTwoFactor_RegenerateBackupCodes_ValidFlow(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Create initial backup codes
	oldCodes := make([]string, 3)
	for i := 0; i < 3; i++ {
		code := &TwoFactorBackupCode{
			UserID:    user.ID,
			Code:      fmt.Sprintf("old-backup-%d", i),
			CreatedAt: time.Now().Add(-1 * time.Hour),
		}
		mockStore.Create2FABackupCode(context.Background(), code)
		oldCodes[i] = code.Code
	}

	regReq := createTestRequest(t, "POST", "/2fa/regenerate-backup-codes", map[string]interface{}{
		"password": "TestPassword123!",
	})
	ctx := context.WithValue(regReq.Context(), ctxKeyUser, user)
	regReq = regReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.RegenerateBackupCodesHandler(rec, regReq)
	var resp RegenerateBackupCodesResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusOK {
		t.Errorf("RegenerateBackupCodesHandler() status = %d, expected %d: %s", rec.Code, http.StatusOK, resp.Error)
	}
	if len(resp.Codes) == 0 {
		t.Error("Expected new backup codes in response")
	}

	// Verify new codes are different from old codes
	newCodesMap := make(map[string]bool)
	for _, code := range resp.Codes {
		newCodesMap[code] = true
	}

	for _, oldCode := range oldCodes {
		if newCodesMap[oldCode] {
			t.Errorf("Old code %s should not appear in new codes", oldCode)
		}
	}
}

// TestTwoFactor_RegenerateBackupCodes_InvalidPassword tests wrong password
func TestTwoFactor_RegenerateBackupCodes_InvalidPassword(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	regReq := createTestRequest(t, "POST", "/2fa/regenerate-backup-codes", map[string]interface{}{
		"password": "WrongPassword!",
	})
	ctx := context.WithValue(regReq.Context(), ctxKeyUser, user)
	regReq = regReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.RegenerateBackupCodesHandler(rec, regReq)
	var resp RegenerateBackupCodesResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for invalid password, got %d", rec.Code)
	}
}

// TestTwoFactor_CompleteFlow tests enable → verify → use during login → disable cycle
func TestTwoFactor_CompleteFlow(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	signupUser, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)
	user, _ := mockStore.GetUserByID(context.Background(), signupUser.ID)

	// Step 1: Enable 2FA
	enableReq := createTestRequest(t, "POST", "/2fa/enable", map[string]interface{}{
		"password": "TestPassword123!",
	})
	ctx := context.WithValue(enableReq.Context(), ctxKeyUser, user)
	enableReq = enableReq.WithContext(ctx)

	rec := httptest.NewRecorder()
	authService.Enable2FAHandler(rec, enableReq)
	var enableResp Enable2FAResponse
	json.NewDecoder(rec.Body).Decode(&enableResp)
	if rec.Code != http.StatusOK {
		t.Fatalf("Enable2FAHandler failed: %s", enableResp.Error)
	}

	// Step 2: Verify 2FA with code
	verifyCode := &TwoFactorCode{
		UserID:    user.ID,
		Code:      "444444",
		CodeType:  "enable",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	mockStore.Create2FACode(context.Background(), verifyCode)

	verifyReq := createTestRequest(t, "POST", "/2fa/verify-enable", map[string]interface{}{
		"code": "444444",
	})
	ctx = context.WithValue(verifyReq.Context(), ctxKeyUser, user)
	verifyReq = verifyReq.WithContext(ctx)

	rec = httptest.NewRecorder()
	authService.VerifyEnable2FAHandler(rec, verifyReq)
	var verifyResp VerifyEnable2FAResponse
	json.NewDecoder(rec.Body).Decode(&verifyResp)
	if rec.Code != http.StatusOK {
		t.Fatalf("VerifyEnable2FAHandler failed: %s", verifyResp.Error)
	}

	// Step 3: Verify 2FA is enabled
	security, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
	if !security.TwoFactorEnabled {
		t.Error("2FA should be enabled after verification")
	}

	// Step 4: Disable 2FA
	disableReq := createTestRequest(t, "POST", "/2fa/disable", map[string]interface{}{
		"password": "TestPassword123!",
	})
	ctx = context.WithValue(disableReq.Context(), ctxKeyUser, user)
	disableReq = disableReq.WithContext(ctx)

	rec = httptest.NewRecorder()
	authService.Disable2FAHandler(rec, disableReq)
	var disableResp Disable2FAResponse
	json.NewDecoder(rec.Body).Decode(&disableResp)
	if rec.Code != http.StatusOK {
		t.Fatalf("Disable2FAHandler failed: %s", disableResp.Error)
	}

	// Step 5: Verify 2FA is disabled
	updatedSecurity, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
	if updatedSecurity.TwoFactorEnabled {
		t.Error("2FA should be disabled after disablement request")
	}

	t.Logf("Complete 2FA flow passed: enable → verify → disable")
}
