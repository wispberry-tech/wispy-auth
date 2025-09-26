package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHandlers_ErrorScenarios tests various error scenarios in handlers
func TestHandlers_ErrorScenarios(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	t.Run("signup_duplicate_user", func(t *testing.T) {
		// Create first user
		req1 := createTestRequest(t, "POST", "/signup", map[string]interface{}{
			"email":    "duplicate@example.com",
			"password": "TestPassword123",
		})
		resp1 := authService.SignUpHandler(req1)
		if resp1.StatusCode != http.StatusCreated {
			t.Fatalf("First signup should succeed: %+v", resp1)
		}

		// Try to create duplicate user
		req2 := createTestRequest(t, "POST", "/signup", map[string]interface{}{
			"email":    "duplicate@example.com",
			"password": "TestPassword456",
		})
		resp2 := authService.SignUpHandler(req2)

		if resp2.StatusCode != http.StatusConflict {
			t.Errorf("Expected 409 for duplicate user, got %d", resp2.StatusCode)
		}
		if resp2.Error == "" {
			t.Error("Expected error message for duplicate user")
		}
	})

	t.Run("signin_inactive_user", func(t *testing.T) {
		// Create user
		user, _ := mustCreateTestUserWithToken(t, authService)

		// Deactivate user
		mockStore := authService.storage.(*mockStorage)
		user.IsActive = false
		mockStore.UpdateUser(user)

		// Try to sign in
		signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
			"email":    user.Email,
			"password": "TestPassword123",
		})

		signinResp := authService.SignInHandler(signinReq)
		if signinResp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for inactive user, got %d", signinResp.StatusCode)
		}
	})

	t.Run("signin_suspended_user", func(t *testing.T) {
		// Create user
		user, _ := mustCreateTestUserWithToken(t, authService)

		// Suspend user
		mockStore := authService.storage.(*mockStorage)
		user.IsSuspended = true
		mockStore.UpdateUser(user)

		// Try to sign in
		signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
			"email":    user.Email,
			"password": "TestPassword123",
		})

		signinResp := authService.SignInHandler(signinReq)
		if signinResp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for suspended user, got %d", signinResp.StatusCode)
		}
	})

	t.Run("signin_locked_account", func(t *testing.T) {
		// Create user
		user, _ := mustCreateTestUserWithToken(t, authService)

		// Lock the account
		mockStore := authService.storage.(*mockStorage)
		lockUntil := time.Now().Add(1 * time.Hour)
		security, _ := mockStore.GetUserSecurity(user.ID)
		security.LockedUntil = &lockUntil
		mockStore.UpdateUserSecurity(security)

		// Try to sign in
		signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
			"email":    user.Email,
			"password": "TestPassword123",
		})

		signinResp := authService.SignInHandler(signinReq)
		if signinResp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for locked account, got %d", signinResp.StatusCode)
		}
		if signinResp.Error != "Account is temporarily locked" {
			t.Errorf("Expected locked account message, got: %s", signinResp.Error)
		}
	})

	t.Run("signin_failed_attempts", func(t *testing.T) {
		// Create user
		user, _ := mustCreateTestUserWithToken(t, authService)

		// Make several failed attempts
		for i := 0; i < 3; i++ {
			signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
				"email":    user.Email,
				"password": "WrongPassword",
			})

			signinResp := authService.SignInHandler(signinReq)
			if signinResp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Failed attempt %d should return 401, got %d", i+1, signinResp.StatusCode)
			}
		}

		// Check that login attempts were tracked
		mockStore := authService.storage.(*mockStorage)
		security, _ := mockStore.GetUserSecurity(user.ID)
		if security.LoginAttempts == 0 {
			t.Error("Expected login attempts to be tracked")
		}
	})

	t.Run("validate_expired_session", func(t *testing.T) {
		// Create user and session
		user, _ := mustCreateTestUserWithToken(t, authService)

		// Create an expired session manually
		expiredToken := "expired-session-token"
		expiredSession := &Session{
			Token:     expiredToken,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		}

		mockStore := authService.storage.(*mockStorage)
		mockStore.CreateSession(expiredSession)

		// Try to validate expired session
		req := httptest.NewRequest("GET", "/validate", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)

		validateResp := authService.ValidateHandler(req)
		if validateResp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for expired session, got %d", validateResp.StatusCode)
		}
		if validateResp.Error != "Invalid token" {
			t.Errorf("Expected 'Invalid token' message, got: %s", validateResp.Error)
		}
	})
}

// TestHandlers_SuccessScenarios tests successful handler scenarios
func TestHandlers_SuccessScenarios(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	t.Run("complete_signup_signin_cycle", func(t *testing.T) {
		email := "cycle@example.com"
		password := "TestPassword123"

		// Signup
		signupReq := createTestRequest(t, "POST", "/signup", map[string]interface{}{
			"email":      email,
			"password":   password,
			"first_name": "Cycle",
			"last_name":  "Test",
		})

		signupResp := authService.SignUpHandler(signupReq)
		if signupResp.StatusCode != http.StatusCreated {
			t.Fatalf("Signup failed: %+v", signupResp)
		}

		if signupResp.User.Email != email {
			t.Errorf("Expected email %s, got %s", email, signupResp.User.Email)
		}
		if signupResp.Token == "" {
			t.Error("Expected token in signup response")
		}

		// Signin
		signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
			"email":    email,
			"password": password,
		})

		signinResp := authService.SignInHandler(signinReq)
		if signinResp.StatusCode != http.StatusOK {
			t.Fatalf("Signin failed: %+v", signinResp)
		}

		if signinResp.User.Email != email {
			t.Errorf("Expected email %s, got %s", email, signinResp.User.Email)
		}
		if signinResp.Token == "" {
			t.Error("Expected token in signin response")
		}

		// Validate token
		validateReq := httptest.NewRequest("GET", "/validate", nil)
		validateReq.Header.Set("Authorization", "Bearer "+signinResp.Token)

		validateResp := authService.ValidateHandler(validateReq)
		if validateResp.StatusCode != http.StatusOK {
			t.Fatalf("Validate failed: %+v", validateResp)
		}

		if validateResp.User.Email != email {
			t.Errorf("Expected email %s, got %s", email, validateResp.User.Email)
		}

		// Logout
		logoutReq := httptest.NewRequest("POST", "/logout", nil)
		logoutReq.Header.Set("Authorization", "Bearer "+signinResp.Token)

		logoutResp := authService.LogoutHandler(logoutReq)
		if logoutResp.StatusCode != http.StatusOK {
			t.Fatalf("Logout failed: %+v", logoutResp)
		}

		// Verify token is invalid after logout
		validateReq2 := httptest.NewRequest("GET", "/validate", nil)
		validateReq2.Header.Set("Authorization", "Bearer "+signinResp.Token)

		validateResp2 := authService.ValidateHandler(validateReq2)
		if validateResp2.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 after logout, got %d", validateResp2.StatusCode)
		}
	})

	t.Run("session_management", func(t *testing.T) {
		// Create user with session
		user, token := mustCreateTestUserWithToken(t, authService)

		// Create context with user (simulating middleware)
		req := httptest.NewRequest("GET", "/sessions", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Add user to context manually for testing
		ctx := req.Context()
		ctx = context.WithValue(ctx, "user", user)
		req = req.WithContext(ctx)

		sessionsResp := authService.GetSessionsHandler(req)
		if sessionsResp.StatusCode != http.StatusOK {
			t.Errorf("GetSessions failed: %+v", sessionsResp)
		}

		if len(sessionsResp.Sessions) == 0 {
			t.Error("Expected at least one session")
		}
	})
}

// TestHandlers_InputValidation tests input validation scenarios
func TestHandlers_InputValidation(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	t.Run("signup_validation_errors", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload map[string]interface{}
			status  int
		}{
			{
				name: "empty_email",
				payload: map[string]interface{}{
					"email":    "",
					"password": "TestPassword123",
				},
				status: http.StatusBadRequest,
			},
			{
				name: "invalid_email_format",
				payload: map[string]interface{}{
					"email":    "not-an-email",
					"password": "TestPassword123",
				},
				status: http.StatusBadRequest,
			},
			{
				name: "missing_password",
				payload: map[string]interface{}{
					"email": "test@example.com",
				},
				status: http.StatusBadRequest,
			},
			{
				name: "empty_password",
				payload: map[string]interface{}{
					"email":    "test@example.com",
					"password": "",
				},
				status: http.StatusBadRequest,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := createTestRequest(t, "POST", "/signup", tc.payload)
				resp := authService.SignUpHandler(req)

				if resp.StatusCode != tc.status {
					t.Errorf("Expected status %d, got %d", tc.status, resp.StatusCode)
				}
				if resp.Error == "" {
					t.Error("Expected validation error message")
				}
			})
		}
	})

	t.Run("signin_validation_errors", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload map[string]interface{}
			status  int
		}{
			{
				name: "empty_email",
				payload: map[string]interface{}{
					"email":    "",
					"password": "TestPassword123",
				},
				status: http.StatusBadRequest,
			},
			{
				name: "invalid_email_format",
				payload: map[string]interface{}{
					"email":    "not-an-email",
					"password": "TestPassword123",
				},
				status: http.StatusBadRequest,
			},
			{
				name: "missing_password",
				payload: map[string]interface{}{
					"email": "test@example.com",
				},
				status: http.StatusBadRequest,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := createTestRequest(t, "POST", "/signin", tc.payload)
				resp := authService.SignInHandler(req)

				if resp.StatusCode != tc.status {
					t.Errorf("Expected status %d, got %d", tc.status, resp.StatusCode)
				}
				if resp.Error == "" {
					t.Error("Expected validation error message")
				}
			})
		}
	})
}

// TestHandlers_TokenExtraction tests token extraction from different sources
func TestHandlers_TokenExtraction(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	// Create user and token
	_, token := mustCreateTestUserWithToken(t, authService)

	t.Run("token_from_authorization_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp := authService.ValidateHandler(req)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for valid token in header, got %d", resp.StatusCode)
		}
	})

	t.Run("token_from_cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)
		req.AddCookie(&http.Cookie{
			Name:  "auth_token",
			Value: token,
		})

		resp := authService.ValidateHandler(req)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for valid token in cookie, got %d", resp.StatusCode)
		}
	})

	t.Run("malformed_authorization_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)
		req.Header.Set("Authorization", "InvalidFormat "+token)

		resp := authService.ValidateHandler(req)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for malformed header, got %d", resp.StatusCode)
		}
	})

	t.Run("no_token_provided", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)

		resp := authService.ValidateHandler(req)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for no token, got %d", resp.StatusCode)
		}
	})
}
