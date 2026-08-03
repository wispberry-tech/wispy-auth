package core

import (
	"context"
	"encoding/json"
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
			"password": "TestPassword123!",
		})
		rec1 := httptest.NewRecorder()
		authService.SignUpHandler(rec1, req1)
		var resp1 SignUpResponse
		json.NewDecoder(rec1.Body).Decode(&resp1)
			if rec1.Code != http.StatusCreated {
				t.Fatalf("First signup should succeed: %+v", resp1)
			}

		// Try to create duplicate user
		req2 := createTestRequest(t, "POST", "/signup", map[string]interface{}{
			"email":    "duplicate@example.com",
			"password": "TestPassword456!",
		})
		rec2 := httptest.NewRecorder()
		authService.SignUpHandler(rec2, req2)
		var resp2 SignUpResponse
		json.NewDecoder(rec2.Body).Decode(&resp2)

			if rec2.Code != http.StatusConflict {
				t.Errorf("Expected 409 for duplicate user, got %d", rec2.Code)
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
		mockStore.UpdateUser(context.Background(), user)

		// Try to sign in
		signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
			"email":    user.Email,
			"password": "TestPassword123!",
		})

		rec := httptest.NewRecorder()
		authService.SignInHandler(rec, signinReq)
		var signinResp SignInResponse
		json.NewDecoder(rec.Body).Decode(&signinResp)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for inactive user, got %d", rec.Code)
		}
	})

	t.Run("signin_suspended_user", func(t *testing.T) {
		// Create user
		user, _ := mustCreateTestUserWithToken(t, authService)

		// Suspend user
		mockStore := authService.storage.(*mockStorage)
		user.IsSuspended = true
		mockStore.UpdateUser(context.Background(), user)

		// Try to sign in
		signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
			"email":    user.Email,
			"password": "TestPassword123!",
		})

		rec := httptest.NewRecorder()
		authService.SignInHandler(rec, signinReq)
		var signinResp SignInResponse
		json.NewDecoder(rec.Body).Decode(&signinResp)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for suspended user, got %d", rec.Code)
		}
	})

	t.Run("signin_locked_account", func(t *testing.T) {
		// Create user
		user, _ := mustCreateTestUserWithToken(t, authService)

		// Lock the account
		mockStore := authService.storage.(*mockStorage)
		lockUntil := time.Now().Add(1 * time.Hour)
		security, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
		security.LockedUntil = &lockUntil
		mockStore.UpdateUserSecurity(context.Background(), security)

		// Try to sign in
		signinReq := createTestRequest(t, "POST", "/signin", map[string]interface{}{
			"email":    user.Email,
			"password": "TestPassword123!",
		})

		rec := httptest.NewRecorder()
		authService.SignInHandler(rec, signinReq)
		var signinResp SignInResponse
		json.NewDecoder(rec.Body).Decode(&signinResp)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for locked account, got %d", rec.Code)
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
				"password": "WrongPassword!",
			})

			rec := httptest.NewRecorder()
			authService.SignInHandler(rec, signinReq)
			var signinResp SignInResponse
			json.NewDecoder(rec.Body).Decode(&signinResp)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Failed attempt %d should return 401, got %d", i+1, rec.Code)
			}
		}

		// Check that login attempts were tracked
		mockStore := authService.storage.(*mockStorage)
		security, _ := mockStore.GetUserSecurity(context.Background(), user.ID)
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
		mockStore.CreateSession(context.Background(), expiredSession)

		// Try to validate expired session
		req := httptest.NewRequest("GET", "/validate", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)

		rec := httptest.NewRecorder()
		authService.ValidateHandler(rec, req)
		var validateResp ValidateResponse
		json.NewDecoder(rec.Body).Decode(&validateResp)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for expired session, got %d", rec.Code)
		}
		if validateResp.Error != "Invalid or expired session" {
			t.Errorf("Expected 'Invalid or expired session' message, got: %s", validateResp.Error)
		}
	})
}

// TestHandlers_SuccessScenarios tests successful handler scenarios
func TestHandlers_SuccessScenarios(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	t.Run("complete_signup_signin_cycle", func(t *testing.T) {
		email := "cycle@example.com"
		password := "TestPassword123!"

		// Signup
		signupReq := createTestRequest(t, "POST", "/signup", map[string]interface{}{
			"email":      email,
			"password":   password,
			"first_name": "Cycle",
			"last_name":  "Test",
		})

		rec := httptest.NewRecorder()
		authService.SignUpHandler(rec, signupReq)
		var signupResp SignUpResponse
		json.NewDecoder(rec.Body).Decode(&signupResp)
		if rec.Code != http.StatusCreated {
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

		rec2 := httptest.NewRecorder()
		authService.SignInHandler(rec2, signinReq)
		var signinResp SignInResponse
		json.NewDecoder(rec2.Body).Decode(&signinResp)
		if rec2.Code != http.StatusOK {
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
		ctx := context.WithValue(validateReq.Context(), "user", signinResp.User)
		validateReq = validateReq.WithContext(ctx)

		rec3 := httptest.NewRecorder()
		authService.ValidateHandler(rec3, validateReq)
		var validateResp ValidateResponse
		json.NewDecoder(rec3.Body).Decode(&validateResp)
		if rec3.Code != http.StatusOK {
			t.Fatalf("Validate failed: %+v", validateResp)
		}

		if validateResp.User.Email != email {
			t.Errorf("Expected email %s, got %s", email, validateResp.User.Email)
		}

		// Logout
		mockStore := authService.storage.(*mockStorage)
		session, _ := mockStore.GetSession(context.Background(), signinResp.Token)
		logoutReq := httptest.NewRequest("POST", "/logout", nil)
		logoutReq.Header.Set("Authorization", "Bearer "+signinResp.Token)
		ctx2 := context.WithValue(logoutReq.Context(), "user", signinResp.User)
		ctx2 = context.WithValue(ctx2, "session", session)
		logoutReq = logoutReq.WithContext(ctx2)

		rec4 := httptest.NewRecorder()
		authService.LogoutHandler(rec4, logoutReq)
		var logoutResp LogoutResponse
		json.NewDecoder(rec4.Body).Decode(&logoutResp)
		if rec4.Code != http.StatusOK {
			t.Fatalf("Logout failed: %+v", logoutResp)
		}

		// Verify session is deleted after logout
		deletedSession, _ := mockStore.GetSession(context.Background(), signinResp.Token)
		if deletedSession != nil {
			t.Error("Session should be deleted after logout")
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

		rec := httptest.NewRecorder()
		authService.GetSessionsHandler(rec, req)
		var sessionsResp GetSessionsResponse
		json.NewDecoder(rec.Body).Decode(&sessionsResp)
		if rec.Code != http.StatusOK {
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
					"password": "TestPassword123!",
				},
				status: http.StatusBadRequest,
			},
			{
				name: "invalid_email_format",
				payload: map[string]interface{}{
					"email":    "not-an-email",
					"password": "TestPassword123!",
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
				rec := httptest.NewRecorder()
				authService.SignUpHandler(rec, req)
				var resp SignUpResponse
				json.NewDecoder(rec.Body).Decode(&resp)

				if rec.Code != tc.status {
					t.Errorf("Expected status %d, got %d", tc.status, rec.Code)
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
					"password": "TestPassword123!",
				},
				status: http.StatusBadRequest,
			},
			{
				name: "invalid_email_format",
				payload: map[string]interface{}{
					"email":    "not-an-email",
					"password": "TestPassword123!",
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
				rec := httptest.NewRecorder()
				authService.SignInHandler(rec, req)
				var resp SignInResponse
				json.NewDecoder(rec.Body).Decode(&resp)

				if rec.Code != tc.status {
					t.Errorf("Expected status %d, got %d", tc.status, rec.Code)
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
	user, token := mustCreateTestUserWithToken(t, authService)

	t.Run("token_from_authorization_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		ctx := context.WithValue(req.Context(), "user", user)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		authService.ValidateHandler(rec, req)
		var resp ValidateResponse
		json.NewDecoder(rec.Body).Decode(&resp)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for valid token in header, got %d", rec.Code)
		}
	})

	t.Run("token_from_cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)
		req.AddCookie(&http.Cookie{
			Name:  "auth_token",
			Value: token,
		})
		ctx := context.WithValue(req.Context(), "user", user)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		authService.ValidateHandler(rec, req)
		var resp ValidateResponse
		json.NewDecoder(rec.Body).Decode(&resp)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for valid token in cookie, got %d", rec.Code)
		}
	})

	t.Run("malformed_authorization_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)
		req.Header.Set("Authorization", "InvalidFormat "+token)

		rec := httptest.NewRecorder()
		authService.ValidateHandler(rec, req)
		var resp ValidateResponse
		json.NewDecoder(rec.Body).Decode(&resp)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for malformed header, got %d", rec.Code)
		}
	})

	t.Run("no_token_provided", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/validate", nil)

		rec := httptest.NewRecorder()
		authService.ValidateHandler(rec, req)
		var resp ValidateResponse
		json.NewDecoder(rec.Body).Decode(&resp)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 for no token, got %d", rec.Code)
		}
	})
}
