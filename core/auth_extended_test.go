package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAuthService_OAuthInitHandler tests OAuth flow initialization
func TestAuthService_OAuthInitHandler(t *testing.T) {
	authService := mustCreateTestAuthServiceWithOAuth(t)
	defer authService.Close()

	tests := []struct {
		name           string
		provider       string
		expectedStatus int
		checkResponse  func(t *testing.T, response OAuthResponse)
	}{
		{
			name:           "valid_google_provider",
			provider:       "google",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response OAuthResponse) {
				if response.URL == "" {
					t.Error("Expected OAuth URL in response")
				}
				if !strings.Contains(response.URL, "accounts.google.com") {
					t.Errorf("Expected Google OAuth URL, got %s", response.URL)
				}
			},
		},
		{
			name:           "valid_github_provider",
			provider:       "github",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response OAuthResponse) {
				if response.URL == "" {
					t.Error("Expected OAuth URL in response")
				}
				if !strings.Contains(response.URL, "github.com") {
					t.Errorf("Expected GitHub OAuth URL, got %s", response.URL)
				}
			},
		},
		{
			name:           "invalid_provider",
			provider:       "invalid",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response OAuthResponse) {
				if response.Error == "" {
					t.Error("Expected error message for invalid provider")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/auth/"+tt.provider, nil)
			response := authService.OAuthInitHandler(req, tt.provider)

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("OAuthInitHandler() status = %d, expected %d", response.StatusCode, tt.expectedStatus)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}
		})
	}
}

// TestAuthService_OAuthCallbackHandler tests OAuth callback processing
func TestAuthService_OAuthCallbackHandler(t *testing.T) {
	authService := mustCreateTestAuthServiceWithOAuth(t)
	defer authService.Close()

	// Create a mock OAuth state first
	mockStore := authService.storage.(*mockStorage)
	oauthState := &OAuthState{
		State:       "test-state-123",
		CSRF:        "test-csrf-456",
		Provider:    "google",
		RedirectURL: "http://localhost/callback",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	mockStore.StoreOAuthState(oauthState)

	tests := []struct {
		name           string
		provider       string
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, response OAuthResponse)
	}{
		{
			name:     "missing_code",
			provider: "google",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/auth/google/callback", nil)
				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response OAuthResponse) {
				if response.Error == "" {
					t.Error("Expected error message for missing code")
				}
			},
		},
		{
			name:     "missing_state",
			provider: "google",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/auth/google/callback?code=test-code", nil)
				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response OAuthResponse) {
				if response.Error == "" {
					t.Error("Expected error message for missing state")
				}
			},
		},
		{
			name:     "invalid_state",
			provider: "google",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/auth/google/callback?code=test-code&state=invalid-state", nil)
				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response OAuthResponse) {
				if response.Error == "" {
					t.Error("Expected error message for invalid state")
				}
			},
		},
		{
			name:     "invalid_provider",
			provider: "invalid",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/auth/invalid/callback?code=test-code&state=test-state-123", nil)
				return req
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response OAuthResponse) {
				if response.Error == "" {
					t.Error("Expected error message for invalid provider")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			response := authService.OAuthCallbackHandler(req, tt.provider)

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("OAuthCallbackHandler() status = %d, expected %d", response.StatusCode, tt.expectedStatus)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}
		})
	}
}

// TestSecurityConfig_EdgeCases tests edge cases in security configuration
func TestSecurityConfig_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		config SecurityConfig
		valid  bool
	}{
		{
			name: "zero_values",
			config: SecurityConfig{
				PasswordMinLength: 0,
				MaxLoginAttempts:  0,
				LockoutDuration:   0,
				SessionLifetime:   0,
			},
			valid: true, // Should use defaults
		},
		{
			name: "negative_values",
			config: SecurityConfig{
				PasswordMinLength: -1,
				MaxLoginAttempts:  -1,
				LockoutDuration:   -1 * time.Hour,
				SessionLifetime:   -1 * time.Hour,
			},
			valid: true, // Should use defaults or handle gracefully
		},
		{
			name: "extreme_values",
			config: SecurityConfig{
				PasswordMinLength: 1000,
				MaxLoginAttempts:  1000,
				LockoutDuration:   24 * time.Hour,
				SessionLifetime:   365 * 24 * time.Hour,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Storage:        mustCreateTestStorage(t),
				SecurityConfig: tt.config,
			}

			authService, err := NewAuthService(config)
			if !tt.valid && err == nil {
				t.Error("Expected error for invalid config")
			} else if tt.valid && err != nil {
				t.Errorf("Unexpected error for valid config: %v", err)
			}

			if authService != nil {
				authService.Close()
			}
		})
	}
}

// TestAuthService_ConcurrentAccess tests concurrent access to auth service
func TestAuthService_ConcurrentAccess(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	// Test concurrent signup requests
	t.Run("concurrent_signups", func(t *testing.T) {
		const numUsers = 10
		done := make(chan bool, numUsers)

		for i := 0; i < numUsers; i++ {
			go func(userNum int) {
				defer func() { done <- true }()

				req := createTestRequest(t, "POST", "/signup", map[string]interface{}{
					"email":      fmt.Sprintf("user%d@example.com", userNum),
					"password":   "TestPassword123",
					"first_name": fmt.Sprintf("User%d", userNum),
				})

				response := authService.SignUpHandler(req)
				if response.StatusCode != http.StatusCreated {
					t.Errorf("Concurrent signup failed for user %d: %+v", userNum, response)
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numUsers; i++ {
			<-done
		}
	})

	// Test concurrent signin requests
	t.Run("concurrent_signins", func(t *testing.T) {
		// First create a user
		signupReq := createTestRequest(t, "POST", "/signup", map[string]interface{}{
			"email":    "concurrent@example.com",
			"password": "TestPassword123",
		})
		signupResp := authService.SignUpHandler(signupReq)
		if signupResp.StatusCode != http.StatusCreated {
			t.Fatalf("Failed to create user for concurrent test: %+v", signupResp)
		}

		const numSignins = 5
		done := make(chan bool, numSignins)

		for i := 0; i < numSignins; i++ {
			go func(reqNum int) {
				defer func() { done <- true }()

				req := createTestRequest(t, "POST", "/signin", map[string]interface{}{
					"email":    "concurrent@example.com",
					"password": "TestPassword123",
				})

				response := authService.SignInHandler(req)
				if response.StatusCode != http.StatusOK {
					t.Errorf("Concurrent signin failed for request %d: %+v", reqNum, response)
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numSignins; i++ {
			<-done
		}
	})
}

// TestPasswordSecurity tests password security validation
func TestPasswordSecurity(t *testing.T) {
	tests := []struct {
		name     string
		password string
		config   SecurityConfig
		valid    bool
	}{
		{
			name:     "meets_all_requirements",
			password: "TestPassword123!",
			config: SecurityConfig{
				PasswordMinLength:      8,
				PasswordRequireUpper:   true,
				PasswordRequireLower:   true,
				PasswordRequireNumber:  true,
				PasswordRequireSpecial: true,
			},
			valid: true,
		},
		{
			name:     "too_short",
			password: "Test1!",
			config: SecurityConfig{
				PasswordMinLength: 8,
			},
			valid: false,
		},
		{
			name:     "missing_upper",
			password: "testpassword123!",
			config: SecurityConfig{
				PasswordMinLength:    8,
				PasswordRequireUpper: true,
			},
			valid: false,
		},
		{
			name:     "missing_lower",
			password: "TESTPASSWORD123!",
			config: SecurityConfig{
				PasswordMinLength:    8,
				PasswordRequireLower: true,
			},
			valid: false,
		},
		{
			name:     "missing_number",
			password: "TestPassword!",
			config: SecurityConfig{
				PasswordMinLength:     8,
				PasswordRequireNumber: true,
			},
			valid: false,
		},
		{
			name:     "missing_special",
			password: "TestPassword123",
			config: SecurityConfig{
				PasswordMinLength:      8,
				PasswordRequireSpecial: true,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePasswordStrength(tt.password, tt.config)
			if tt.valid && err != nil {
				t.Errorf("Expected password to be valid, got error: %v", err)
			} else if !tt.valid && err == nil {
				t.Error("Expected password to be invalid, but got no error")
			}
		})
	}
}

// TestSessionManagement tests session-related functionality
func TestSessionManagement(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	// Create user and session
	user, _ := mustCreateTestUserWithToken(t, authService)
	mockStore := authService.storage.(*mockStorage)

	t.Run("session_cleanup", func(t *testing.T) {
		// Create an expired session
		expiredToken := "expired-token-123"
		expiredSession := &Session{
			Token:     expiredToken,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		}
		mockStore.CreateSession(expiredSession)

		// Try to validate expired session
		req := httptest.NewRequest("GET", "/validate", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		response := authService.ValidateHandler(req)

		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 for expired session, got %d", response.StatusCode)
		}
	})

	t.Run("multiple_sessions", func(t *testing.T) {
		// Create multiple sessions for same user
		for i := 0; i < 3; i++ {
			sessionToken := fmt.Sprintf("session-token-%d", i)
			session := &Session{
				Token:     sessionToken,
				UserID:    user.ID,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}
			mockStore.CreateSession(session)
		}

		// Get user sessions
		sessions, err := mockStore.GetUserSessions(user.ID)
		if err != nil {
			t.Fatalf("Failed to get user sessions: %v", err)
		}

		if len(sessions) < 3 {
			t.Errorf("Expected at least 3 sessions, got %d", len(sessions))
		}
	})
}

// mustCreateTestAuthServiceWithOAuth creates an AuthService with OAuth providers for testing
func mustCreateTestAuthServiceWithOAuth(t *testing.T) *AuthService {
	t.Helper()
	config := Config{
		Storage:        mustCreateTestStorage(t),
		SecurityConfig: DefaultSecurityConfig(),
		OAuthProviders: map[string]OAuthProviderConfig{
			"google": NewGoogleOAuthProvider("test-google-id", "test-google-secret", "http://localhost/auth/google/callback"),
			"github": NewGitHubOAuthProvider("test-github-id", "test-github-secret", "http://localhost/auth/github/callback"),
		},
	}

	authService, err := NewAuthService(config)
	if err != nil {
		t.Fatalf("Failed to create test AuthService with OAuth: %v", err)
	}

	return authService
}
