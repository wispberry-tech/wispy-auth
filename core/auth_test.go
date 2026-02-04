package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAuthService_NewAuthService tests the AuthService constructor
func TestAuthService_NewAuthService(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_config_with_defaults",
			config: Config{
				Storage: mustCreateTestStorage(t),
			},
			wantErr: false,
		},
		{
			name: "valid_config_with_custom_security",
			config: Config{
				Storage: mustCreateTestStorage(t),
				SecurityConfig: SecurityConfig{
					PasswordMinLength: 12,
					MaxLoginAttempts:  3,
					LockoutDuration:   30 * time.Minute,
					SessionLifetime:   2 * time.Hour,
					RequireTwoFactor:  true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid_config_with_oauth_providers",
			config: Config{
				Storage: mustCreateTestStorage(t),
				OAuthProviders: map[string]OAuthProviderConfig{
					"google": NewGoogleOAuthProvider("test-id", "test-secret", "http://localhost/callback"),
					"github": NewGitHubOAuthProvider("test-id", "test-secret", "http://localhost/callback"),
				},
			},
			wantErr: false,
		},
		{
			name: "nil_storage",
			config: Config{
				Storage: nil,
			},
			wantErr: true,
			errMsg:  "storage is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, err := NewAuthService(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewAuthService() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("NewAuthService() error = %v, expected to contain %v", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("NewAuthService() unexpected error = %v", err)
				return
			}

			if authService == nil {
				t.Error("NewAuthService() returned nil service")
				return
			}

			// Verify service properties
			if authService.storage == nil {
				t.Error("AuthService.storage is nil")
			}

			if authService.validator == nil {
				t.Error("AuthService.validator is nil")
			}

			// Test that we can close the service
			if err := authService.Close(); err != nil {
				t.Errorf("AuthService.Close() error = %v", err)
			}
		})
	}
}

// TestAuthService_SignUpHandler tests user registration
func TestAuthService_SignUpHandler(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		checkResponse  func(t *testing.T, response SignUpResponse)
	}{
		{
			name: "valid_signup",
			requestBody: map[string]interface{}{
				"email":      "test@example.com",
				"password":   "TestPassword123!",
				"first_name": "John",
				"last_name":  "Doe",
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, response SignUpResponse) {
				if response.User == nil {
					t.Error("Expected user in response")
					return
				}
				if response.User.Email != "test@example.com" {
					t.Errorf("Expected email test@example.com, got %s", response.User.Email)
				}
				if response.User.FirstName != "John" {
					t.Errorf("Expected first name John, got %s", response.User.FirstName)
				}
				if response.Token == "" {
					t.Error("Expected token in response")
				}
			},
		},
		{
			name: "invalid_email",
			requestBody: map[string]interface{}{
				"email":    "invalid-email",
				"password": "TestPassword123!",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response SignUpResponse) {
				if response.Error == "" {
					t.Error("Expected error message for invalid email")
				}
			},
		},
		{
			name: "weak_password",
			requestBody: map[string]interface{}{
				"email":    "test2@example.com",
				"password": "weak",
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response SignUpResponse) {
				if response.Error == "" {
					t.Error("Expected error message for weak password")
				}
			},
		},
		{
			name: "missing_required_fields",
			requestBody: map[string]interface{}{
				"email": "test3@example.com",
				// missing password
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response SignUpResponse) {
				if response.Error == "" {
					t.Error("Expected error message for missing fields")
				}
			},
		},
		{
			name:           "invalid_json",
			requestBody:    "invalid-json",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response SignUpResponse) {
				if response.Error == "" {
					t.Error("Expected error message for invalid JSON")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createTestRequest(t, "POST", "/signup", tt.requestBody)
			response := authService.SignUpHandler(req)

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("SignUpHandler() status = %d, expected %d", response.StatusCode, tt.expectedStatus)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}
		})
	}
}

// TestAuthService_SignInHandler tests user authentication
func TestAuthService_SignInHandler(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	// First create a user to authenticate
	signupReq := createTestRequest(t, "POST", "/signup", map[string]interface{}{
		"email":      "signin@example.com",
		"password":   "TestPassword123!",
		"first_name": "Test",
		"last_name":  "User",
	})
	signupResp := authService.SignUpHandler(signupReq)
	if signupResp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create test user: %+v", signupResp)
	}

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		checkResponse  func(t *testing.T, response SignInResponse)
	}{
		{
			name: "valid_signin",
			requestBody: map[string]interface{}{
				"email":    "signin@example.com",
				"password": "TestPassword123!",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response SignInResponse) {
				if response.User == nil {
					t.Error("Expected user in response")
					return
				}
				if response.User.Email != "signin@example.com" {
					t.Errorf("Expected email signin@example.com, got %s", response.User.Email)
				}
				if response.Token == "" {
					t.Error("Expected token in response")
				}
			},
		},
		{
			name: "invalid_credentials",
			requestBody: map[string]interface{}{
				"email":    "signin@example.com",
				"password": "WrongPassword!",
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, response SignInResponse) {
				if response.Error == "" {
					t.Error("Expected error message for invalid credentials")
				}
				if response.User != nil {
					t.Error("Should not return user for invalid credentials")
				}
			},
		},
		{
			name: "nonexistent_user",
			requestBody: map[string]interface{}{
				"email":    "nonexistent@example.com",
				"password": "TestPassword123!",
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, response SignInResponse) {
				if response.Error == "" {
					t.Error("Expected error message for nonexistent user")
				}
			},
		},
		{
			name: "missing_credentials",
			requestBody: map[string]interface{}{
				"email": "signin@example.com",
				// missing password
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response SignInResponse) {
				if response.Error == "" {
					t.Error("Expected error message for missing credentials")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createTestRequest(t, "POST", "/signin", tt.requestBody)
			response := authService.SignInHandler(req)

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("SignInHandler() status = %d, expected %d", response.StatusCode, tt.expectedStatus)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}
		})
	}
}

// TestAuthService_ValidateHandler tests token validation
func TestAuthService_ValidateHandler(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	// Create a user and get their token
	user, token := mustCreateTestUserWithToken(t, authService)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, response ValidateResponse)
	}{
		{
			name: "valid_token_in_header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/validate", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response ValidateResponse) {
				if response.User == nil {
					t.Error("Expected user in response")
					return
				}
				if response.User.ID != user.ID {
					t.Errorf("Expected user ID %d, got %d", user.ID, response.User.ID)
				}
			},
		},
		{
			name: "valid_token_in_cookie",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/validate", nil)
				req.AddCookie(&http.Cookie{
					Name:  "auth_token",
					Value: token,
				})
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response ValidateResponse) {
				if response.User == nil {
					t.Error("Expected user in response")
					return
				}
				if response.User.ID != user.ID {
					t.Errorf("Expected user ID %d, got %d", user.ID, response.User.ID)
				}
			},
		},
		{
			name: "invalid_token",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/validate", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, response ValidateResponse) {
				if response.Error == "" {
					t.Error("Expected error message for invalid token")
				}
			},
		},
		{
			name: "missing_token",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/validate", nil)
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, response ValidateResponse) {
				if response.Error == "" {
					t.Error("Expected error message for missing token")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			response := authService.ValidateHandler(req)

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("ValidateHandler() status = %d, expected %d", response.StatusCode, tt.expectedStatus)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}
		})
	}
}

// TestAuthService_LogoutHandler tests session termination
func TestAuthService_LogoutHandler(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	// Create a user and get their token
	_, token := mustCreateTestUserWithToken(t, authService)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, response LogoutResponse)
	}{
		{
			name: "valid_logout",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/logout", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response LogoutResponse) {
				if response.Message == "" {
					t.Error("Expected success message")
				}
			},
		},
		{
			name: "logout_without_token",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("POST", "/logout", nil)
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response LogoutResponse) {
				if response.Error == "" {
					t.Error("Expected error message for missing token")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			response := authService.LogoutHandler(req)

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("LogoutHandler() status = %d, expected %d", response.StatusCode, tt.expectedStatus)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}

			// If logout was successful, token should be invalid
			if response.StatusCode == http.StatusOK {
				validateReq := httptest.NewRequest("GET", "/validate", nil)
				validateReq.Header.Set("Authorization", "Bearer "+token)
				validateResp := authService.ValidateHandler(validateReq)
				if validateResp.StatusCode != http.StatusUnauthorized {
					t.Error("Token should be invalid after logout")
				}
			}
		})
	}
}

// TestAuthService_GetSessionsHandler tests session listing
func TestAuthService_GetSessionsHandler(t *testing.T) {
	authService := mustCreateTestAuthService(t)
	defer authService.Close()

	// Create a user and get their token
	user, token := mustCreateTestUserWithToken(t, authService)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, response SessionsResponse)
	}{
		{
			name: "valid_request",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/sessions", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				// Add user to context (normally done by middleware)
				ctx := context.WithValue(req.Context(), "user", user)
				return req.WithContext(ctx)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response SessionsResponse) {
				if len(response.Sessions) == 0 {
					t.Error("Expected at least one session")
				}
			},
		},
		{
			name: "unauthorized_request",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/sessions", nil)
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, response SessionsResponse) {
				if response.Error == "" {
					t.Error("Expected error message for unauthorized request")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			response := authService.GetSessionsHandler(req)

			if response.StatusCode != tt.expectedStatus {
				t.Errorf("GetSessionsHandler() status = %d, expected %d", response.StatusCode, tt.expectedStatus)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, response)
			}
		})
	}
}

// TestGetUserFromContext tests context user extraction
func TestGetUserFromContext(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *http.Request
		expected *User
	}{
		{
			name: "user_exists_in_context",
			setup: func() *http.Request {
				user := &User{
					ID:    1,
					Email: "test@example.com",
				}
				req := httptest.NewRequest("GET", "/", nil)
				ctx := context.WithValue(req.Context(), "user", user)
				return req.WithContext(ctx)
			},
			expected: &User{
				ID:    1,
				Email: "test@example.com",
			},
		},
		{
			name: "user_not_in_context",
			setup: func() *http.Request {
				return httptest.NewRequest("GET", "/", nil)
			},
			expected: nil,
		},
		{
			name: "wrong_type_in_context",
			setup: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				ctx := context.WithValue(req.Context(), "user", "not-a-user")
				return req.WithContext(ctx)
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setup()
			result := GetUserFromContext(req)

			if tt.expected == nil && result != nil {
				t.Errorf("Expected nil, got %+v", result)
			} else if tt.expected != nil && result == nil {
				t.Errorf("Expected %+v, got nil", tt.expected)
			} else if tt.expected != nil && result != nil {
				if result.ID != tt.expected.ID || result.Email != tt.expected.Email {
					t.Errorf("Expected %+v, got %+v", tt.expected, result)
				}
			}
		})
	}
}

// TestMustGetUserFromContext tests context user extraction with panic
func TestMustGetUserFromContext(t *testing.T) {
	t.Run("user_exists", func(t *testing.T) {
		user := &User{ID: 1, Email: "test@example.com"}
		req := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), "user", user)
		req = req.WithContext(ctx)

		result := MustGetUserFromContext(req)
		if result.ID != user.ID {
			t.Errorf("Expected user ID %d, got %d", user.ID, result.ID)
		}
	})

	t.Run("user_not_exists_panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic but none occurred")
			}
		}()

		req := httptest.NewRequest("GET", "/", nil)
		MustGetUserFromContext(req)
	})
}

// TestDefaultSecurityConfig tests default security configuration
func TestDefaultSecurityConfig(t *testing.T) {
	config := DefaultSecurityConfig()

	// Test that all required fields have reasonable defaults
	if config.PasswordMinLength < 8 {
		t.Errorf("PasswordMinLength should be at least 8, got %d", config.PasswordMinLength)
	}

	if config.MaxLoginAttempts < 1 {
		t.Errorf("MaxLoginAttempts should be positive, got %d", config.MaxLoginAttempts)
	}

	if config.LockoutDuration < time.Minute {
		t.Errorf("LockoutDuration should be at least 1 minute, got %v", config.LockoutDuration)
	}

	if config.SessionLifetime < time.Hour {
		t.Errorf("SessionLifetime should be at least 1 hour, got %v", config.SessionLifetime)
	}

	if config.TwoFactorCodeExpiry < time.Minute {
		t.Errorf("TwoFactorCodeExpiry should be at least 1 minute, got %v", config.TwoFactorCodeExpiry)
	}
}

// TestOAuthProviderConfigurations tests OAuth provider helper functions
func TestOAuthProviderConfigurations(t *testing.T) {
	t.Run("google_provider", func(t *testing.T) {
		config := NewGoogleOAuthProvider("test-id", "test-secret", "http://localhost/callback")

		if config.ClientID != "test-id" {
			t.Errorf("Expected ClientID test-id, got %s", config.ClientID)
		}
		if config.ClientSecret != "test-secret" {
			t.Errorf("Expected ClientSecret test-secret, got %s", config.ClientSecret)
		}
		if config.RedirectURL != "http://localhost/callback" {
			t.Errorf("Expected RedirectURL http://localhost/callback, got %s", config.RedirectURL)
		}
		if len(config.Scopes) == 0 {
			t.Error("Expected scopes to be set")
		}
	})

	t.Run("github_provider", func(t *testing.T) {
		config := NewGitHubOAuthProvider("test-id", "test-secret", "http://localhost/callback")

		if config.ClientID != "test-id" {
			t.Errorf("Expected ClientID test-id, got %s", config.ClientID)
		}
		if len(config.Scopes) == 0 {
			t.Error("Expected scopes to be set")
		}
	})

	t.Run("discord_provider", func(t *testing.T) {
		config := NewDiscordOAuthProvider("test-id", "test-secret", "http://localhost/callback")

		if config.ClientID != "test-id" {
			t.Errorf("Expected ClientID test-id, got %s", config.ClientID)
		}
		if config.AuthURL != DiscordAuthURL {
			t.Errorf("Expected AuthURL %s, got %s", DiscordAuthURL, config.AuthURL)
		}
		if config.TokenURL != DiscordTokenURL {
			t.Errorf("Expected TokenURL %s, got %s", DiscordTokenURL, config.TokenURL)
		}
	})

	t.Run("custom_provider", func(t *testing.T) {
		scopes := []string{"read", "write"}
		config := NewCustomOAuthProvider(
			"test-id",
			"test-secret",
			"http://localhost/callback",
			"https://example.com/auth",
			"https://example.com/token",
			scopes,
		)

		if config.AuthURL != "https://example.com/auth" {
			t.Errorf("Expected AuthURL https://example.com/auth, got %s", config.AuthURL)
		}
		if config.TokenURL != "https://example.com/token" {
			t.Errorf("Expected TokenURL https://example.com/token, got %s", config.TokenURL)
		}
		if len(config.Scopes) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(config.Scopes))
		}
	})
}

// Helper functions for tests

// mockStorage implements the Storage interface for testing
type mockStorage struct {
	mu                  sync.RWMutex
	users               map[string]*User
	userSecurity        map[uint]*UserSecurity
	sessions            map[string]*Session
	securityEvents      []*SecurityEvent
	oauthStates         map[string]*OAuthState
	passwordResetTokens map[string]*PasswordResetToken
	nextUserID          uint
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		users:               make(map[string]*User),
		userSecurity:        make(map[uint]*UserSecurity),
		sessions:            make(map[string]*Session),
		securityEvents:      make([]*SecurityEvent, 0),
		oauthStates:         make(map[string]*OAuthState),
		passwordResetTokens: make(map[string]*PasswordResetToken),
		nextUserID:          1,
	}
}

func (m *mockStorage) CreateUser(user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user.ID = m.nextUserID
	m.nextUserID++
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	// Generate UUID if not set
	if user.UUID == "" {
		token, _ := generateSecureToken(16)
		user.UUID = token
	}
	// Create a copy to avoid issues when handlers modify the original
	userCopy := *user
	m.users[user.Email+":"+user.Provider] = &userCopy
	return nil
}

func (m *mockStorage) GetUserByEmail(email, provider string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := email + ":" + provider
	if user, exists := m.users[key]; exists {
		// Return a copy to avoid race conditions when handlers modify the user
		userCopy := *user
		return &userCopy, nil
	}
	return nil, nil // Return nil when user not found, not an error
}

func (m *mockStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for key, user := range m.users {
		if strings.HasPrefix(key, email+":") {
			// Return a copy to avoid race conditions when handlers modify the user
			userCopy := *user
			return &userCopy, nil
		}
	}
	return nil, nil // Return nil when user not found, not an error
}

func (m *mockStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, user := range m.users {
		if user.Provider == provider && user.ProviderID == providerID {
			// Return a copy to avoid race conditions when handlers modify the user
			userCopy := *user
			return &userCopy, nil
		}
	}
	return nil, nil // Return nil when user not found, not an error
}

func (m *mockStorage) GetUserByID(id uint) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, user := range m.users {
		if user.ID == id {
			// Return a copy to avoid race conditions when handlers modify the user
			userCopy := *user
			return &userCopy, nil
		}
	}
	return nil, nil // Return nil when user not found, not an error
}

func (m *mockStorage) GetUserByUUID(uuid string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, user := range m.users {
		if user.UUID == uuid {
			// Return a copy to avoid race conditions when handlers modify the user
			userCopy := *user
			return &userCopy, nil
		}
	}
	return nil, nil // Return nil when user not found, not an error
}

func (m *mockStorage) UpdateUser(user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user.UpdatedAt = time.Now()
	// Update in all relevant keys
	for key, existingUser := range m.users {
		if existingUser.ID == user.ID {
			m.users[key] = user
		}
	}
	return nil
}

func (m *mockStorage) CreateUserSecurity(security *UserSecurity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security.CreatedAt = time.Now()
	security.UpdatedAt = time.Now()
	m.userSecurity[security.UserID] = security
	return nil
}

func (m *mockStorage) GetUserSecurity(userID uint) (*UserSecurity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if security, exists := m.userSecurity[userID]; exists {
		// Return a copy to avoid race conditions when handlers modify the security record
		securityCopy := *security
		return &securityCopy, nil
	}
	return nil, nil // Return nil when security record not found, not an error
}

func (m *mockStorage) UpdateUserSecurity(security *UserSecurity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	security.UpdatedAt = time.Now()
	m.userSecurity[security.UserID] = security
	return nil
}

func (m *mockStorage) IncrementLoginAttempts(userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if security, exists := m.userSecurity[userID]; exists {
		security.LoginAttempts++
		security.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStorage) ResetLoginAttempts(userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if security, exists := m.userSecurity[userID]; exists {
		security.LoginAttempts = 0
		security.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStorage) SetUserLocked(userID uint, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if security, exists := m.userSecurity[userID]; exists {
		security.LockedUntil = &until
		security.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStorage) UpdateLastLogin(userID uint, ipAddress *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if security, exists := m.userSecurity[userID]; exists {
		now := time.Now()
		security.LastLoginAt = &now
		security.LastLoginIP = ipAddress
		security.UpdatedAt = time.Now()
	}
	return nil
}

func (m *mockStorage) CreateSession(session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session.CreatedAt = time.Now()
	session.LastAccessedAt = time.Now()
	m.sessions[session.Token] = session
	return nil
}

func (m *mockStorage) GetSession(token string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if session, exists := m.sessions[token]; exists {
		// Check if session is expired
		if session.ExpiresAt.Before(time.Now()) {
			// Note: We can't delete here because we're under RLock
			// The session will be cleaned up by CleanupExpiredSessions
			return nil, nil
		}
		return session, nil
	}
	return nil, nil // Return nil when session not found, not an error
}

func (m *mockStorage) GetUserSessions(userID uint) ([]*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sessions []*Session
	for _, session := range m.sessions {
		if session.UserID == userID && session.ExpiresAt.After(time.Now()) {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (m *mockStorage) DeleteSession(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, token)
	return nil
}

func (m *mockStorage) DeleteUserSessions(userID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for token, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, token)
		}
	}
	return nil
}

func (m *mockStorage) CleanupExpiredSessions() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for token, session := range m.sessions {
		if session.ExpiresAt.Before(now) {
			delete(m.sessions, token)
		}
	}
	return nil
}

func (m *mockStorage) CreateSecurityEvent(event *SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	event.CreatedAt = time.Now()
	m.securityEvents = append(m.securityEvents, event)
	return nil
}

func (m *mockStorage) GetSecurityEvents(userID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var events []*SecurityEvent
	for _, event := range m.securityEvents {
		if userID != nil && (event.UserID == nil || *event.UserID != *userID) {
			continue
		}
		if eventType != "" && event.EventType != eventType {
			continue
		}
		events = append(events, event)
	}

	// Apply pagination
	start := offset
	if start >= len(events) {
		return []*SecurityEvent{}, nil
	}

	end := start + limit
	if end > len(events) {
		end = len(events)
	}

	return events[start:end], nil
}

func (m *mockStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return m.GetSecurityEvents(&userID, "", limit, offset)
}

func (m *mockStorage) CreateUserWithSecurity(user *User, security *UserSecurity) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create user
	user.ID = m.nextUserID
	m.nextUserID++
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	// Generate UUID if not set
	if user.UUID == "" {
		token, _ := generateSecureToken(16)
		user.UUID = token
	}
	// Create a copy to avoid issues when handlers modify the original
	userCopy := *user
	m.users[user.Email+":"+user.Provider] = &userCopy

	// Create security record
	security.UserID = user.ID
	security.CreatedAt = time.Now()
	security.UpdatedAt = time.Now()
	m.userSecurity[security.UserID] = security

	return nil
}

func (m *mockStorage) HandleFailedLogin(userID uint, maxAttempts int, lockoutDuration time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	security, exists := m.userSecurity[userID]
	if !exists {
		return false, ErrUserNotFound
	}

	security.LoginAttempts++
	now := time.Now()
	security.LastFailedLoginAt = &now
	security.UpdatedAt = now

	if security.LoginAttempts >= maxAttempts {
		lockUntil := now.Add(lockoutDuration)
		security.LockedUntil = &lockUntil
		return true, nil
	}

	return false, nil
}

func (m *mockStorage) UpdateSession(session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session.LastAccessedAt = time.Now()
	m.sessions[session.Token] = session
	return nil
}

func (m *mockStorage) CountActiveSessions(userID uint) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, session := range m.sessions {
		if session.UserID == userID && session.ExpiresAt.After(now) {
			count++
		}
	}
	return count, nil
}

func (m *mockStorage) StoreOAuthState(state *OAuthState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state.CreatedAt = time.Now()
	m.oauthStates[state.State] = state
	return nil
}

func (m *mockStorage) CreateOAuthState(state *OAuthState) error {
	return m.StoreOAuthState(state)
}

func (m *mockStorage) GetOAuthState(state string) (*OAuthState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if oauthState, exists := m.oauthStates[state]; exists {
		// Check if state is expired
		if oauthState.ExpiresAt.Before(time.Now()) {
			// Note: We can't delete here because we're under RLock
			// The state will be cleaned up by CleanupExpiredOAuthStates
			return nil, nil
		}
		return oauthState, nil
	}
	return nil, nil // Return nil when state not found, not an error
}

func (m *mockStorage) DeleteOAuthState(state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.oauthStates, state)
	return nil
}

func (m *mockStorage) CleanupExpiredOAuthStates() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for state, oauthState := range m.oauthStates {
		if oauthState.ExpiresAt.Before(now) {
			delete(m.oauthStates, state)
		}
	}
	return nil
}

func (m *mockStorage) CreatePasswordResetToken(token *PasswordResetToken) error {
	m.passwordResetTokens[token.Token] = token
	return nil
}

func (m *mockStorage) GetPasswordResetToken(tokenStr string) (*PasswordResetToken, error) {
	token, exists := m.passwordResetTokens[tokenStr]
	if !exists || token.UsedAt != nil || token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("password reset token not found or expired")
	}
	return token, nil
}

func (m *mockStorage) UsePasswordResetToken(tokenStr string) error {
	token, exists := m.passwordResetTokens[tokenStr]
	if !exists {
		return fmt.Errorf("password reset token not found")
	}
	now := time.Now()
	token.UsedAt = &now
	return nil
}

func (m *mockStorage) CleanupExpiredPasswordResetTokens() error {
	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)
	for tokenStr, token := range m.passwordResetTokens {
		if token.ExpiresAt.Before(now) || (token.UsedAt != nil && token.UsedAt.Before(cutoff)) {
			delete(m.passwordResetTokens, tokenStr)
		}
	}
	return nil
}

func (m *mockStorage) Ping() error {
	return nil
}

func (m *mockStorage) Close() error {
	return nil
}

// mustCreateTestStorage creates a mock storage for testing
func mustCreateTestStorage(t *testing.T) Storage {
	t.Helper()
	return newMockStorage()
}

// mustCreateTestAuthService creates an AuthService for testing
func mustCreateTestAuthService(t *testing.T) *AuthService {
	t.Helper()
	config := Config{
		Storage:        mustCreateTestStorage(t),
		SecurityConfig: DefaultSecurityConfig(),
	}

	authService, err := NewAuthService(config)
	if err != nil {
		t.Fatalf("Failed to create test AuthService: %v", err)
	}

	return authService
}

// createTestRequest creates an HTTP request with JSON body for testing
func createTestRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()

	var reqBody *bytes.Buffer

	if body != nil {
		if str, ok := body.(string); ok {
			reqBody = bytes.NewBufferString(str)
		} else {
			jsonData, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}
			reqBody = bytes.NewBuffer(jsonData)
		}
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")

	return req
}

// mustCreateTestUserWithToken creates a user and returns the user and token
func mustCreateTestUserWithToken(t *testing.T, authService *AuthService) (*User, string) {
	t.Helper()

	// Use test name to generate unique email to avoid conflicts
	email := "testuser-" + strings.ReplaceAll(t.Name(), "/", "-") + "@example.com"
	signupReq := createTestRequest(t, "POST", "/signup", map[string]interface{}{
		"email":      email,
		"password":   "TestPassword123!",
		"first_name": "Test",
		"last_name":  "User",
	})

	signupResp := authService.SignUpHandler(signupReq)
	if signupResp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create test user: %+v", signupResp)
	}

	if signupResp.User == nil || signupResp.Token == "" {
		t.Fatalf("Signup response missing user or token: %+v", signupResp)
	}

	return signupResp.User, signupResp.Token
}
