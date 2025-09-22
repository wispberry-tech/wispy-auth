package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wispberry-tech/wispy-auth/storage"
)

// Enhanced email service with tracking (extends the one in minimal_test.go)
type TrackingEmailService struct {
	SentEmails []EmailRecord
}

type EmailRecord struct {
	Type      string
	Email     string
	Token     string
	Timestamp time.Time
}

func (t *TrackingEmailService) SendVerificationEmail(email, token string) error {
	t.SentEmails = append(t.SentEmails, EmailRecord{
		Type:      "verification",
		Email:     email,
		Token:     token,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TrackingEmailService) SendPasswordResetEmail(email, token string) error {
	t.SentEmails = append(t.SentEmails, EmailRecord{
		Type:      "password_reset",
		Email:     email,
		Token:     token,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TrackingEmailService) SendWelcomeEmail(email, name string) error {
	t.SentEmails = append(t.SentEmails, EmailRecord{
		Type:      "welcome",
		Email:     email,
		Token:     name,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TrackingEmailService) Send2FACode(email, code string) error {
	t.SentEmails = append(t.SentEmails, EmailRecord{
		Type:      "2fa_code",
		Email:     email,
		Token:     code,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TrackingEmailService) Send2FAEnabled(email string) error {
	t.SentEmails = append(t.SentEmails, EmailRecord{
		Type:      "2fa_enabled",
		Email:     email,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TrackingEmailService) Send2FADisabled(email string) error {
	t.SentEmails = append(t.SentEmails, EmailRecord{
		Type:      "2fa_disabled",
		Email:     email,
		Timestamp: time.Now(),
	})
	return nil
}

func (t *TrackingEmailService) GetLastEmail() *EmailRecord {
	if len(t.SentEmails) == 0 {
		return nil
	}
	return &t.SentEmails[len(t.SentEmails)-1]
}

func (t *TrackingEmailService) Reset() {
	t.SentEmails = []EmailRecord{}
}

// Test helper functions
func createTestAuthService(t *testing.T) (*AuthService, storage.Interface) {
	sqliteStorage, err := storage.NewInMemorySQLiteStorage()
	if err != nil {
		t.Fatal("Failed to create storage:", err)
	}

	config := Config{
		Storage:      sqliteStorage,
		EmailService: &TrackingEmailService{},
		SecurityConfig: SecurityConfig{
			PasswordMinLength:        8,
			RequireEmailVerification: false,
			DefaultUserRoleName:      "user",
			SessionLifetime:          24 * time.Hour,
		},
	}

	authService, err := NewAuthService(config)
	if err != nil {
		t.Fatal("Failed to create auth service:", err)
	}

	return authService, sqliteStorage
}

func createMockRequest() *http.Request {
	req, _ := http.NewRequest("GET", "http://localhost:8080/test", nil)
	return req
}

func createTestConfig() Config {
	storage, _ := storage.NewInMemorySQLiteStorage()
	return Config{
		Storage:      storage,
		EmailService: &TrackingEmailService{},
		SecurityConfig: SecurityConfig{
			PasswordMinLength:   8,
			DefaultUserRoleName: "user",
			SessionLifetime:     24 * time.Hour,
		},
	}
}

// Core AuthService Tests
func TestNewAuthService(t *testing.T) {
	config := createTestConfig()

	authService, err := NewAuthService(config)
	if err != nil {
		t.Fatal("Failed to create auth service:", err)
	}

	if authService == nil {
		t.Error("AuthService should not be nil")
	}

	if authService.storage == nil {
		t.Error("Storage should be initialized")
	}

	if authService.emailService == nil {
		t.Error("Email service should be initialized")
	}
}

func TestNewAuthServiceWithNilStorage(t *testing.T) {
	config := Config{
		Storage:      nil,
		EmailService: &TrackingEmailService{},
		SecurityConfig: SecurityConfig{
			DefaultUserRoleName: "user",
		},
	}

	_, err := NewAuthService(config)
	if err == nil {
		t.Error("Expected error with nil storage")
	}
}

func TestDefaultStorageConfig(t *testing.T) {
	config := DefaultStorageConfig()

	if config.UsersTable != "users" {
		t.Errorf("Expected users table 'users', got '%s'", config.UsersTable)
	}

	if config.SessionsTable != "sessions" {
		t.Errorf("Expected sessions table 'sessions', got '%s'", config.SessionsTable)
	}
}

func TestDefaultSecurityConfig(t *testing.T) {
	config := DefaultSecurityConfig()

	if config.PasswordMinLength != 8 {
		t.Errorf("Expected password min length 8, got %d", config.PasswordMinLength)
	}

	if config.SessionLifetime != 24*time.Hour {
		t.Errorf("Expected session lifetime 24h, got %v", config.SessionLifetime)
	}

	if config.DefaultUserRoleName != "user" {
		t.Errorf("Expected default role 'user', got '%s'", config.DefaultUserRoleName)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Should have default storage config
	if config.StorageConfig.MaxOpenConnections != 25 {
		t.Errorf("Expected max open connections 25, got %d", config.StorageConfig.MaxOpenConnections)
	}

	// Should have default security config
	if config.SecurityConfig.PasswordMinLength != 8 {
		t.Errorf("Expected password min length 8, got %d", config.SecurityConfig.PasswordMinLength)
	}

	// Should have empty OAuth providers map (not nil)
	if config.OAuthProviders == nil {
		t.Error("Expected OAuth providers map to be initialized, got nil")
	}

	// Should not be in development mode by default
	if config.DevelopmentMode {
		t.Error("Expected development mode to be false by default")
	}

	// Storage and EmailService should be nil (user needs to set these)
	if config.Storage != nil {
		t.Error("Expected Storage to be nil by default")
	}

	if config.EmailService != nil {
		t.Error("Expected EmailService to be nil by default")
	}

	// DatabaseDSN should be empty (user needs to set this if not using Storage)
	if config.DatabaseDSN != "" {
		t.Errorf("Expected DatabaseDSN to be empty by default, got '%s'", config.DatabaseDSN)
	}
}

// OAuth Provider Tests
func TestNewGoogleOAuthProvider(t *testing.T) {
	provider := NewGoogleOAuthProvider("client-id", "client-secret", "redirect-url")

	if provider.ClientID != "client-id" {
		t.Error("Client ID not set correctly")
	}

	if provider.ClientSecret != "client-secret" {
		t.Error("Client secret not set correctly")
	}

	if provider.RedirectURL != "redirect-url" {
		t.Error("Redirect URL not set correctly")
	}

	if provider.AuthURL != "https://accounts.google.com/o/oauth2/auth" {
		t.Error("Google auth URL not set correctly")
	}
}

func TestNewGitHubOAuthProvider(t *testing.T) {
	provider := NewGitHubOAuthProvider("client-id", "client-secret", "redirect-url")

	if provider.ClientID != "client-id" {
		t.Error("Client ID not set correctly")
	}

	if provider.AuthURL != "https://github.com/login/oauth/authorize" {
		t.Error("GitHub auth URL not set correctly")
	}

	if provider.TokenURL != "https://github.com/login/oauth/access_token" {
		t.Error("GitHub token URL not set correctly")
	}
}

func TestNewDiscordOAuthProvider(t *testing.T) {
	provider := NewDiscordOAuthProvider("client-id", "client-secret", "redirect-url")

	if provider.ClientID != "client-id" {
		t.Error("Client ID not set correctly")
	}

	if provider.AuthURL != "https://discord.com/api/oauth2/authorize" {
		t.Error("Discord auth URL not set correctly")
	}
}

func TestNewCustomOAuthProvider(t *testing.T) {
	scopes := []string{"profile", "email"}
	provider := NewCustomOAuthProvider(
		"client-id", "client-secret", "redirect-url",
		"https://example.com/auth", "https://example.com/token",
		scopes,
	)

	if provider.AuthURL != "https://example.com/auth" {
		t.Error("Custom auth URL not set correctly")
	}

	if provider.TokenURL != "https://example.com/token" {
		t.Error("Custom token URL not set correctly")
	}

	if len(provider.Scopes) != 2 {
		t.Error("Custom scopes not set correctly")
	}
}

// User Registration Tests
func TestSignUp(t *testing.T) {
	authService, _ := createTestAuthService(t)

	req := SignUpRequest{
		Email:    "test@example.com",
		Password: "Password123",
		Username: "testuser",
	}

	user, err := authService.SignUp(req)
	if err != nil {
		t.Fatal("Failed to sign up user:", err)
	}

	if user.Email != "test@example.com" {
		t.Error("User email not set correctly")
	}

	if user.Username != "testuser" {
		t.Error("User username not set correctly")
	}

	if user.PasswordHash == "" {
		t.Error("Password hash should be set")
	}

	if !user.IsActive {
		t.Error("User should be active by default")
	}
}

func TestSignUpWithDuplicateEmail(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Create first user
	req1 := SignUpRequest{
		Email:    "test@example.com",
		Password: "Password123",
		Username: "testuser1",
	}
	_, err := authService.SignUp(req1)
	if err != nil {
		t.Fatal("Failed to create first user:", err)
	}

	// Try to create second user with same email
	req2 := SignUpRequest{
		Email:    "test@example.com",
		Password: "Password123",
		Username: "testuser2",
	}
	_, err = authService.SignUp(req2)
	if err == nil {
		t.Error("Expected error for duplicate email")
	}
}

func TestSignUpWithWeakPassword(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Test with password too short
	req := SignUpRequest{
		Email:    "test@example.com",
		Password: "weak",
		Username: "testuser",
	}
	_, err := authService.SignUp(req)
	if err == nil {
		t.Error("Expected error for weak password")
	}
}

func TestSignUpWithInvalidEmail(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Test with invalid email
	req := SignUpRequest{
		Email:    "invalid-email",
		Password: "Password123",
		Username: "testuser",
	}
	_, err := authService.SignUp(req)
	if err == nil {
		t.Error("Expected error for invalid email")
	}
}

// User Authentication Tests
func TestSignIn(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Create user first
	req := SignUpRequest{
		Email:    "test@example.com",
		Password: "Password123",
		Username: "testuser",
	}
	_, err := authService.SignUp(req)
	if err != nil {
		t.Fatal("Failed to create user:", err)
	}

	// Test sign in
	user, err := authService.SignIn("test@example.com", "Password123")
	if err != nil {
		t.Fatal("Failed to sign in:", err)
	}

	if user.Email != "test@example.com" {
		t.Error("User email should match")
	}

	if user.ID == 0 {
		t.Error("User ID should be set")
	}

	if !user.IsActive {
		t.Error("User should be active")
	}
}

func TestSignInWithInvalidCredentials(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Create user first
	req := SignUpRequest{
		Email:    "test@example.com",
		Password: "Password123",
		Username: "testuser",
	}
	_, err := authService.SignUp(req)
	if err != nil {
		t.Fatal("Failed to create user:", err)
	}

	// Test sign in with wrong password
	_, err = authService.SignIn("test@example.com", "WrongPassword")
	if err == nil {
		t.Error("Expected error for invalid credentials")
	}
}

func TestSignInWithNonexistentUser(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Test sign in with non-existent user
	_, err := authService.SignIn("nonexistent@example.com", "Password123")
	if err == nil {
		t.Error("Expected error for non-existent user")
	}
}

// OAuth Provider Tests
func TestGetAvailableProviders(t *testing.T) {
	storage, _ := storage.NewInMemorySQLiteStorage()
	config := Config{
		Storage:      storage,
		EmailService: &TrackingEmailService{},
		SecurityConfig: SecurityConfig{
			DefaultUserRoleName: "user",
		},
		OAuthProviders: map[string]OAuthProviderConfig{
			"google": NewGoogleOAuthProvider("id", "secret", "redirect"),
			"github": NewGitHubOAuthProvider("id", "secret", "redirect"),
		},
	}

	authService, err := NewAuthService(config)
	if err != nil {
		t.Fatal("Failed to create auth service:", err)
	}

	providers := authService.GetAvailableProviders()
	if len(providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(providers))
	}

	found := make(map[string]bool)
	for _, provider := range providers {
		found[provider] = true
	}

	if !found["google"] {
		t.Error("Google provider should be available")
	}

	if !found["github"] {
		t.Error("GitHub provider should be available")
	}
}

func TestGetOAuthURL(t *testing.T) {
	storage, _ := storage.NewInMemorySQLiteStorage()
	config := Config{
		Storage:      storage,
		EmailService: &TrackingEmailService{},
		SecurityConfig: SecurityConfig{
			DefaultUserRoleName: "user",
		},
		OAuthProviders: map[string]OAuthProviderConfig{
			"google": NewGoogleOAuthProvider("client-id", "client-secret", "http://localhost/callback"),
		},
	}

	authService, err := NewAuthService(config)
	if err != nil {
		t.Fatal("Failed to create auth service:", err)
	}

	// Create a mock request
	req := createMockRequest()

	url, state, err := authService.GetOAuthURL("google", req)
	if err != nil {
		t.Fatal("Failed to get OAuth URL:", err)
	}

	if url == "" {
		t.Error("OAuth URL should not be empty")
	}

	if state == "" {
		t.Error("OAuth state should not be empty")
	}

	if !containsString(url, "accounts.google.com") {
		t.Error("URL should contain Google OAuth endpoint")
	}

	if !containsString(url, "client-id") {
		t.Error("URL should contain client ID")
	}
}

func TestGetOAuthURLInvalidProvider(t *testing.T) {
	authService, _ := createTestAuthService(t)

	req := createMockRequest()
	_, _, err := authService.GetOAuthURL("invalid-provider", req)
	if err == nil {
		t.Error("Expected error for invalid provider")
	}
}

// Configuration Validation Tests (Additional cases)
func TestAuthServiceConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    func() Config
		shouldErr bool
	}{
		{
			name: "valid config with tracking email service",
			config: func() Config {
				return createTestConfig()
			},
			shouldErr: false,
		},
		{
			name: "empty default role name",
			config: func() Config {
				config := createTestConfig()
				config.SecurityConfig.DefaultUserRoleName = ""
				return config
			},
			shouldErr: true,
		},
		{
			name: "negative session lifetime",
			config: func() Config {
				config := createTestConfig()
				config.SecurityConfig.SessionLifetime = -1 * time.Hour
				return config
			},
			shouldErr: false, // This might be valid, just unusual
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAuthService(test.config())

			if test.shouldErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.shouldErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// Helper function
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}
