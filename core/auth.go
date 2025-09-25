// Package core provides a simplified authentication library focused on essential features.
//
// This package includes:
//   - Email/password authentication with security features
//   - Multi-provider OAuth2 support (Google, GitHub, Discord)
//   - Session management with device tracking
//   - Security event auditing and logging
//   - Rate limiting and account lockout protection
//
// ## Key Features:
//   - Built-in security with detailed tracking
//   - Return-based handlers - maximum control over HTTP responses
//   - Works with any HTTP router (Chi, Gorilla Mux, stdlib, etc.)
//
// ## Quick Start:
//
//	cfg := core.Config{
//		Storage: storage,
//		SecurityConfig: core.SecurityConfig{
//			MaxLoginAttempts: 5,
//		},
//		OAuthProviders: map[string]core.OAuthProviderConfig{
//			"google": core.NewGoogleOAuthProvider(clientID, secret, redirectURL),
//		},
//	}
//
//	authService, err := core.NewAuthService(cfg)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Mount routes with maximum simplicity and control
//	r.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
//		result := authService.SignUpHandler(r)  // Single API!
//		w.WriteHeader(result.StatusCode)
//		json.NewEncoder(w).Encode(result)
//	})
package core

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// Discord OAuth2 endpoints for Discord authentication integration
var (
	// DiscordAuthURL is the Discord OAuth2 authorization endpoint
	DiscordAuthURL = "https://discord.com/api/oauth2/authorize"
	// DiscordTokenURL is the Discord OAuth2 token endpoint
	DiscordTokenURL = "https://discord.com/api/oauth2/token"
)

// Common authentication errors returned by the library
var (
	// ErrUserNotFound is returned when a user cannot be found in the database
	ErrUserNotFound = errors.New("user not found")
	// ErrInvalidCredentials is returned for authentication failures
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUserExists is returned when attempting to create a user that already exists
	ErrUserExists = errors.New("user already exists")
	// ErrInvalidProvider is returned when an unsupported OAuth provider is specified
	ErrInvalidProvider = errors.New("invalid OAuth provider")
	// ErrAccountLocked is returned when an account is temporarily locked
	ErrAccountLocked = errors.New("account temporarily locked")
)

// SecurityConfig defines security-related configuration options
type SecurityConfig struct {
	// Password security
	PasswordMinLength      int
	PasswordRequireUpper   bool
	PasswordRequireLower   bool
	PasswordRequireNumber  bool
	PasswordRequireSpecial bool

	// Login security
	MaxLoginAttempts int           // Maximum failed login attempts before lockout
	LockoutDuration  time.Duration // How long accounts remain locked
	SessionLifetime  time.Duration // How long sessions remain valid
	RequireTwoFactor bool          // Whether 2FA is required for all users

	// 2FA Security Settings
	TwoFactorCodeExpiry      time.Duration // How long 2FA codes remain valid (default: 5 minutes)
	Max2FAAttempts           int           // Maximum failed 2FA attempts before lockout (default: 3)
	TwoFactorLockoutDuration time.Duration // How long to lock 2FA after max failures (default: 15 minutes)
}

// DefaultSecurityConfig returns a secure default configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		PasswordMinLength:        8,
		PasswordRequireUpper:     true,
		PasswordRequireLower:     true,
		PasswordRequireNumber:    true,
		PasswordRequireSpecial:   false,
		MaxLoginAttempts:         5,
		LockoutDuration:          15 * time.Minute,
		SessionLifetime:          24 * time.Hour,
		RequireTwoFactor:         false,
		TwoFactorCodeExpiry:      5 * time.Minute,
		Max2FAAttempts:           3,
		TwoFactorLockoutDuration: 15 * time.Minute,
	}
}


// OAuthProviderConfig defines the configuration for an OAuth2 provider.
type OAuthProviderConfig struct {
	ClientID     string   `json:"client_id"`     // OAuth2 client ID from provider
	ClientSecret string   `json:"client_secret"` // OAuth2 client secret from provider
	RedirectURL  string   `json:"redirect_url"`  // Callback URL registered with provider
	AuthURL      string   `json:"auth_url"`      // OAuth2 authorization endpoint (optional for known providers)
	TokenURL     string   `json:"token_url"`     // OAuth2 token endpoint (optional for known providers)
	Scopes       []string `json:"scopes"`        // OAuth2 scopes to request (optional, defaults provided)
}

// NewGoogleOAuthProvider creates a Google OAuth provider configuration with defaults
func NewGoogleOAuthProvider(clientID, clientSecret, redirectURL string) OAuthProviderConfig {
	return OAuthProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      google.Endpoint.AuthURL,
		TokenURL:     google.Endpoint.TokenURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
	}
}

// NewGitHubOAuthProvider creates a GitHub OAuth provider configuration with defaults
func NewGitHubOAuthProvider(clientID, clientSecret, redirectURL string) OAuthProviderConfig {
	return OAuthProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      github.Endpoint.AuthURL,
		TokenURL:     github.Endpoint.TokenURL,
		Scopes:       []string{"user:email", "read:user"},
	}
}

// NewDiscordOAuthProvider creates a Discord OAuth provider configuration with defaults
func NewDiscordOAuthProvider(clientID, clientSecret, redirectURL string) OAuthProviderConfig {
	return OAuthProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      DiscordAuthURL,
		TokenURL:     DiscordTokenURL,
		Scopes:       []string{"identify", "email"},
	}
}

// NewCustomOAuthProvider creates a custom OAuth provider configuration
func NewCustomOAuthProvider(clientID, clientSecret, redirectURL, authURL, tokenURL string, scopes []string) OAuthProviderConfig {
	return OAuthProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		Scopes:       scopes,
	}
}

// Config contains the configuration for the AuthService
type Config struct {
	Storage        Storage                            // Storage implementation (required)
	SecurityConfig SecurityConfig                     // Security configuration
	OAuthProviders map[string]OAuthProviderConfig     // OAuth provider configurations
}

// AuthService is the main service for handling authentication operations.
type AuthService struct {
	storage        Storage
	oauthConfigs   map[string]*oauth2.Config
	securityConfig SecurityConfig
	validator      *validator.Validate
}

// NewAuthService creates a new authentication service
func NewAuthService(cfg Config) (*AuthService, error) {
	if cfg.Storage == nil {
		return nil, fmt.Errorf("storage is required")
	}

	// Test storage connection
	if err := cfg.Storage.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to storage: %w", err)
	}

	// Use default security config if not provided
	securityConfig := cfg.SecurityConfig
	if securityConfig.SessionLifetime == 0 {
		securityConfig = DefaultSecurityConfig()
	}

	// Convert OAuth provider configs to oauth2.Config
	oauthConfigs := make(map[string]*oauth2.Config)
	for provider, providerCfg := range cfg.OAuthProviders {
		oauthConfigs[provider] = &oauth2.Config{
			ClientID:     providerCfg.ClientID,
			ClientSecret: providerCfg.ClientSecret,
			RedirectURL:  providerCfg.RedirectURL,
			Scopes:       providerCfg.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  providerCfg.AuthURL,
				TokenURL: providerCfg.TokenURL,
			},
		}
	}

	validator := validator.New()

	service := &AuthService{
		storage:        cfg.Storage,
		oauthConfigs:   oauthConfigs,
		securityConfig: securityConfig,
		validator:      validator,
	}

	return service, nil
}

// GetUserFromContext retrieves the authenticated user from the request context.
// This function is used by middleware and handlers to access the current user.
func GetUserFromContext(r *http.Request) *User {
	if user, ok := r.Context().Value("user").(*User); ok {
		return user
	}
	return nil
}

// MustGetUserFromContext retrieves the authenticated user from context and panics if not found.
// This function should only be used when you are certain authentication middleware has run.
func MustGetUserFromContext(r *http.Request) *User {
	user := GetUserFromContext(r)
	if user == nil {
		panic("user not found in context - ensure authentication middleware is applied")
	}
	return user
}

// logSecurityEvent logs a security event to the database
func (a *AuthService) logSecurityEvent(userID *uint, eventType, description, ipAddress, userAgent string, success bool) {
	event := &SecurityEvent{
		UserID:      userID,
		EventType:   eventType,
		Description: description,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Severity:    "info",
		Success:     success,
		Metadata:    "",
	}

	if !success {
		event.Severity = "warning"
	}

	if err := a.storage.CreateSecurityEvent(event); err != nil {
		slog.Error("Failed to log security event",
			"event_type", eventType,
			"user_id", userID,
			"error", err)
	}
}

// Close closes the auth service and cleans up resources
func (a *AuthService) Close() error {
	return a.storage.Close()
}