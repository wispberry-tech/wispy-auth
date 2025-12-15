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
	DiscordTokenURL = "https://discord.com/api/oauth2/token" // #nosec G101
)

// Common authentication errors returned by the library
var (
	// ErrUserNotFound is returned when a user cannot be found in the database
	ErrUserNotFound = errors.New("user not found")
)

// SecurityConfig defines security-related configuration options for the authentication system.
//
// This configuration controls various security aspects including password requirements,
// login attempt limits, session management, and two-factor authentication settings.
// All settings have secure defaults provided by DefaultSecurityConfig().
//
// Password Security:
//   - Controls password complexity requirements
//   - Configurable minimum length and character class requirements
//
// Authentication Security:
//   - Login attempt tracking and account lockout protection
//   - Configurable lockout duration and attempt limits
//
// Session Security:
//   - Session lifetime management
//   - Automatic session expiration
//
// Two-Factor Authentication:
//   - Optional 2FA enforcement for enhanced security
//   - Configurable code expiry and attempt limits
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

	// Rate Limiting
	EnableRateLimiting bool          // Whether to enable rate limiting
	RateLimitRequests  int           // Maximum requests per window
	RateLimitWindow    time.Duration // Time window for rate limiting
}

// DefaultSecurityConfig returns a secure default configuration suitable for most applications.
//
// Default values:
//   - PasswordMinLength: 8 characters
//   - PasswordRequireUpper: true (requires uppercase letters)
//   - PasswordRequireLower: true (requires lowercase letters)
//   - PasswordRequireNumber: true (requires numeric digits)
//   - PasswordRequireSpecial: true (special characters required)
//   - MaxLoginAttempts: 5 (account locked after 5 failed attempts)
//   - LockoutDuration: 15 minutes
//   - SessionLifetime: 24 hours
//   - RequireTwoFactor: false (2FA not mandatory)
//   - TwoFactorCodeExpiry: 5 minutes
//   - Max2FAAttempts: 3 failed attempts before lockout
//   - TwoFactorLockoutDuration: 15 minutes
//   - EnableRateLimiting: true (rate limiting enabled)
//   - RateLimitRequests: 10 (10 requests per window)
//   - RateLimitWindow: 1 minute
//
// Example usage:
//
//	config := core.Config{
//		Storage:        storage,
//		SecurityConfig: core.DefaultSecurityConfig(),
//	}
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		PasswordMinLength:        8,
		PasswordRequireUpper:     true,
		PasswordRequireLower:     true,
		PasswordRequireNumber:    true,
		PasswordRequireSpecial:   true,
		MaxLoginAttempts:         5,
		LockoutDuration:          15 * time.Minute,
		SessionLifetime:          24 * time.Hour,
		RequireTwoFactor:         false,
		TwoFactorCodeExpiry:      5 * time.Minute,
		Max2FAAttempts:           3,
		TwoFactorLockoutDuration: 15 * time.Minute,
		EnableRateLimiting:       true,
		RateLimitRequests:        10,
		RateLimitWindow:          1 * time.Minute,
	}
}

// OAuthProviderConfig defines the configuration for an OAuth2 provider.
//
// This structure contains all necessary information to configure OAuth2 authentication
// with external providers. For well-known providers (Google, GitHub, Discord), use
// the helper functions like NewGoogleOAuthProvider() which set appropriate defaults.
//
// Required fields:
//   - ClientID: OAuth2 client identifier from provider
//   - ClientSecret: OAuth2 client secret from provider
//   - RedirectURL: Callback URL registered with provider
//
// Optional fields (auto-configured for known providers):
//   - AuthURL: Authorization endpoint URL
//   - TokenURL: Token exchange endpoint URL
//   - Scopes: Requested permissions/scopes
//
// The RedirectURL must exactly match what's registered with the OAuth provider
// and should follow the pattern: https://yourdomain.com/auth/{provider}/callback
type OAuthProviderConfig struct {
	ClientID     string   `json:"client_id"`     // OAuth2 client ID from provider
	ClientSecret string   `json:"client_secret"` // OAuth2 client secret from provider
	RedirectURL  string   `json:"redirect_url"`  // Callback URL registered with provider
	AuthURL      string   `json:"auth_url"`      // OAuth2 authorization endpoint (optional for known providers)
	TokenURL     string   `json:"token_url"`     // OAuth2 token endpoint (optional for known providers)
	Scopes       []string `json:"scopes"`        // OAuth2 scopes to request (optional, defaults provided)
}

// NewGoogleOAuthProvider creates a Google OAuth provider configuration with secure defaults.
//
// This function sets up Google OAuth2 integration with the following scopes:
//   - userinfo.email: Access to user's email address
//   - userinfo.profile: Access to basic profile information
//
// Parameters:
//   - clientID: OAuth2 client ID from Google Cloud Console
//   - clientSecret: OAuth2 client secret from Google Cloud Console
//   - redirectURL: Callback URL that must be registered in Google Cloud Console
//
// The redirectURL should match the pattern: https://yourdomain.com/auth/google/callback
//
// Example:
//
//	googleProvider := core.NewGoogleOAuthProvider(
//		"123456789.apps.googleusercontent.com",
//		"GOCSPX-your-client-secret",
//		"https://yourdomain.com/auth/google/callback",
//	)
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

// NewGitHubOAuthProvider creates a GitHub OAuth provider configuration with secure defaults.
//
// This function sets up GitHub OAuth2 integration with the following scopes:
//   - user:email: Access to user's email addresses (including private ones)
//   - read:user: Access to public and private profile information
//
// Parameters:
//   - clientID: OAuth2 client ID from GitHub Developer Settings
//   - clientSecret: OAuth2 client secret from GitHub Developer Settings
//   - redirectURL: Callback URL that must be registered in your GitHub OAuth App
//
// The redirectURL should match the pattern: https://yourdomain.com/auth/github/callback
//
// Example:
//
//	githubProvider := core.NewGitHubOAuthProvider(
//		"Iv1.a1b2c3d4e5f6g7h8",
//		"1234567890abcdef1234567890abcdef12345678",
//		"https://yourdomain.com/auth/github/callback",
//	)
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

// NewDiscordOAuthProvider creates a Discord OAuth provider configuration with secure defaults.
//
// This function sets up Discord OAuth2 integration with the following scopes:
//   - identify: Access to user's Discord username, discriminator, and avatar
//   - email: Access to user's email address
//
// Parameters:
//   - clientID: OAuth2 client ID from Discord Developer Portal
//   - clientSecret: OAuth2 client secret from Discord Developer Portal
//   - redirectURL: Callback URL that must be registered in your Discord Application
//
// The redirectURL should match the pattern: https://yourdomain.com/auth/discord/callback
//
// Example:
//
//	discordProvider := core.NewDiscordOAuthProvider(
//		"123456789012345678",
//		"abcdef1234567890abcdef1234567890ab",
//		"https://yourdomain.com/auth/discord/callback",
//	)
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

// NewCustomOAuthProvider creates a custom OAuth provider configuration for any OAuth2-compliant provider.
//
// This function allows integration with OAuth2 providers not directly supported by the library.
// You must provide the authorization and token endpoints specific to your provider.
//
// Parameters:
//   - clientID: OAuth2 client ID from your provider
//   - clientSecret: OAuth2 client secret from your provider
//   - redirectURL: Callback URL registered with your provider
//   - authURL: Provider's OAuth2 authorization endpoint (e.g., "https://provider.com/oauth/authorize")
//   - tokenURL: Provider's OAuth2 token endpoint (e.g., "https://provider.com/oauth/token")
//   - scopes: OAuth2 scopes to request from the provider
//
// Example:
//
//	customProvider := core.NewCustomOAuthProvider(
//		"your-client-id",
//		"your-client-secret",
//		"https://yourdomain.com/auth/custom/callback",
//		"https://provider.com/oauth/authorize",
//		"https://provider.com/oauth/token",
//		[]string{"read:user", "user:email"},
//	)
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

// Config contains the complete configuration for the AuthService.
//
// This is the primary configuration structure used to initialize an AuthService
// instance. It brings together storage, security settings, and OAuth provider
// configurations into a single cohesive setup.
//
// Required fields:
//   - Storage: Must implement the Storage interface for data persistence
//
// Optional fields:
//   - SecurityConfig: Uses DefaultSecurityConfig() if not provided
//   - OAuthProviders: OAuth2 providers, can be empty map if not using OAuth
//
// The Storage field must be a valid implementation of the Storage interface.
// Multiple implementations are available including SQLite and PostgreSQL.
type Config struct {
	Storage        Storage                        // Storage implementation (required)
	SecurityConfig SecurityConfig                 // Security configuration
	OAuthProviders map[string]OAuthProviderConfig // OAuth provider configurations
}

// AuthService is the main service for handling authentication operations.
//
// This is the core service that orchestrates all authentication functionality
// including user registration, login, session management, OAuth integration,
// and security event tracking. It provides HTTP handler methods that return
// structured responses, giving you complete control over HTTP response handling.
//
// Key responsibilities:
//   - User authentication and registration
//   - Session token management and validation
//   - OAuth2 provider integration
//   - Security event logging and tracking
//   - Password security enforcement
//   - Account lockout and rate limiting
//
// The service is designed to work with any HTTP router by providing handler
// methods that process requests and return response structures. You maintain
// full control over HTTP status codes, headers, and response formatting.
//
// Thread safety: AuthService is safe for concurrent use across multiple goroutines.
type AuthService struct {
	storage        Storage
	oauthConfigs   map[string]*oauth2.Config
	securityConfig SecurityConfig
	validator      *validator.Validate
	rateLimiter    *RateLimiter
}

// NewAuthService creates a new authentication service with the provided configuration.
//
// This is the primary constructor for the authentication system. It validates the configuration,
// tests the storage connection, sets up OAuth2 providers, and initializes the service.
//
// The function performs the following validation:
//   - Ensures storage implementation is provided
//   - Tests storage connectivity with Ping()
//   - Applies default security configuration if not specified
//   - Configures OAuth2 providers with proper endpoints
//   - Initializes request validation
//
// Parameters:
//   - cfg: Configuration containing storage, security settings, and OAuth providers
//
// Returns:
//   - *AuthService: Configured authentication service ready to handle requests
//   - error: Configuration or connectivity errors
//
// Example:
//
//	storage, err := storage.NewInMemorySQLiteStorage()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	config := core.Config{
//		Storage:        storage,
//		SecurityConfig: core.DefaultSecurityConfig(),
//		OAuthProviders: map[string]core.OAuthProviderConfig{
//			"google": core.NewGoogleOAuthProvider(clientID, secret, redirectURL),
//		},
//	}
//
//	authService, err := core.NewAuthService(config)
//	if err != nil {
//		log.Fatal("Failed to create auth service:", err)
//	}
//	defer authService.Close()
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

	// Initialize rate limiter if enabled
	if securityConfig.EnableRateLimiting {
		service.rateLimiter = NewRateLimiter(securityConfig.RateLimitRequests, securityConfig.RateLimitWindow)
	}

	return service, nil
}

// GetUserFromContext retrieves the authenticated user from the request context.
//
// This function safely extracts user information that was previously set by the
// AuthMiddleware during request processing. It returns nil if no user is found
// in the context, which typically indicates the request was not authenticated.
//
// Usage patterns:
//   - Use in protected route handlers to access current user
//   - Check return value for nil to handle unauthenticated requests
//   - Prefer this over MustGetUserFromContext for optional authentication
//
// Parameters:
//   - r: HTTP request with context potentially containing user information
//
// Returns:
//   - *User: Authenticated user information, or nil if not authenticated
//
// Example:
//
//	func profileHandler(w http.ResponseWriter, r *http.Request) {
//		user := core.GetUserFromContext(r)
//		if user == nil {
//			http.Error(w, "Authentication required", http.StatusUnauthorized)
//			return
//		}
//		// Use user information...
//		json.NewEncoder(w).Encode(user)
//	}
func GetUserFromContext(r *http.Request) *User {
	if user, ok := r.Context().Value("user").(*User); ok {
		return user
	}
	return nil
}

// MustGetUserFromContext retrieves the authenticated user from context and panics if not found.
//
// This function is a convenience method for handlers that require authentication
// and should only be used when you are certain that authentication middleware
// has been properly applied to the route. If no user is found in context,
// this function will panic with a descriptive error message.
//
// Use cases:
//   - Protected endpoints where authentication is guaranteed by middleware
//   - When you want to fail fast if authentication setup is incorrect
//   - Avoid the need for nil checks when authentication is required
//
// WARNING: This function panics if no user is found in context. Only use when
// authentication middleware is guaranteed to have run successfully.
//
// Parameters:
//   - r: HTTP request with context containing authenticated user
//
// Returns:
//   - *User: Authenticated user information (never nil)
//
// Panics:
//   - If no user found in context (authentication middleware not applied)
//
// Example:
//
//	mux.Handle("GET /admin", authService.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		user := core.MustGetUserFromContext(r) // Safe - middleware guarantees user presence
//		if !user.IsAdmin {
//			http.Error(w, "Admin access required", http.StatusForbidden)
//			return
//		}
//		// Handle admin request...
//	})))
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

// GetStorage returns the storage instance for use by independent modules.
//
// This method provides access to the underlying storage implementation used
// by the AuthService. It's primarily intended for use by extension modules
// (like referrals or email verification) that need to interact with the same
// database instance for consistency and transaction support.
//
// The returned storage interface implements all core authentication data
// operations and can be extended by modules that implement additional
// storage interfaces for their specific needs.
//
// Returns:
//   - Storage: The configured storage implementation
//
// Example usage by extension modules:
//
//	// In a referrals module
//	coreStorage := authService.GetStorage()
//	referralStorage, ok := coreStorage.(referrals.Storage)
//	if !ok {
//		return fmt.Errorf("storage does not implement referrals.Storage interface")
//	}
func (a *AuthService) GetStorage() Storage {
	return a.storage
}

// Close closes the auth service and cleans up resources.
//
// This method should be called when the application is shutting down to ensure
// proper cleanup of database connections and other resources. It delegates to
// the underlying storage implementation's Close method.
//
// It's recommended to use defer with this method to ensure cleanup happens
// even if the application exits unexpectedly.
//
// Returns:
//   - error: Any error encountered during cleanup
//
// Example:
//
//	authService, err := core.NewAuthService(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer authService.Close() // Ensures cleanup on exit
//
//	// Application logic...
func (a *AuthService) Close() error {
	// Cleanup rate limiter if it exists
	if a.rateLimiter != nil {
		a.rateLimiter.Cleanup()
	}
	return a.storage.Close()
}
