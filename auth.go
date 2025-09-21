// Package auth provides a comprehensive authentication library with enterprise-grade security features.
//
// This package includes:
//   - Email/password authentication with advanced security
//   - Multi-provider OAuth2 support (Google, GitHub, Discord)
//   - Multi-tenant architecture with RBAC
//   - Session management with device tracking
//   - Email verification and password reset flows
//   - Security event auditing and logging
//   - Rate limiting and account lockout protection
//   - Chi router middleware and simplified HTTP handlers
//
// ## Key Features:
//   - Built-in email integration - configure once, works everywhere
//   - Return-based handlers - maximum control over HTTP responses
//   - Enterprise-grade security with 25+ security fields per user
//   - Works with any HTTP router (Chi, Gorilla Mux, stdlib, etc.)
//
// ## Quick Start:
//
//	cfg := auth.Config{
//		DatabaseDSN: "postgresql://user:pass@localhost/db",
//		EmailService: myEmailService,  // Built-in email integration!
//		SecurityConfig: auth.SecurityConfig{
//			RequireEmailVerification: true,
//			MaxLoginAttempts: 5,
//		},
//	}
//
//	authService, err := auth.NewAuthService(cfg)
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
package auth

import (
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand"
	"net/http"
	"time"

	"crypto/subtle"

	"github.com/go-playground/validator/v10"
	"github.com/wispberry-tech/wispy-auth/storage"
	"golang.org/x/crypto/bcrypt"
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
)

// User is an alias to the storage User type to maintain API compatibility
// while using the centralized storage type definitions.
type User = storage.User

// SecurityEvent is an alias to the storage SecurityEvent type
type SecurityEvent = storage.SecurityEvent

// OAuthState is an alias to the storage OAuthState type
type OAuthState = storage.OAuthState

// Tenant is an alias to the storage Tenant type
type Tenant = storage.Tenant

// Role is an alias to the storage Role type
type Role = storage.Role

// Permission is an alias to the storage Permission type
type Permission = storage.Permission

// UserTenant is an alias to the storage UserTenant type
type UserTenant = storage.UserTenant

// Session is an alias to the storage Session type
type Session = storage.Session

// SecurityConfig defines security-related configuration options
type SecurityConfig struct {
	// Email verification
	RequireEmailVerification bool
	VerificationTokenExpiry  time.Duration // How long verification tokens are valid

	// Password security
	PasswordMinLength      int
	PasswordRequireUpper   bool
	PasswordRequireLower   bool
	PasswordRequireNumber  bool
	PasswordRequireSpecial bool
	PasswordResetExpiry    time.Duration // How long reset tokens are valid

	// Login security
	MaxLoginAttempts int           // Maximum failed login attempts before lockout
	LockoutDuration  time.Duration // How long accounts remain locked
	SessionLifetime  time.Duration // How long sessions remain valid
	RequireTwoFactor bool          // Whether 2FA is required for all users

	// Referral System
	RequireReferralCode  bool              `json:"require_referral_code"`    // Make referral codes mandatory for signup
	DefaultUserRoleName  string            `json:"default_user_role_name"`   // Role assigned to new users (e.g., "default-user")
	MaxInviteesPerRole   map[string]int    `json:"max_invitees_per_role"`    // Max referrals per role {"default-user": 5, "premium": 20}
	ReferralCodeLength   int               `json:"referral_code_length"`     // Length of generated codes (default: 8)
	ReferralCodePrefix   string            `json:"referral_code_prefix"`     // Optional prefix for branding (e.g., "REF")
	ReferralCodeExpiry   time.Duration     `json:"referral_code_expiry"`     // How long codes remain valid (0 = no expiry)
}

// OAuthProviderConfig defines the configuration for an OAuth2 provider.
// This struct supports any OAuth2-compliant provider by allowing full customization
// of endpoints and scopes. For common providers (Google, GitHub, Discord), use the
// helper functions NewGoogleOAuthProvider, NewGitHubOAuthProvider, etc.
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

// EmailService interface defines methods for sending various types of authentication emails.
// Implement this interface to integrate your email service (SendGrid, Mailgun, SES, etc.)
// with the authentication system for seamless email delivery.
type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
	SendWelcomeEmail(email, name string) error
}

// AuthService is the main service for handling authentication operations.
// It provides methods for user signup/signin, OAuth integration, session management,
// middleware protection, and all other authentication-related functionality.
type AuthService struct {
	storage         storage.Interface
	oauthConfigs    map[string]*oauth2.Config
	storageConfig   StorageConfig
	securityConfig  SecurityConfig
	emailService    EmailService
	validator       *validator.Validate
	developmentMode bool // Whether running in development mode
}

// Config holds the main configuration for the authentication service.
// This includes database connection details, OAuth provider
// configurations, security/storage settings, and email service integration.
type Config struct {
	// Storage configuration - can use either Storage interface or DatabaseDSN string
	Storage        storage.Interface // Direct storage interface (takes precedence over DatabaseDSN)
	DatabaseDSN    string           // Database connection string (used if Storage is nil)
	OAuthProviders map[string]OAuthProviderConfig
	StorageConfig  StorageConfig
	SecurityConfig SecurityConfig
	EmailService   EmailService // Email service for sending verification/reset emails

	// Environment configuration
	DevelopmentMode bool // Whether running in development mode (affects cookie security)
}

// DefaultSecurityConfig returns sensible security defaults
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		// Email verification settings
		RequireEmailVerification: true,
		VerificationTokenExpiry:  24 * time.Hour,

		// Password requirements
		PasswordMinLength:      8,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireNumber:  true,
		PasswordRequireSpecial: false,
		PasswordResetExpiry:    1 * time.Hour,

		// Login security
		MaxLoginAttempts: 5,
		LockoutDuration:  15 * time.Minute,
		SessionLifetime:  24 * time.Hour,
		RequireTwoFactor: false,
	}
}

// NewAuthService creates and initializes a new authentication service with the provided configuration.
// It sets up the database connection, OAuth providers, and security settings.
// Returns an error if the database connection fails or configuration is invalid.
//
// Example usage:
//
//	cfg := auth.Config{
//		DatabaseDSN: "postgresql://user:pass@localhost/db",
//		SecurityConfig: auth.SecurityConfig{
//			RequireEmailVerification: true,
//		},
//	}
//
//	authService, err := auth.NewAuthService(cfg)
//	if err != nil {
//		log.Fatal(err)
//	}

func NewAuthService(cfg Config) (*AuthService, error) {
	var storageInstance storage.Interface
	var err error

	// Use provided storage interface or create PostgreSQL storage from DSN
	if cfg.Storage != nil {
		storageInstance = cfg.Storage
		slog.Info("Using provided storage interface")
	} else if cfg.DatabaseDSN != "" {
		// Initialize storage interface with PostgreSQL
		storageInstance, err = storage.NewPostgresStorage(cfg.DatabaseDSN)
		if err != nil {
			slog.Error("Failed to initialize storage", "error", err, "dsn", cfg.DatabaseDSN)
			return nil, fmt.Errorf("failed to initialize storage: %w", err)
		}
	} else {
		return nil, fmt.Errorf("either Storage or DatabaseDSN must be provided")
	}

	// Set up OAuth2 configurations for multiple providers
	oauthConfigs := make(map[string]*oauth2.Config)

	for provider, providerCfg := range cfg.OAuthProviders {
		// Validate required fields
		if providerCfg.ClientID == "" || providerCfg.ClientSecret == "" || providerCfg.RedirectURL == "" {
			slog.Error("OAuth provider missing required fields", "provider", provider)
			return nil, fmt.Errorf("OAuth provider '%s' missing required fields (ClientID, ClientSecret, RedirectURL)", provider)
		}

		// Use configured endpoints, or provide helpful defaults for known providers if missing
		authURL := providerCfg.AuthURL
		tokenURL := providerCfg.TokenURL
		scopes := providerCfg.Scopes

		// Provide defaults for common providers if endpoints are not specified
		if authURL == "" || tokenURL == "" {
			switch provider {
			case "google":
				if authURL == "" {
					authURL = google.Endpoint.AuthURL
				}
				if tokenURL == "" {
					tokenURL = google.Endpoint.TokenURL
				}
				if len(scopes) == 0 {
					scopes = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
				}
			case "github":
				if authURL == "" {
					authURL = github.Endpoint.AuthURL
				}
				if tokenURL == "" {
					tokenURL = github.Endpoint.TokenURL
				}
				if len(scopes) == 0 {
					scopes = []string{"user:email", "read:user"}
				}
			case "discord":
				if authURL == "" {
					authURL = DiscordAuthURL
				}
				if tokenURL == "" {
					tokenURL = DiscordTokenURL
				}
				if len(scopes) == 0 {
					scopes = []string{"identify", "email"}
				}
			default:
				// For custom providers, both AuthURL and TokenURL must be provided
				if authURL == "" || tokenURL == "" {
					slog.Error("Custom OAuth provider missing required endpoints", "provider", provider)
					return nil, fmt.Errorf("OAuth provider '%s' must specify both AuthURL and TokenURL", provider)
				}
			}
		}

		// Ensure we have at least one scope
		if len(scopes) == 0 {
			slog.Warn("OAuth provider has no scopes defined, using minimal scope", "provider", provider)
			scopes = []string{"openid", "email", "profile"} // Common default scopes
		}

		oauthConfigs[provider] = &oauth2.Config{
			ClientID:     providerCfg.ClientID,
			ClientSecret: providerCfg.ClientSecret,
			RedirectURL:  providerCfg.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		}

		slog.Info("Configured OAuth provider", "provider", provider, "scopes", scopes)
	}

	authService := &AuthService{
		storage:         storageInstance,
		oauthConfigs:    oauthConfigs,
		storageConfig:   cfg.StorageConfig,
		securityConfig:  cfg.SecurityConfig,
		emailService:    cfg.EmailService,
		validator:       validator.New(),
		developmentMode: cfg.DevelopmentMode,
	}

	// Setup default tenant if multi-tenant is enabled
	if err := authService.SetupDefaultTenant(); err != nil {
		slog.Error("Failed to setup default tenant", "error", err)
		return nil, fmt.Errorf("failed to setup default tenant: %w", err)
	}

	return authService, nil
}

// GetAvailableProviders returns the list of configured OAuth providers
func (a *AuthService) GetAvailableProviders() []string {
	providers := make([]string, 0, len(a.oauthConfigs))
	for provider := range a.oauthConfigs {
		providers = append(providers, provider)
	}
	return providers
}

func (a *AuthService) SignUp(req SignUpRequest) (*User, error) {
	return a.SignUpWithTenant(req, 0) // Use default tenant
}

type SignUpRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Password     string `json:"password" validate:"required,min=8"`
	Username     string `json:"username" validate:"required"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	ReferralCode string `json:"referral_code,omitempty"`
}

func (a *AuthService) SignUpWithTenant(req SignUpRequest, tenantID uint) (*User, error) {
	// Validate email format
	if !isValidEmail(req.Email) {
		slog.Warn("Invalid email format provided", "email", req.Email)
		return nil, fmt.Errorf("invalid email format")
	}

	// Validate password strength
	if err := validatePasswordStrength(req.Password, a.securityConfig); err != nil {
		slog.Warn("Password validation failed", "error", err, "email", req.Email)
		return nil, err
	}

	// Check if user already exists
	_, err := a.storage.GetUserByEmail(req.Email, "email")
	if err == nil {
		return nil, ErrUserExists
	}
	if err != ErrUserNotFound {
		slog.Error("Failed to check existing user", "error", err, "email", req.Email)
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Validate referral code if provided or required
	var referralCode *ReferralCode
	if req.ReferralCode != "" || a.securityConfig.RequireReferralCode {
		if req.ReferralCode == "" && a.securityConfig.RequireReferralCode {
			return nil, fmt.Errorf("referral code is required")
		}

		if req.ReferralCode != "" {
			referralCode, err = a.ValidateReferralCode(req.ReferralCode, tenantID)
			if err != nil {
				slog.Warn("Invalid referral code in signup", "code", req.ReferralCode, "email", req.Email, "error", err)
				return nil, fmt.Errorf("invalid referral code: %w", err)
			}
		}
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err, "email", req.Email)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate verification token if email verification is required
	var verificationToken string
	if a.securityConfig.RequireEmailVerification {
		verificationToken, err = generateVerificationToken()
		if err != nil {
			slog.Error("Failed to generate verification token", "error", err, "email", req.Email)
			return nil, fmt.Errorf("failed to generate verification token: %w", err)
		}
	}

	now := time.Now()
	// Create core user record
	user := User{
		Email:         req.Email,
		Username:      req.Username,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		PasswordHash:  hashedPassword,
		Provider:      "email",
		EmailVerified: !a.securityConfig.RequireEmailVerification, // Auto-verify if not required
		IsActive:      true,
		IsSuspended:   false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := a.storage.CreateUser(&user); err != nil {
		slog.Error("Failed to create user", "error", err, "email", req.Email, "username", req.Username)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create security record
	userSecurity := storage.UserSecurity{
		UserID:            user.ID,
		VerificationToken: verificationToken,
		PasswordChangedAt: &now,
		ReferredByCode:    req.ReferralCode,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// Set email verification timestamp if not required
	if !a.securityConfig.RequireEmailVerification {
		userSecurity.EmailVerifiedAt = &now
	}

	if err := a.storage.CreateUserSecurity(&userSecurity); err != nil {
		slog.Error("Failed to create user security", "error", err, "userID", user.ID)
		return nil, fmt.Errorf("failed to create user security: %w", err)
	}

	// Assign user to tenant if multi-tenant is enabled
	if err := a.assignUserToDefaultTenant(&user, tenantID); err != nil {
		slog.Error("Failed to assign user to tenant", "error", err, "user_id", user.ID, "tenant_id", tenantID)
		return nil, fmt.Errorf("failed to assign user to tenant: %w", err)
	}

	// Process referral code after user creation and tenant assignment
	if referralCode != nil {
		err = a.UseReferralCode(referralCode, user.ID)
		if err != nil {
			slog.Error("Failed to process referral code", "error", err, "user_id", user.ID, "code", req.ReferralCode)
			// Don't fail signup, but log the error
		}
	}

	return &user, nil
}

func (a *AuthService) SignIn(email, password string) (*User, error) {
	return a.SignInWithContext(email, password, "", "", "")
}

func (a *AuthService) SignInWithContext(email, password, ip, userAgent, location string) (*User, error) {
	startTime := time.Now()
	defer func() {
		// Add random sleep to make timing attacks harder
		elapsed := time.Since(startTime)
		if elapsed < 500*time.Millisecond {
			time.Sleep(time.Duration(mathrand.Int63n(100)) * time.Millisecond)
		}
	}()

	user, err := a.storage.GetUserByEmail(email, "email")
	if err != nil {
		if err == ErrUserNotFound {
			// Use constant time comparison even for non-existent users
			// This prevents timing attacks that could determine if an email exists
			bcrypt.CompareHashAndPassword(
				[]byte("$2a$10$dummyhashfordeletedaccounts"),
				[]byte(password),
			)
			return nil, ErrInvalidCredentials
		}
		slog.Error("Database error during user lookup", "error", err, "email", email)
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Validate login attempt (checks account status, suspension, lock, etc.)
	if err := a.validateLoginAttempt(user, ip, userAgent); err != nil {
		return nil, err
	}

	// Verify password using constant-time comparison
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		// Record failed login attempt
		if err := a.recordLoginFailure(user, ip, userAgent); err != nil {
			// Log error but don't block the response
			slog.Error("Failed to record failed login", "error", err, "user_id", user.ID, "email", email)
		}
		return nil, ErrInvalidCredentials
	}

	// Check if email verification is required and not verified (after password validation)
	if a.securityConfig.RequireEmailVerification && !user.EmailVerified {
		slog.Warn("Login attempt with unverified email", "user_id", user.ID, "email", email)
		return nil, ErrEmailNotVerified
	}

	// Password is correct, record successful login
	if err := a.recordLoginSuccess(user, ip, userAgent, location); err != nil {
		// Log error but don't block the response
		slog.Error("Failed to record successful login", "error", err, "user_id", user.ID, "email", email)
	}

	return user, nil
}

// OAuthState type is defined in oauth.go

// Session type is defined in models.go

func (a *AuthService) GetOAuthURL(provider string, r *http.Request) (string, string, error) {
	config, exists := a.oauthConfigs[provider]
	if !exists {
		return "", "", ErrInvalidProvider
	}

	// Generate secure state and CSRF tokens
	state := generateSecureRandomString(32)
	csrfToken := generateSecureRandomString(32)

	// Store state with CSRF token
	oauthState := &OAuthState{
		State:     state,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CSRF:      csrfToken,
	}

	// Store in storage backend
	if err := a.storage.StoreOAuthState(oauthState); err != nil {
		slog.Error("Failed to store OAuth state", "error", err, "provider", provider)
		return "", "", fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return config.AuthCodeURL(state), csrfToken, nil
}

func (a *AuthService) ValidateOAuthState(state, csrfToken string) error {
	// Retrieve state from storage
	storedState, err := a.storage.GetOAuthState(state)
	if err != nil {
		slog.Warn("Invalid OAuth state attempted", "error", err, "state", state)
		return fmt.Errorf("invalid OAuth state")
	}

	// Check expiration
	if time.Now().After(storedState.ExpiresAt) {
		slog.Warn("OAuth state expired", "state", state, "expired_at", storedState.ExpiresAt)
		return fmt.Errorf("OAuth state expired")
	}

	// Validate CSRF token using constant time comparison
	if subtle.ConstantTimeCompare([]byte(csrfToken), []byte(storedState.CSRF)) != 1 {
		slog.Warn("CSRF token mismatch", "state", state)
		return fmt.Errorf("CSRF token mismatch")
	}

	// Delete the used state
	if err := a.storage.DeleteOAuthState(state); err != nil {
		// Log error but don't fail the validation
		slog.Error("Failed to delete OAuth state", "error", err, "state", state)
	}

	return nil
}

// Security helper methods
func (a *AuthService) logSecurityEvent(userID *uint, tenantID *uint, eventType, description, ip, userAgent, location string) {
	event := &SecurityEvent{
		UserID:      userID,
		TenantID:    tenantID,
		EventType:   eventType,
		Description: description,
		IPAddress:   ip,
		UserAgent:   userAgent,
		Location:    location,
		CreatedAt:   time.Now(),
	}

	// Log security event (ignore errors to avoid blocking auth flow)
	a.storage.CreateSecurityEvent(event)
}

// Multi-tenant helper methods
func (a *AuthService) assignUserToDefaultTenant(user *User, tenantID uint) error {
	// Get storage config for multi-tenant setup
	storageConfig := a.getStorageConfig()

	// Use provided tenantID or fall back to default
	targetTenantID := tenantID
	if targetTenantID == 0 {
		targetTenantID = storageConfig.MultiTenant.DefaultTenantID
	}

	// Ensure default role exists and get its ID
	defaultRoleID, err := a.ensureDefaultRole(targetTenantID)
	if err != nil {
		return fmt.Errorf("failed to ensure default role: %w", err)
	}

	// Assign user to tenant with default role
	return a.storage.AssignUserToTenant(user.ID, targetTenantID, defaultRoleID)
}

// ensureDefaultRole ensures the default role exists for a tenant and returns its ID
func (a *AuthService) ensureDefaultRole(tenantID uint) (uint, error) {
	// Get default role name from configuration
	defaultRoleName := a.securityConfig.DefaultUserRoleName
	if defaultRoleName == "" {
		defaultRoleName = "default-user"
	}

	// Try to find existing default role
	roles, err := a.storage.GetRolesByTenant(tenantID)
	if err != nil {
		return 0, fmt.Errorf("failed to get tenant roles: %w", err)
	}

	for _, role := range roles {
		if role.Name == defaultRoleName {
			return role.ID, nil
		}
	}

	// Create default role if it doesn't exist
	defaultRole := &Role{
		TenantID:    tenantID,
		Name:        defaultRoleName,
		Description: "Default role for new users",
		IsSystem:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := a.storage.CreateRole(defaultRole); err != nil {
		return 0, fmt.Errorf("failed to create default role: %w", err)
	}

	slog.Info("Created default role for tenant",
		"role_name", defaultRoleName,
		"tenant_id", tenantID,
		"role_id", defaultRole.ID)

	return defaultRole.ID, nil
}

func (a *AuthService) getStorageConfig() *StorageConfig {
	return &a.storageConfig
}

// Multi-tenant API methods

// CreateTenant creates a new tenant
func (a *AuthService) CreateTenant(name, slug, domain string) (*Tenant, error) {
	tenant := &Tenant{
		Name:     name,
		Slug:     slug,
		Domain:   domain,
		IsActive: true,
		Settings: "{}",
	}

	if err := a.storage.CreateTenant(tenant); err != nil {
		slog.Error("Failed to create tenant", "error", err, "name", name, "slug", slug)
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (a *AuthService) GetTenant(id uint) (*Tenant, error) {
	return a.storage.GetTenantByID(id)
}

// GetTenantBySlug retrieves a tenant by slug
func (a *AuthService) GetTenantBySlug(slug string) (*Tenant, error) {
	return a.storage.GetTenantBySlug(slug)
}

// CreateRole creates a new role for a tenant
func (a *AuthService) CreateRole(tenantID uint, name, description string, isSystem bool) (*Role, error) {
	role := &Role{
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		IsSystem:    isSystem,
	}

	if err := a.storage.CreateRole(role); err != nil {
		slog.Error("Failed to create role", "error", err, "tenant_id", tenantID, "name", name)
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	return role, nil
}

// GetRolesByTenant retrieves all roles for a tenant
func (a *AuthService) GetRolesByTenant(tenantID uint) ([]*Role, error) {
	return a.storage.GetRolesByTenant(tenantID)
}

// CreatePermission creates a new permission
func (a *AuthService) CreatePermission(name, resource, action, description string) (*Permission, error) {
	permission := &Permission{
		Name:        name,
		Resource:    resource,
		Action:      action,
		Description: description,
	}

	if err := a.storage.CreatePermission(permission); err != nil {
		slog.Error("Failed to create permission", "error", err, "name", name, "resource", resource, "action", action)
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return permission, nil
}

// AssignPermissionToRole assigns a permission to a role
func (a *AuthService) AssignPermissionToRole(roleID, permissionID uint) error {
	return a.storage.AssignPermissionToRole(roleID, permissionID)
}

// AssignUserToTenant assigns a user to a tenant with a role
func (a *AuthService) AssignUserToTenant(userID, tenantID, roleID uint) error {
	return a.storage.AssignUserToTenant(userID, tenantID, roleID)
}

// GetUserTenants retrieves all tenants for a user
func (a *AuthService) GetUserTenants(userID uint) ([]*UserTenant, error) {
	return a.storage.GetUserTenants(userID)
}

// UserHasPermission checks if a user has a specific permission in a tenant
func (a *AuthService) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	return a.storage.UserHasPermission(userID, tenantID, permission)
}

// GetUserPermissionsInTenant gets all permissions for a user in a specific tenant
func (a *AuthService) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	return a.storage.GetUserPermissionsInTenant(userID, tenantID)
}

// Password Reset functionality
func (a *AuthService) InitiatePasswordReset(email string) error {
	user, err := a.storage.GetUserByEmail(email, "email")
	if err != nil {
		// Don't reveal if email exists
		return nil
	}

	token, err := generatePasswordResetToken()
	if err != nil {
		slog.Error("Failed to generate reset token", "error", err, "email", email)
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	expiresAt := time.Now().Add(a.securityConfig.PasswordResetExpiry)

	// Get or create user security record
	userSecurity, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		// Create new security record if it doesn't exist
		userSecurity = &storage.UserSecurity{
			UserID:    user.ID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := a.storage.CreateUserSecurity(userSecurity); err != nil {
			slog.Error("Failed to create user security", "error", err, "user_id", user.ID)
			return fmt.Errorf("failed to create user security: %w", err)
		}
	}

	userSecurity.PasswordResetToken = token
	userSecurity.PasswordResetExpiresAt = &expiresAt
	userSecurity.UpdatedAt = time.Now()

	if err := a.storage.UpdateUserSecurity(userSecurity); err != nil {
		slog.Error("Failed to save reset token", "error", err, "user_id", user.ID, "email", email)
		return fmt.Errorf("failed to save reset token: %w", err)
	}

	a.logSecurityEvent(&user.ID, nil, EventPasswordReset,
		"Password reset initiated", "", "", "")

	return nil
}

func (a *AuthService) ResetPassword(token, newPassword string) error {
	user, err := a.storage.GetUserByPasswordResetToken(token)
	if err != nil {
		slog.Warn("Invalid reset token used", "error", err, "token", token)
		return fmt.Errorf("invalid reset token")
	}

	// Get user security record to check token expiry
	userSecurity, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Warn("No security record found for reset token", "user_id", user.ID, "token", token)
		return fmt.Errorf("invalid reset token")
	}

	// Check if token is expired
	if userSecurity.PasswordResetExpiresAt == nil || time.Now().After(*userSecurity.PasswordResetExpiresAt) {
		slog.Warn("Expired reset token used", "user_id", user.ID, "token", token, "expired_at", userSecurity.PasswordResetExpiresAt)
		return fmt.Errorf("reset token has expired")
	}

	// Validate new password
	if err := validatePasswordStrength(newPassword, a.securityConfig); err != nil {
		slog.Warn("Password validation failed during reset", "error", err, "user_id", user.ID)
		return err
	}

	// Hash new password
	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		slog.Error("Failed to hash password during reset", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()

	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to update password", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Clear reset token and update security record
	now := time.Now()
	userSecurity.PasswordChangedAt = &now
	userSecurity.PasswordResetToken = ""
	userSecurity.PasswordResetExpiresAt = nil
	userSecurity.UpdatedAt = now

	if err := a.storage.UpdateUserSecurity(userSecurity); err != nil {
		slog.Error("Failed to update user security after password reset", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to update user security: %w", err)
	}

	a.logSecurityEvent(&user.ID, nil, EventPasswordChanged,
		"Password reset completed", "", "", "")

	return nil
}

// Email Verification functionality
func (a *AuthService) SendEmailVerification(userID uint) error {
	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		slog.Error("User not found for email verification", "error", err, "user_id", userID)
		return fmt.Errorf("user not found: %w", err)
	}

	if user.EmailVerified {
		slog.Warn("Attempt to send verification for already verified email", "user_id", userID, "email", user.Email)
		return fmt.Errorf("email already verified")
	}

	token, err := generateVerificationToken()
	if err != nil {
		slog.Error("Failed to generate verification token", "error", err, "user_id", userID)
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Get or create user security record
	userSecurity, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		// Create new security record if it doesn't exist
		userSecurity = &storage.UserSecurity{
			UserID:    user.ID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := a.storage.CreateUserSecurity(userSecurity); err != nil {
			slog.Error("Failed to create user security", "error", err, "user_id", user.ID)
			return fmt.Errorf("failed to create user security: %w", err)
		}
	}

	userSecurity.VerificationToken = token
	userSecurity.UpdatedAt = time.Now()

	if err := a.storage.UpdateUserSecurity(userSecurity); err != nil {
		slog.Error("Failed to save verification token", "error", err, "user_id", userID)
		return fmt.Errorf("failed to save verification token: %w", err)
	}

	return nil
}

// GetUserByVerificationToken retrieves a user by their verification token
func (a *AuthService) GetUserByVerificationToken(token string) (*User, error) {
	return a.storage.GetUserByVerificationToken(token)
}

func (a *AuthService) VerifyEmail(token string) error {
	user, err := a.storage.GetUserByVerificationToken(token)
	if err != nil {
		slog.Warn("Invalid verification token used", "error", err, "token", token)
		return fmt.Errorf("invalid verification token")
	}

	// Check if already verified
	if user.EmailVerified {
		slog.Warn("Attempt to verify already verified email", "user_id", user.ID, "email", user.Email)
		return fmt.Errorf("email already verified")
	}

	// Get user security record to check verification token
	userSecurity, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Warn("No security record found for verification token", "user_id", user.ID, "token", token)
		return fmt.Errorf("invalid verification token")
	}

	// Check if token has expired
	if userSecurity.VerificationToken == "" || userSecurity.EmailVerifiedAt != nil {
		slog.Warn("Invalid or expired verification token", "user_id", user.ID, "token", token)
		return fmt.Errorf("invalid verification token")
	}

	// Mark email as verified
	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to update user email verification", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to verify email: %w", err)
	}

	// Update security record
	now := time.Now()
	userSecurity.EmailVerifiedAt = &now
	userSecurity.VerificationToken = "" // Clear the token after use
	userSecurity.UpdatedAt = now

	if err := a.storage.UpdateUserSecurity(userSecurity); err != nil {
		slog.Error("Failed to update user security after email verification", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to update user security: %w", err)
	}

	// Log the verification
	a.logSecurityEvent(&user.ID, nil, EventEmailVerified,
		"Email verification completed", "", "", "")

	return nil
}

// Session Management
func (a *AuthService) CreateSession(userID uint, ip, userAgent, location string) (*Session, error) {
	// Check if user has too many active sessions
	activeCount, err := a.storage.CountActiveSessions(userID)
	if err != nil {
		slog.Error("Failed to count active sessions", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to count active sessions: %w", err)
	}

	if activeCount >= 5 { // Default max sessions
		slog.Warn("Maximum number of active sessions reached", "user_id", userID, "active_count", activeCount)
		return nil, fmt.Errorf("maximum number of active sessions reached")
	}

	token, err := generateSecureToken(48)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	session := &Session{
		ID:                fmt.Sprintf("%d_%d", userID, time.Now().Unix()),
		UserID:            userID,
		Token:             token,
		ExpiresAt:         calculateSessionExpiry(a.securityConfig),
		DeviceFingerprint: generateDeviceFingerprint(userAgent, ip),
		UserAgent:         userAgent,
		IPAddress:         ip,
		Location:          location,
		IsActive:          true,
		LastActivity:      time.Now(),
		RequiresTwoFactor: a.securityConfig.RequireTwoFactor,
		TwoFactorVerified: !a.securityConfig.RequireTwoFactor,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		slog.Error("Failed to create session", "error", err, "user_id", userID, "session_id", session.ID)
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	a.logSecurityEvent(&userID, nil, EventSessionCreated,
		"New session created", ip, userAgent, location)

	return session, nil
}

func (a *AuthService) GetUserSessions(userID uint) ([]*Session, error) {
	return a.storage.GetUserSessions(userID)
}

func (a *AuthService) RevokeSession(sessionID string) error {
	session, err := a.storage.GetSession(sessionID)
	if err != nil {
		slog.Error("Session not found for revocation", "error", err, "session_id", sessionID)
		return fmt.Errorf("session not found: %w", err)
	}

	if err := a.storage.DeleteSession(sessionID); err != nil {
		slog.Error("Failed to revoke session", "error", err, "session_id", sessionID)
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	a.logSecurityEvent(&session.UserID, nil, EventSessionTerminated,
		"Session manually revoked", session.IPAddress, session.UserAgent, session.Location)

	return nil
}

func (a *AuthService) RevokeAllUserSessions(userID uint) error {
	if err := a.storage.DeleteUserSessions(userID); err != nil {
		slog.Error("Failed to revoke user sessions", "error", err, "user_id", userID)
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	a.logSecurityEvent(&userID, nil, EventSessionTerminated,
		"All user sessions revoked", "", "", "")

	return nil
}
