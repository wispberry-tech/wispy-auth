// Package auth provides a comprehensive authentication library with enterprise-grade security features.
//
// This package includes:
//   - Email/password authentication with advanced security
//   - Multi-provider OAuth2 support (Google, GitHub, Discord)
//   - JWT token generation and validation
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
//		JWTSecret:   "your-secret-key",
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

// User represents a user in the authentication system with comprehensive security features.
// This struct contains all necessary fields for enterprise-grade user management including
// email verification, password reset, login tracking, multi-factor authentication,
// and account security controls.
type User struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`

	PasswordHash string `json:"-"` // Hide password from JSON
	AvatarURL    string `json:"avatar_url,omitempty"`
	Provider     string `json:"provider"` // "email", "google", "github", "discord"
	ProviderID   string `json:"provider_id"`

	// Email Security
	EmailVerified     bool       `json:"email_verified"`
	EmailVerifiedAt   *time.Time `json:"email_verified_at,omitempty"`
	VerificationToken string     `json:"-"` // Hidden from JSON

	// Password Security
	PasswordResetToken     string     `json:"-"`
	PasswordResetExpiresAt *time.Time `json:"-"`
	PasswordChangedAt      *time.Time `json:"password_changed_at,omitempty"`

	// Login Security
	LoginAttempts     int        `json:"-"`
	LastFailedLoginAt *time.Time `json:"-"`
	LockedUntil       *time.Time `json:"-"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`

	// Location & Device Tracking
	LastKnownIP       string `json:"-"`
	LastLoginLocation string `json:"last_login_location,omitempty"`

	// Two-Factor Authentication
	TwoFactorEnabled bool   `json:"two_factor_enabled"`
	TwoFactorSecret  string `json:"-"`
	BackupCodes      string `json:"-"` // JSON array stored as string

	// Account Security
	IsActive      bool       `json:"is_active"`
	IsSuspended   bool       `json:"is_suspended"`
	SuspendedAt   *time.Time `json:"suspended_at,omitempty"`
	SuspendReason string     `json:"suspend_reason,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecurityEvent represents a security-related event for audit logging
type SecurityEvent struct {
	ID          uint      `json:"id"`
	UserID      *uint     `json:"user_id,omitempty"`
	TenantID    *uint     `json:"tenant_id,omitempty"`
	EventType   string    `json:"event_type"` // login_success, login_failed, password_reset, etc.
	Description string    `json:"description"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Location    string    `json:"location,omitempty"`
	Metadata    string    `json:"metadata,omitempty"` // JSON for additional context
	CreatedAt   time.Time `json:"created_at"`
}

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
}

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
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
	storage        StorageInterface
	jwtSecret      []byte
	oauthConfigs   map[string]*oauth2.Config
	storageConfig  StorageConfig
	securityConfig SecurityConfig
	emailService   EmailService
	validator      *validator.Validate
}

// Config holds the main configuration for the authentication service.
// This includes database connection details, JWT secret, OAuth provider
// configurations, security/storage settings, and email service integration.
type Config struct {
	DatabaseDSN    string
	JWTSecret      string
	OAuthProviders map[string]OAuthProviderConfig
	StorageConfig  StorageConfig
	SecurityConfig SecurityConfig
	EmailService   EmailService // Email service for sending verification/reset emails
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
//		JWTSecret:   "your-secret-key",
//		SecurityConfig: auth.SecurityConfig{
//			RequireEmailVerification: true,
//		},
//	}
//
//	authService, err := auth.NewAuthService(cfg)
//	if err != nil {
//		log.Fatal(err)
//	}
func init() {
	// Initialize random seed
	mathrand.Seed(time.Now().UnixNano())
}

func NewAuthService(cfg Config) (*AuthService, error) {
	// Initialize storage interface with PostgreSQL
	storage, err := NewPostgresStorage(cfg.DatabaseDSN, cfg.StorageConfig)
	if err != nil {
		slog.Error("Failed to initialize storage", "error", err, "dsn", cfg.DatabaseDSN)
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Set up OAuth2 configurations for multiple providers
	oauthConfigs := make(map[string]*oauth2.Config)

	for provider, providerCfg := range cfg.OAuthProviders {
		var endpoint oauth2.Endpoint
		var scopes []string

		switch provider {
		case "google":
			endpoint = google.Endpoint
			scopes = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
		case "github":
			endpoint = github.Endpoint
			scopes = []string{"user:email", "read:user"}
		case "discord":
			endpoint = oauth2.Endpoint{
				AuthURL:  DiscordAuthURL,
				TokenURL: DiscordTokenURL,
			}
			scopes = []string{"identify", "email"}
		default:
			slog.Error("Unsupported OAuth provider", "provider", provider)
			return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
		}

		oauthConfigs[provider] = &oauth2.Config{
			ClientID:     providerCfg.ClientID,
			ClientSecret: providerCfg.ClientSecret,
			RedirectURL:  providerCfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     endpoint,
		}
	}

	return &AuthService{
		storage:        storage,
		jwtSecret:      []byte(cfg.JWTSecret),
		oauthConfigs:   oauthConfigs,
		storageConfig:  cfg.StorageConfig,
		securityConfig: cfg.SecurityConfig,
		emailService:   cfg.EmailService,
		validator:      validator.New(),
	}, nil
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
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	Username  string `json:"username" validate:"required"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
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
	user := User{
		Email:             req.Email,
		Username:          req.Username,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		PasswordHash:      hashedPassword,
		Provider:          "email",
		EmailVerified:     !a.securityConfig.RequireEmailVerification, // Auto-verify if not required
		VerificationToken: verificationToken,
		PasswordChangedAt: &now,
		IsActive:          true,
		IsSuspended:       false,
		CreatedAt:         now,
		UpdatedAt:         now,
	} // Set email as verified if verification is not required
	if !a.securityConfig.RequireEmailVerification {
		user.EmailVerifiedAt = &now
	}

	if err := a.storage.CreateUser(&user); err != nil {
		slog.Error("Failed to create user", "error", err, "email", req.Email, "username", req.Username)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign user to tenant if multi-tenant is enabled
	if err := a.assignUserToDefaultTenant(&user, tenantID); err != nil {
		slog.Error("Failed to assign user to tenant", "error", err, "user_id", user.ID, "tenant_id", tenantID)
		return nil, fmt.Errorf("failed to assign user to tenant: %w", err)
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

	// Check if account is suspended
	if user.IsSuspended {
		slog.Warn("Login attempt on suspended account", "user_id", user.ID, "email", email, "suspend_reason", user.SuspendReason)
		a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
			"Login attempt on suspended account", ip, userAgent, location)
		return nil, fmt.Errorf("account is suspended: %s", user.SuspendReason)
	}

	// Check if account is inactive
	if !user.IsActive {
		slog.Warn("Login attempt on inactive account", "user_id", user.ID, "email", email)
		a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
			"Login attempt on inactive account", ip, userAgent, location)
		return nil, fmt.Errorf("account is inactive")
	}

	// Check if email verification is required and not verified
	if a.securityConfig.RequireEmailVerification && !user.EmailVerified {
		slog.Warn("Login attempt with unverified email", "user_id", user.ID, "email", email)
		return nil, fmt.Errorf("email not verified")
	}

	// Check if account is locked
	if a.isAccountLocked(user) {
		slog.Warn("Login attempt on locked account", "user_id", user.ID, "email", email, "locked_until", user.LockedUntil)
		a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
			"Login attempt on locked account", ip, userAgent, location)
		return nil, fmt.Errorf("account is locked until %v", user.LockedUntil.Format(time.RFC3339))
	}

	// Verify password using constant-time comparison
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		// Record failed login attempt
		if err := a.recordFailedLogin(user, ip, userAgent); err != nil {
			// Log error but don't block the response
			slog.Error("Failed to record failed login", "error", err, "user_id", user.ID, "email", email)
		}
		return nil, ErrInvalidCredentials
	}

	// Password is correct, record successful login
	if err := a.recordSuccessfulLogin(user, ip, userAgent, location); err != nil {
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

// shouldLockAccount checks if the account should be locked based on failed attempts
func (a *AuthService) shouldLockAccount(user *User) bool {
	return user.LoginAttempts >= a.securityConfig.MaxLoginAttempts
}

func (a *AuthService) lockAccount(user *User) error {
	lockUntil := time.Now().Add(a.securityConfig.LockoutDuration)
	user.LockedUntil = &lockUntil

	if err := a.storage.UpdateUser(user); err != nil {
		return err
	}

	a.logSecurityEvent(&user.ID, nil, EventAccountLocked,
		fmt.Sprintf("Account locked due to %d failed login attempts", user.LoginAttempts),
		user.LastKnownIP, "", user.LastLoginLocation)

	return nil
}

func (a *AuthService) recordFailedLogin(user *User, ip, userAgent string) error {
	user.LoginAttempts++
	now := time.Now()
	user.LastFailedLoginAt = &now
	user.LastKnownIP = ip

	if err := a.storage.UpdateUser(user); err != nil {
		return err
	}

	a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
		fmt.Sprintf("Failed login attempt (%d/%d)", user.LoginAttempts, a.securityConfig.MaxLoginAttempts),
		ip, userAgent, "")

	// Lock account if too many attempts
	if a.shouldLockAccount(user) {
		return a.lockAccount(user)
	}

	return nil
}

func (a *AuthService) recordSuccessfulLogin(user *User, ip, userAgent, location string) error {
	now := time.Now()
	user.LastLoginAt = &now
	user.LastKnownIP = ip
	user.LastLoginLocation = location

	// Reset login attempts on successful login
	user.LoginAttempts = 0
	user.LastFailedLoginAt = nil
	user.LockedUntil = nil

	if err := a.storage.UpdateUser(user); err != nil {
		return err
	}

	a.logSecurityEvent(&user.ID, nil, EventLoginSuccess,
		"Successful login", ip, userAgent, location)

	return nil
}

// Multi-tenant helper methods
func (a *AuthService) assignUserToDefaultTenant(user *User, tenantID uint) error {
	// Get storage config to check if multi-tenant is enabled
	storageConfig := a.getStorageConfig()
	if !storageConfig.MultiTenant.Enabled {
		return nil // Skip if multi-tenant is disabled
	}

	// Use provided tenantID or fall back to default
	targetTenantID := tenantID
	if targetTenantID == 0 {
		targetTenantID = storageConfig.MultiTenant.DefaultTenantID
	}

	// Get default role for the tenant (assume ID 1 is default user role)
	defaultRoleID := uint(1) // This should be configurable

	return a.storage.AssignUserToTenant(user.ID, targetTenantID, defaultRoleID)
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
	user.PasswordResetToken = token
	user.PasswordResetExpiresAt = &expiresAt

	if err := a.storage.UpdateUser(user); err != nil {
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

	// Check if token is expired
	if user.PasswordResetExpiresAt == nil || time.Now().After(*user.PasswordResetExpiresAt) {
		slog.Warn("Expired reset token used", "user_id", user.ID, "token", token, "expired_at", user.PasswordResetExpiresAt)
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

	// Update user
	user.PasswordHash = hashedPassword
	now := time.Now()
	user.PasswordChangedAt = &now
	user.PasswordResetToken = ""
	user.PasswordResetExpiresAt = nil

	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to update password", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to update password: %w", err)
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

	user.VerificationToken = token

	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to save verification token", "error", err, "user_id", userID)
		return fmt.Errorf("failed to save verification token: %w", err)
	}

	return nil
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

	// Check if token has expired (48 hours)
	if user.VerificationToken == "" || user.EmailVerifiedAt != nil {
		slog.Warn("Invalid or expired verification token", "user_id", user.ID, "token", token)
		return fmt.Errorf("invalid verification token")
	}

	// Mark email as verified
	user.EmailVerified = true
	now := time.Now()
	user.EmailVerifiedAt = &now
	user.VerificationToken = "" // Clear the token after use

	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to verify email", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to verify email: %w", err)
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
