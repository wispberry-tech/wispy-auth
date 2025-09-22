// Package storage provides storage interfaces and implementations for the auth system.
//
// This package defines the core storage interfaces and provides multiple implementations
// including PostgreSQL and SQLite drivers. Each implementation is in this package
// to provide a unified storage layer.
package storage

import (
	"errors"
	"time"
)

// Column mapping types for database operations
type UserColumnMapping struct {
	Table               string
	IDColumn            string
	EmailColumn         string
	UsernameColumn      string
	FirstNameColumn     string
	LastNameColumn      string
	PasswordHashColumn  string
	ProviderColumn      string
	ProviderIDColumn    string
	EmailVerifiedColumn string
	IsActiveColumn      string
	IsSuspendedColumn   string
	CreatedAtColumn     string
	UpdatedAtColumn     string
}

type SessionColumnMapping struct {
	Table                   string
	IDColumn                string
	UserIDColumn            string
	TokenColumn             string
	ExpiresAtColumn         string
	CSRFColumn              string
	DeviceFingerprintColumn string
	UserAgentColumn         string
	IPAddressColumn         string
	LocationColumn          string
	IsActiveColumn          string
	LastActivityColumn      string
	RequiresTwoFactorColumn string
	TwoFactorVerifiedColumn string
	CreatedAtColumn         string
	UpdatedAtColumn         string
}

type SecurityEventColumnMapping struct {
	Table             string
	IDColumn          string
	UserIDColumn      string
	TenantIDColumn    string
	EventTypeColumn   string
	DescriptionColumn string
	IPAddressColumn   string
	UserAgentColumn   string
	LocationColumn    string
	MetadataColumn    string
	CreatedAtColumn   string
}

// MultiTenantConfig contains configuration for multi-tenant mode
type MultiTenantConfig struct {
	Enabled         bool
	DefaultTenantID uint
}

// Config contains storage configuration options
type Config struct {
	DatabaseDSN        string
	MaxOpenConnections int
	MaxIdleConnections int
	ConnMaxLifetime    time.Duration
	UserColumns        UserColumnMapping
	SessionColumns     SessionColumnMapping
	EventColumns       SecurityEventColumnMapping
	MultiTenant        MultiTenantConfig
	UsersTable         string
	SessionsTable      string
}

// DefaultConfig returns the default storage configuration
func DefaultConfig() Config {
	return Config{
		MaxOpenConnections: 25,
		MaxIdleConnections: 5,
		ConnMaxLifetime:    time.Hour,
		MultiTenant:        MultiTenantConfig{Enabled: false, DefaultTenantID: 1},
		UsersTable:         "users",
		SessionsTable:      "sessions",
		UserColumns: UserColumnMapping{
			Table:               "users",
			IDColumn:            "id",
			EmailColumn:         "email",
			UsernameColumn:      "username",
			FirstNameColumn:     "first_name",
			LastNameColumn:      "last_name",
			PasswordHashColumn:  "password_hash",
			ProviderColumn:      "provider",
			ProviderIDColumn:    "provider_id",
			EmailVerifiedColumn: "email_verified",
			IsActiveColumn:      "is_active",
			IsSuspendedColumn:   "is_suspended",
			CreatedAtColumn:     "created_at",
			UpdatedAtColumn:     "updated_at",
		},
		SessionColumns: SessionColumnMapping{
			Table:                   "sessions",
			IDColumn:                "id",
			UserIDColumn:            "user_id",
			TokenColumn:             "token",
			ExpiresAtColumn:         "expires_at",
			CSRFColumn:              "csrf_token",
			DeviceFingerprintColumn: "device_fingerprint",
			UserAgentColumn:         "user_agent",
			IPAddressColumn:         "ip_address",
			LocationColumn:          "location",
			IsActiveColumn:          "is_active",
			LastActivityColumn:      "last_activity",
			RequiresTwoFactorColumn: "requires_two_factor",
			TwoFactorVerifiedColumn: "two_factor_verified",
			CreatedAtColumn:         "created_at",
			UpdatedAtColumn:         "updated_at",
		},
		EventColumns: SecurityEventColumnMapping{
			Table:             "security_events",
			IDColumn:          "id",
			UserIDColumn:      "user_id",
			TenantIDColumn:    "tenant_id",
			EventTypeColumn:   "event_type",
			DescriptionColumn: "description",
			IPAddressColumn:   "ip_address",
			UserAgentColumn:   "user_agent",
			LocationColumn:    "location",
			MetadataColumn:    "metadata",
			CreatedAtColumn:   "created_at",
		},
	}
}

var (
	ErrSessionNotFound  = errors.New("session not found")
	ErrInvalidSession   = errors.New("invalid session")
	ErrEmailNotVerified = errors.New("email not verified")
	ErrUserNotFound     = errors.New("user not found")
)

// Session represents a user session with enhanced security tracking
type Session struct {
	ID        string    `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CSRF      string    `json:"csrf_token"` // Anti-CSRF token

	// Device & Location Tracking
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent"`
	IPAddress         string `json:"ip_address"`
	Location          string `json:"location"`

	// Status
	IsActive          bool      `json:"is_active"`
	LastActivity      time.Time `json:"last_activity"`
	RequiresTwoFactor bool      `json:"requires_two_factor"`
	TwoFactorVerified bool      `json:"two_factor_verified"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// User represents core user identity and authentication information.
// Security details are handled separately via UserSecurity.
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

	// Core Security (frequently accessed)
	EmailVerified bool `json:"email_verified"`
	IsActive      bool `json:"is_active"`
	IsSuspended   bool `json:"is_suspended"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserSecurity represents detailed security tracking and sensitive data for a user.
type UserSecurity struct {
	UserID uint `json:"user_id"`

	// Email Security Details
	EmailVerifiedAt   *time.Time `json:"email_verified_at,omitempty"`
	VerificationToken string     `json:"-"` // Hidden from JSON

	// Password Security
	PasswordResetToken     string     `json:"-"` // Hidden from JSON
	PasswordResetExpiresAt *time.Time `json:"password_reset_expires_at,omitempty"`
	PasswordChangedAt      *time.Time `json:"password_changed_at,omitempty"`

	// Login Security Tracking
	LoginAttempts     int        `json:"login_attempts"`
	LastFailedLoginAt *time.Time `json:"last_failed_login_at,omitempty"`
	LockedUntil       *time.Time `json:"locked_until,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`

	// Location & Device Tracking
	LastKnownIP       string `json:"last_known_ip,omitempty"`
	LastLoginLocation string `json:"last_login_location,omitempty"`

	// Two-Factor Authentication
	TwoFactorEnabled bool   `json:"two_factor_enabled"`
	TwoFactorSecret  string `json:"-"` // Hidden from JSON
	BackupCodes      string `json:"-"` // Hidden from JSON

	// Account Management
	SuspendedAt   *time.Time `json:"suspended_at,omitempty"`
	SuspendReason string     `json:"suspend_reason,omitempty"`

	// Referral System
	ReferredByCode string `json:"referred_by_code,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Tenant represents a tenant/organization in the system
type Tenant struct {
	ID        uint      `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`   // URL-friendly identifier
	Domain    string    `json:"domain"` // Custom domain (optional)
	IsActive  bool      `json:"is_active"`
	Settings  string    `json:"settings"` // JSON settings specific to tenant
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Role represents a role within a tenant
type Role struct {
	ID          uint      `json:"id"`
	TenantID    uint      `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"` // System roles can't be deleted
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Permission represents a permission that can be assigned to roles
type Permission struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`     // e.g., "users.read", "posts.write"
	Resource    string    `json:"resource"` // e.g., "users", "posts"
	Action      string    `json:"action"`   // e.g., "read", "write", "delete"
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserTenant links users to tenants with roles
type UserTenant struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	TenantID  uint      `json:"tenant_id"`
	RoleID    uint      `json:"role_id"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Populated by joins
	Tenant *Tenant `json:"tenant,omitempty"`
	Role   *Role   `json:"role,omitempty"`
}

// SecurityEvent represents a security-related event in the system
type SecurityEvent struct {
	ID          uint      `json:"id"`
	UserID      *uint     `json:"user_id,omitempty"`
	TenantID    *uint     `json:"tenant_id,omitempty"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Location    string    `json:"location"`
	Metadata    string    `json:"metadata"`
	CreatedAt   time.Time `json:"created_at"`
}

// OAuthState represents OAuth state for CSRF protection
type OAuthState struct {
	State     string    `json:"state"`
	CSRF      string    `json:"csrf"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ReferralCode represents a referral code generated by a user
type ReferralCode struct {
	ID                uint       `json:"id"`
	Code              string     `json:"code"`
	GeneratedByUserID uint       `json:"generated_by_user_id"`
	GeneratedByRoleID uint       `json:"generated_by_role_id"`
	TenantID          uint       `json:"tenant_id"`
	MaxUses           int        `json:"max_uses"`
	CurrentUses       int        `json:"current_uses"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	IsActive          bool       `json:"is_active"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`

	// Populated by joins
	GeneratedByUser *User   `json:"generated_by_user,omitempty"`
	GeneratedByRole *Role   `json:"generated_by_role,omitempty"`
	Tenant          *Tenant `json:"tenant,omitempty"`
}

// UserReferral represents a referral relationship between users
type UserReferral struct {
	ID             uint      `json:"id"`
	ReferrerUserID uint      `json:"referrer_user_id"`
	ReferredUserID uint      `json:"referred_user_id"`
	ReferralCodeID uint      `json:"referral_code_id"`
	ReferrerRoleID uint      `json:"referrer_role_id"`
	TenantID       uint      `json:"tenant_id"`
	CreatedAt      time.Time `json:"created_at"`

	// Populated by joins
	ReferrerUser *User         `json:"referrer_user,omitempty"`
	ReferredUser *User         `json:"referred_user,omitempty"`
	ReferralCode *ReferralCode `json:"referral_code,omitempty"`
	ReferrerRole *Role         `json:"referrer_role,omitempty"`
	Tenant       *Tenant       `json:"tenant,omitempty"`
}

// TwoFactorCode represents a 2FA verification code with security tracking
type TwoFactorCode struct {
	ID           uint       `json:"id"`
	UserID       uint       `json:"user_id"`
	Code         string     `json:"-"` // Hidden from JSON
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	AttemptCount int        `json:"attempt_count"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
}

// Interface defines the contract for data storage operations
type Interface interface {
	// User operations - core identity only
	CreateUser(user *User) error
	GetUserByEmail(email, provider string) (*User, error)
	GetUserByEmailAnyProvider(email string) (*User, error)
	GetUserByProviderID(provider, providerID string) (*User, error)
	GetUserByID(id uint) (*User, error)
	UpdateUser(user *User) error

	// User Security operations - separate and explicit
	CreateUserSecurity(security *UserSecurity) error
	GetUserSecurity(userID uint) (*UserSecurity, error)
	UpdateUserSecurity(security *UserSecurity) error

	// Optimized methods for common security operations
	IncrementLoginAttempts(userID uint) error
	ResetLoginAttempts(userID uint) error
	SetUserLocked(userID uint, until time.Time) error
	UpdateLastLogin(userID uint, ipAddress string) error

	// Session operations
	CreateSession(session *Session) error
	GetSession(token string) (*Session, error)
	GetUserSessions(userID uint) ([]*Session, error)
	UpdateSession(session *Session) error
	DeleteSession(token string) error
	DeleteUserSessions(userID uint) error
	CleanupExpiredSessions() error
	CountActiveSessions(userID uint) (int, error)

	// OAuth state operations
	StoreOAuthState(state *OAuthState) error
	GetOAuthState(state string) (*OAuthState, error)
	DeleteOAuthState(state string) error

	// Multi-tenant operations
	CreateTenant(tenant *Tenant) error
	GetTenantByID(id uint) (*Tenant, error)
	GetTenantBySlug(slug string) (*Tenant, error)
	UpdateTenant(tenant *Tenant) error
	ListTenants() ([]*Tenant, error)

	// Role operations
	CreateRole(role *Role) error
	GetRoleByID(id uint) (*Role, error)
	GetRolesByTenant(tenantID uint) ([]*Role, error)
	UpdateRole(role *Role) error
	DeleteRole(id uint) error

	// Permission operations
	CreatePermission(permission *Permission) error
	GetPermissionByID(id uint) (*Permission, error)
	GetPermissionByName(name string) (*Permission, error)
	ListPermissions() ([]*Permission, error)
	UpdatePermission(permission *Permission) error
	DeletePermission(id uint) error

	// Role-Permission operations
	AssignPermissionToRole(roleID, permissionID uint) error
	RemovePermissionFromRole(roleID, permissionID uint) error
	GetRolePermissions(roleID uint) ([]*Permission, error)

	// User-Tenant operations
	AssignUserToTenant(userID, tenantID, roleID uint) error
	RemoveUserFromTenant(userID, tenantID uint) error
	GetUserTenants(userID uint) ([]*UserTenant, error)
	GetTenantUsers(tenantID uint) ([]*UserTenant, error)
	UpdateUserTenantRole(userID, tenantID, roleID uint) error

	// Permission checking
	UserHasPermission(userID, tenantID uint, permission string) (bool, error)
	GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error)

	// Security Event operations
	CreateSecurityEvent(event *SecurityEvent) error
	GetSecurityEvents(userID *uint, tenantID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error)
	GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error)

	// Token-based operations (work directly with UserSecurity)
	GetUserByPasswordResetToken(token string) (*User, error)
	GetUserByVerificationToken(token string) (*User, error)

	// Referral Code operations
	CreateReferralCode(code *ReferralCode) error
	GetReferralCodeByCode(code string) (*ReferralCode, error)
	GetReferralCodesByUser(userID uint) ([]*ReferralCode, error)
	UpdateReferralCode(code *ReferralCode) error
	DeactivateReferralCode(codeID uint) error
	CountActiveReferralsByUserRole(userID, roleID uint) (int, error)

	// User Referral operations
	CreateUserReferral(referral *UserReferral) error
	GetUserReferralsByReferrer(referrerUserID uint) ([]*UserReferral, error)
	GetUserReferralByReferred(referredUserID uint) (*UserReferral, error)
	GetReferralStatsByUser(userID uint) (int, int, error) // totalReferred, activeReferrals

	// Two Factor Code operations
	CreateTwoFactorCode(code *TwoFactorCode) error
	GetActiveTwoFactorCodeByUserID(userID uint) (*TwoFactorCode, error)
	UpdateTwoFactorCode(code *TwoFactorCode) error
	DeleteExpiredTwoFactorCodes() error

	// Utility operations
	Close() error
}
