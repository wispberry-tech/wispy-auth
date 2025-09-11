package auth

import (
	"errors"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrInvalidSession  = errors.New("invalid session")
)

// Session represents a user session with enhanced security tracking
type Session struct {
	ID        string    `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`

	// Device & Location Tracking
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent"`
	IPAddress         string `json:"ip_address"`
	Location          string `json:"location,omitempty"`

	// Security Features
	IsActive          bool      `json:"is_active"`
	LastActivity      time.Time `json:"last_activity"`
	RequiresTwoFactor bool      `json:"requires_2fa"`
	TwoFactorVerified bool      `json:"2fa_verified"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StorageInterface defines the contract for data storage operations
type StorageInterface interface {
	// User operations
	CreateUser(user *User) error
	GetUserByEmail(email, provider string) (*User, error)
	GetUserByEmailAnyProvider(email string) (*User, error)
	GetUserByProviderID(provider, providerID string) (*User, error)
	GetUserByID(id uint) (*User, error)
	UpdateUser(user *User) error

	// Session operations
	CreateSession(session *Session) error
	GetSession(token string) (*Session, error)
	GetUserSessions(userID uint) ([]*Session, error)

	// OAuth state operations
	StoreOAuthState(state *OAuthState) error
	GetOAuthState(state string) (*OAuthState, error)
	DeleteOAuthState(state string) error
	UpdateSession(session *Session) error
	DeleteSession(token string) error
	DeleteUserSessions(userID uint) error
	CleanupExpiredSessions() error
	CountActiveSessions(userID uint) (int, error)

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

	// Password Reset operations
	CreatePasswordResetToken(userID uint, token string, expiresAt time.Time) error
	GetUserByPasswordResetToken(token string) (*User, error)
	ClearPasswordResetToken(userID uint) error

	// Email Verification operations
	SetEmailVerificationToken(userID uint, token string) error
	GetUserByVerificationToken(token string) (*User, error)
	MarkEmailAsVerified(userID uint) error

	// Login Attempt operations
	IncrementLoginAttempts(userID uint) error
	ResetLoginAttempts(userID uint) error
	LockUser(userID uint, until time.Time) error
	UnlockUser(userID uint) error

	// Utility operations
	Close() error
}

// StorageConfig holds configuration for table names and database settings
type StorageConfig struct {
	// Table names
	UsersTable          string `json:"users_table"`
	SessionsTable       string `json:"sessions_table"`
	SecurityEventsTable string `json:"security_events_table"`

	// Required user columns mapping
	UserColumns UserColumnMapping `json:"user_columns"`

	// Required session columns mapping
	SessionColumns SessionColumnMapping `json:"session_columns"`

	// Required security event columns mapping
	SecurityEventColumns SecurityEventColumnMapping `json:"security_event_columns"`

	// Multi-tenant configuration
	MultiTenant MultiTenantConfig `json:"multi_tenant"`
}

// UserColumnMapping maps logical user fields to actual database column names
type UserColumnMapping struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Name         string `json:"name"`
	AvatarURL    string `json:"avatar_url"`
	Provider     string `json:"provider"`
	ProviderID   string `json:"provider_id"`

	// Email Security
	EmailVerified     string `json:"email_verified"`
	EmailVerifiedAt   string `json:"email_verified_at"`
	VerificationToken string `json:"verification_token"`

	// Password Security
	PasswordResetToken     string `json:"password_reset_token"`
	PasswordResetExpiresAt string `json:"password_reset_expires_at"`
	PasswordChangedAt      string `json:"password_changed_at"`

	// Login Security
	LoginAttempts     string `json:"login_attempts"`
	LastFailedLoginAt string `json:"last_failed_login_at"`
	LockedUntil       string `json:"locked_until"`
	LastLoginAt       string `json:"last_login_at"`

	// Location & Device Tracking
	LastKnownIP       string `json:"last_known_ip"`
	LastLoginLocation string `json:"last_login_location"`

	// Two-Factor Authentication
	TwoFactorEnabled string `json:"two_factor_enabled"`
	TwoFactorSecret  string `json:"two_factor_secret"`
	BackupCodes      string `json:"backup_codes"`

	// Account Security
	IsActive      string `json:"is_active"`
	IsSuspended   string `json:"is_suspended"`
	SuspendedAt   string `json:"suspended_at"`
	SuspendReason string `json:"suspend_reason"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// SessionColumnMapping maps logical session fields to actual database column names
type SessionColumnMapping struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`

	// Device & Location Tracking
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent"`
	IPAddress         string `json:"ip_address"`
	Location          string `json:"location"`

	// Security Features
	IsActive          string `json:"is_active"`
	LastActivity      string `json:"last_activity"`
	RequiresTwoFactor string `json:"requires_two_factor"`
	TwoFactorVerified string `json:"two_factor_verified"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// SecurityEventColumnMapping maps logical security event fields to actual database column names
type SecurityEventColumnMapping struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	TenantID    string `json:"tenant_id"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	Location    string `json:"location"`
	Metadata    string `json:"metadata"`
	CreatedAt   string `json:"created_at"`
}

// DefaultStorageConfig returns a default configuration with standard table and column names
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		UsersTable:          "users",
		SessionsTable:       "sessions",
		SecurityEventsTable: "security_events",
		UserColumns: UserColumnMapping{
			ID:           "id",
			Email:        "email",
			PasswordHash: "password_hash",
			Name:         "name",
			AvatarURL:    "avatar_url",
			Provider:     "provider",
			ProviderID:   "provider_id",

			// Email Security
			EmailVerified:     "email_verified",
			EmailVerifiedAt:   "email_verified_at",
			VerificationToken: "verification_token",

			// Password Security
			PasswordResetToken:     "password_reset_token",
			PasswordResetExpiresAt: "password_reset_expires_at",
			PasswordChangedAt:      "password_changed_at",

			// Login Security
			LoginAttempts:     "login_attempts",
			LastFailedLoginAt: "last_failed_login_at",
			LockedUntil:       "locked_until",
			LastLoginAt:       "last_login_at",

			// Location & Device Tracking
			LastKnownIP:       "last_known_ip",
			LastLoginLocation: "last_login_location",

			// Two-Factor Authentication
			TwoFactorEnabled: "two_factor_enabled",
			TwoFactorSecret:  "two_factor_secret",
			BackupCodes:      "backup_codes",

			// Account Security
			IsActive:      "is_active",
			IsSuspended:   "is_suspended",
			SuspendedAt:   "suspended_at",
			SuspendReason: "suspend_reason",

			CreatedAt: "created_at",
			UpdatedAt: "updated_at",
		},
		SessionColumns: SessionColumnMapping{
			ID:        "id",
			UserID:    "user_id",
			Token:     "token",
			ExpiresAt: "expires_at",

			// Device & Location Tracking
			DeviceFingerprint: "device_fingerprint",
			UserAgent:         "user_agent",
			IPAddress:         "ip_address",
			Location:          "location",

			// Security Features
			IsActive:          "is_active",
			LastActivity:      "last_activity",
			RequiresTwoFactor: "requires_two_factor",
			TwoFactorVerified: "two_factor_verified",

			CreatedAt: "created_at",
			UpdatedAt: "updated_at",
		},
		SecurityEventColumns: SecurityEventColumnMapping{
			ID:          "id",
			UserID:      "user_id",
			TenantID:    "tenant_id",
			EventType:   "event_type",
			Description: "description",
			IPAddress:   "ip_address",
			UserAgent:   "user_agent",
			Location:    "location",
			Metadata:    "metadata",
			CreatedAt:   "created_at",
		},
		MultiTenant: DefaultMultiTenantConfig(),
	}
}
