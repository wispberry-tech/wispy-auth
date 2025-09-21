package auth

import (
	"errors"
)

var (
	ErrSessionNotFound  = errors.New("session not found")
	ErrInvalidSession   = errors.New("invalid session")
	ErrEmailNotVerified = errors.New("email not verified")
)



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
	Username     string `json:"username"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
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
			Username:     "username",
			FirstName:    "first_name",
			LastName:     "last_name",
			PasswordHash: "password_hash",
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
