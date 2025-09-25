package core

import (
	"time"
)

// User represents core user identity and authentication information.
type User struct {
	ID        uint   `json:"id"`
	UUID      string `json:"uuid"`
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

	// Login Security
	LoginAttempts     int        `json:"login_attempts"`
	LockedUntil       *time.Time `json:"locked_until,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP       string     `json:"last_login_ip,omitempty"`
	LastFailedLoginAt *time.Time `json:"last_failed_login_at,omitempty"`
	LastFailedLoginIP string     `json:"last_failed_login_ip,omitempty"`

	// Password Security
	PasswordChangedAt     *time.Time `json:"password_changed_at,omitempty"`
	ForcePasswordChange   bool       `json:"force_password_change"`

	// 2FA Settings
	TwoFactorEnabled    bool   `json:"two_factor_enabled"`
	TwoFactorSecret     string `json:"-"` // Hidden from JSON
	TwoFactorBackupCodes string `json:"-"` // Hidden from JSON
	TwoFactorVerifiedAt *time.Time `json:"two_factor_verified_at,omitempty"`

	// Session Security
	ConcurrentSessions  int    `json:"concurrent_sessions"`
	LastSessionToken    string `json:"last_session_token"`

	// Device Tracking
	DeviceFingerprint string `json:"device_fingerprint"`
	KnownDevices      string `json:"known_devices"` // JSON string

	// Security Metadata
	SecurityVersion          int `json:"security_version"`
	RiskScore               int `json:"risk_score"`
	SuspiciousActivityCount int `json:"suspicious_activity_count"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents a user session with enhanced security tracking
type Session struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`

	// Device & Location Tracking
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent"`
	IPAddress         string `json:"ip_address"`

	// Status
	IsActive      bool      `json:"is_active"`
	LastAccessedAt time.Time `json:"last_accessed_at"`

	CreatedAt time.Time `json:"created_at"`
}

// SecurityEvent represents security-related events for audit logging
type SecurityEvent struct {
	ID       uint   `json:"id"`
	UserID   *uint  `json:"user_id,omitempty"`

	// Event Details
	EventType   string `json:"event_type"`
	Description string `json:"description"`

	// Request Context
	IPAddress         string `json:"ip_address"`
	UserAgent         string `json:"user_agent"`
	DeviceFingerprint string `json:"device_fingerprint"`

	// Event Metadata
	Severity string `json:"severity"`
	Success  bool   `json:"success"`
	Metadata string `json:"metadata"` // JSON string

	CreatedAt time.Time `json:"created_at"`
}

// OAuthState represents OAuth state for CSRF protection
type OAuthState struct {
	ID          uint      `json:"id"`
	State       string    `json:"state"`
	CSRF        string    `json:"csrf"`
	Provider    string    `json:"provider"`
	RedirectURL string    `json:"redirect_url"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// Storage defines the contract for core authentication data storage operations
type Storage interface {
	// User operations - core identity only
	CreateUser(user *User) error
	GetUserByEmail(email, provider string) (*User, error)
	GetUserByEmailAnyProvider(email string) (*User, error)
	GetUserByProviderID(provider, providerID string) (*User, error)
	GetUserByID(id uint) (*User, error)
	GetUserByUUID(uuid string) (*User, error)
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

	// Security Event operations
	CreateSecurityEvent(event *SecurityEvent) error
	GetSecurityEvents(userID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error)
	GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error)

	// Health check
	Ping() error
	Close() error
}