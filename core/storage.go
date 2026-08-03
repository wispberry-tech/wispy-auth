package core

import (
	"context"
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
	LastLoginIP       *string    `json:"last_login_ip,omitempty"`
	LastFailedLoginAt *time.Time `json:"last_failed_login_at,omitempty"`
	LastFailedLoginIP *string    `json:"last_failed_login_ip,omitempty"`

	// Password Security
	PasswordChangedAt   *time.Time `json:"password_changed_at,omitempty"`
	ForcePasswordChange bool       `json:"force_password_change"`

	// 2FA Settings
	TwoFactorEnabled     bool       `json:"two_factor_enabled"`
	TwoFactorSecret      string     `json:"-"` // Hidden from JSON
	TwoFactorVerifiedAt  *time.Time `json:"two_factor_verified_at,omitempty"`

	// Session Security
	ConcurrentSessions int    `json:"concurrent_sessions"`
	LastSessionToken   string `json:"last_session_token"`

	// Device Tracking
	DeviceFingerprint string `json:"device_fingerprint"`
	KnownDevices      string `json:"known_devices"` // JSON string

	// Security Metadata
	SecurityVersion         int `json:"security_version"`
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
	IsActive       bool      `json:"is_active"`
	LastAccessedAt time.Time `json:"last_accessed_at"`

	CreatedAt time.Time `json:"created_at"`
}

// SecurityEvent represents security-related events for audit logging
type SecurityEvent struct {
	ID     uint  `json:"id"`
	UserID *uint `json:"user_id,omitempty"`

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

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        uint       `json:"id"`
	UserID    uint       `json:"user_id"`
	Token     string     `json:"token"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// TwoFactorCode represents a temporary 2FA verification code
type TwoFactorCode struct {
	ID        uint       `json:"id"`
	UserID    uint       `json:"user_id"`
	Code      string     `json:"code"`      // 6-digit code
	CodeType  string     `json:"code_type"` // "enable", "login", "disable"
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// TwoFactorBackupCode represents a backup 2FA code
type TwoFactorBackupCode struct {
	ID        uint       `json:"id"`
	UserID    uint       `json:"user_id"`
	Code      string     `json:"code"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// RefreshToken represents a refresh token for session renewal
type RefreshToken struct {
	ID         uint       `json:"id"`
	Token      string     `json:"token"`
	UserID     uint       `json:"user_id"`
	SessionID  uint       `json:"session_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// UserStore defines core user identity and security operations.
type UserStore interface {
	// User operations - core identity only
	CreateUser(ctx context.Context, user *User) error
	GetUserByEmail(ctx context.Context, email, provider string) (*User, error)
	GetUserByEmailAnyProvider(ctx context.Context, email string) (*User, error)
	GetUserByProviderID(ctx context.Context, provider, providerID string) (*User, error)
	GetUserByID(ctx context.Context, id uint) (*User, error)
	GetUserByUUID(ctx context.Context, uuid string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error

	// User Security operations - separate and explicit
	CreateUserSecurity(ctx context.Context, security *UserSecurity) error
	GetUserSecurity(ctx context.Context, userID uint) (*UserSecurity, error)
	UpdateUserSecurity(ctx context.Context, security *UserSecurity) error

	// Optimized methods for common security operations
	IncrementLoginAttempts(ctx context.Context, userID uint) error
	ResetLoginAttempts(ctx context.Context, userID uint) error
	SetUserLocked(ctx context.Context, userID uint, until time.Time) error
	UpdateLastLogin(ctx context.Context, userID uint, ipAddress *string) error

	// Transactional operations for complex multi-table operations
	CreateUserWithSecurity(ctx context.Context, user *User, security *UserSecurity) error
	HandleFailedLogin(ctx context.Context, userID uint, maxAttempts int, lockoutDuration time.Duration) (bool, error) // returns (wasLocked, error)
}

// SessionStore defines session lifecycle operations.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, token string) (*Session, error)
	GetUserSessions(ctx context.Context, userID uint) ([]*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	DeleteSession(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID uint) error
	CleanupExpiredSessions(ctx context.Context) error
	CountActiveSessions(ctx context.Context, userID uint) (int, error)
}

// OAuthStateStore defines OAuth state lifecycle operations.
type OAuthStateStore interface {
	StoreOAuthState(ctx context.Context, state *OAuthState) error
	GetOAuthState(ctx context.Context, state string) (*OAuthState, error)
	DeleteOAuthState(ctx context.Context, state string) error
	CleanupExpiredOAuthStates(ctx context.Context) error
}

// SecurityEventStore defines security audit log operations.
type SecurityEventStore interface {
	CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error
	GetSecurityEvents(ctx context.Context, userID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error)
	GetSecurityEventsByUser(ctx context.Context, userID uint, limit int, offset int) ([]*SecurityEvent, error)
}

// PasswordResetTokenStore defines password reset token operations.
type PasswordResetTokenStore interface {
	CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error)
	UsePasswordResetToken(ctx context.Context, token string) error
	CleanupExpiredPasswordResetTokens(ctx context.Context) error
}

// TwoFactorStore defines 2FA code and backup code operations.
type TwoFactorStore interface {
	// 2FA Code operations
	Create2FACode(ctx context.Context, code *TwoFactorCode) error
	Get2FACode(ctx context.Context, userID uint, code string, codeType string) (*TwoFactorCode, error)
	GetLatestPending2FACode(ctx context.Context, code string, codeType string) (*TwoFactorCode, error)
	Use2FACode(ctx context.Context, userID uint, code string) error
	CleanupExpired2FACodes(ctx context.Context) error

	// Backup Code operations
	Create2FABackupCode(ctx context.Context, code *TwoFactorBackupCode) error
	Get2FABackupCodes(ctx context.Context, userID uint) ([]*TwoFactorBackupCode, error)
	GetBackupCodeByCode(ctx context.Context, code string) (*TwoFactorBackupCode, error)
	Use2FABackupCode(ctx context.Context, userID uint, code string) error
	Regenerate2FABackupCodes(ctx context.Context, userID uint) ([]*TwoFactorBackupCode, error)
}

// RefreshTokenStore defines refresh token lifecycle operations.
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, token *RefreshToken) error
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteUserRefreshTokens(ctx context.Context, userID uint) error
	CleanupExpiredRefreshTokens(ctx context.Context) error
}

// Storage defines the contract for core authentication data storage operations.
type Storage interface {
	UserStore
	SessionStore
	OAuthStateStore
	SecurityEventStore
	PasswordResetTokenStore
	TwoFactorStore
	RefreshTokenStore

	// Health check
	Ping() error
	Close() error
}
