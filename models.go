package auth

import "time"

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
