package referrals

import (
	"time"

	"github.com/wispberry-tech/wispy-auth/core"
)

// ReferralCode represents a referral code that can be used for user signups
type ReferralCode struct {
	ID          uint       `json:"id"`
	Code        string     `json:"code"`         // The actual referral code
	GeneratedBy uint       `json:"generated_by"` // User ID who generated the code
	MaxUses     int        `json:"max_uses"`     // Maximum number of times code can be used (0 = unlimited)
	CurrentUses int        `json:"current_uses"` // Number of times code has been used
	IsActive    bool       `json:"is_active"`    // Whether the code is currently active
	ExpiresAt   *time.Time `json:"expires_at"`   // When the code expires (nil = never expires)
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`

	// Populated by joins
	GeneratedByUser *core.User `json:"generated_by_user,omitempty"`
}

// ReferralRelationship represents the relationship between a referrer and referred user
type ReferralRelationship struct {
	ID             uint      `json:"id"`
	ReferrerUserID uint      `json:"referrer_user_id"` // User who referred
	ReferredUserID uint      `json:"referred_user_id"` // User who was referred
	ReferralCodeID uint      `json:"referral_code_id"` // The referral code used
	CreatedAt      time.Time `json:"created_at"`

	// Populated by joins
	ReferrerUser *core.User    `json:"referrer_user,omitempty"`
	ReferredUser *core.User    `json:"referred_user,omitempty"`
	ReferralCode *ReferralCode `json:"referral_code,omitempty"`
}

// ReferralStats represents referral statistics for a user
type ReferralStats struct {
	UserID            uint `json:"user_id"`
	TotalReferred     int  `json:"total_referred"`     // Total number of users referred
	ActiveCodes       int  `json:"active_codes"`       // Number of active referral codes
	TotalCodesUsed    int  `json:"total_codes_used"`   // Total times all codes have been used
	SuccessfulSignups int  `json:"successful_signups"` // Number of successful signups from referrals
}

// GenerateOptions contains options for generating referral codes
type GenerateOptions struct {
	CustomCode string     `json:"custom_code,omitempty"` // Custom code (if allowed)
	MaxUses    int        `json:"max_uses"`              // Maximum uses (0 = default from config)
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`  // Expiration time
}

// Config contains configuration for the referrals extension
type Config struct {
	// Code generation settings
	CodeLength       int    `json:"code_length"`        // Length of generated codes (default: 8)
	CodePrefix       string `json:"code_prefix"`        // Optional prefix for branding (e.g., "REF")
	AllowCustomCodes bool   `json:"allow_custom_codes"` // Whether users can create custom codes

	// Usage limits
	MaxCodesPerUser int           `json:"max_codes_per_user"` // Max referral codes per user (0 = unlimited)
	DefaultMaxUses  int           `json:"default_max_uses"`   // Default max uses per code (0 = unlimited)
	DefaultExpiry   time.Duration `json:"default_expiry"`     // Default expiry duration (0 = never expires)

	// Requirements
	RequireReferralCode bool `json:"require_referral_code"` // Make referral codes mandatory for signup
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() Config {
	return Config{
		CodeLength:          8,
		CodePrefix:          "",
		AllowCustomCodes:    false,
		MaxCodesPerUser:     5,
		DefaultMaxUses:      0, // Unlimited uses by default
		DefaultExpiry:       0, // Never expires by default
		RequireReferralCode: false,
	}
}

// IsExpired checks if a referral code has expired
func (r *ReferralCode) IsExpired() bool {
	if r.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*r.ExpiresAt)
}

// IsUsable checks if a referral code can be used
func (r *ReferralCode) IsUsable() bool {
	if !r.IsActive {
		return false
	}

	if r.IsExpired() {
		return false
	}

	if r.MaxUses > 0 && r.CurrentUses >= r.MaxUses {
		return false
	}

	return true
}

// RemainingUses returns the number of times the code can still be used
func (r *ReferralCode) RemainingUses() int {
	if r.MaxUses == 0 {
		return -1 // Unlimited
	}
	remaining := r.MaxUses - r.CurrentUses
	if remaining < 0 {
		return 0
	}
	return remaining
}
