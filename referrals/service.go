package referrals

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/wispberry-tech/wispy-auth/core"
)

// AuthService extends the core auth service with referral functionality
// It uses composition to wrap the core service and add referral features
type AuthService struct {
	*core.AuthService // Embed core auth service
	storage           Storage
	config            Config
}

// NewAuthService creates a new referral-enabled auth service
// It takes a core auth service and extends it with referral functionality
func NewAuthService(coreService *core.AuthService, storage Storage, config Config) *AuthService {
	return &AuthService{
		AuthService: coreService,
		storage:     storage,
		config:      config,
	}
}

// GenerateReferralCode creates a new referral code for a user
func (a *AuthService) GenerateReferralCode(userID uint, options GenerateCodeOptions) (*ReferralCode, error) {
	// Check if user can create more codes
	if a.config.MaxCodesPerUser > 0 {
		activeCount, err := a.storage.CountActiveReferralCodes(userID)
		if err != nil {
			return nil, fmt.Errorf("failed to count active codes: %w", err)
		}

		if activeCount >= a.config.MaxCodesPerUser {
			return nil, fmt.Errorf("user has reached maximum number of referral codes (%d)", a.config.MaxCodesPerUser)
		}
	}

	// Generate or use provided code
	var code string
	var err error

	if options.CustomCode != "" && a.config.AllowCustomCodes {
		// Validate custom code format (basic validation)
		if len(options.CustomCode) < 3 || len(options.CustomCode) > 50 {
			return nil, fmt.Errorf("custom code must be between 3 and 50 characters")
		}

		// Check if code is available
		available, err := a.storage.CheckCodeAvailability(options.CustomCode)
		if err != nil {
			return nil, fmt.Errorf("failed to check code availability: %w", err)
		}

		if !available {
			return nil, fmt.Errorf("code '%s' is already taken", options.CustomCode)
		}

		code = options.CustomCode
	} else {
		// Generate random code
		code, err = a.generateRandomCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate code: %w", err)
		}

		// Ensure uniqueness
		maxAttempts := 10
		for i := 0; i < maxAttempts; i++ {
			available, err := a.storage.CheckCodeAvailability(code)
			if err != nil {
				return nil, fmt.Errorf("failed to check code availability: %w", err)
			}

			if available {
				break
			}

			// Generate new code
			code, err = a.generateRandomCode()
			if err != nil {
				return nil, fmt.Errorf("failed to generate code: %w", err)
			}

			if i == maxAttempts-1 {
				return nil, fmt.Errorf("failed to generate unique code after %d attempts", maxAttempts)
			}
		}
	}

	// Set defaults from config if not specified
	maxUses := options.MaxUses
	if maxUses == 0 {
		maxUses = a.config.DefaultMaxUses
	}

	var expiresAt *time.Time
	if options.ExpiresAt != nil {
		expiresAt = options.ExpiresAt
	} else if a.config.DefaultExpiry > 0 {
		expiry := time.Now().Add(a.config.DefaultExpiry)
		expiresAt = &expiry
	}

	// Create referral code
	referralCode := &ReferralCode{
		Code:        code,
		GeneratedBy: userID,
		MaxUses:     maxUses,
		CurrentUses: 0,
		IsActive:    true,
		ExpiresAt:   expiresAt,
	}

	if err := a.storage.CreateReferralCode(referralCode); err != nil {
		return nil, fmt.Errorf("failed to create referral code: %w", err)
	}

	slog.Info("Referral code created",
		"user_id", userID,
		"code", code,
		"max_uses", maxUses,
		"expires_at", expiresAt)

	return referralCode, nil
}

// ValidateAndUseReferralCode validates a referral code and marks it as used
// Returns the referral code if valid, nil if invalid/unusable
func (a *AuthService) ValidateAndUseReferralCode(code string, newUserID uint) (*ReferralCode, error) {
	// Get and validate the referral code
	referralCode, err := a.storage.ValidateReferralCode(code)
	if err != nil {
		return nil, fmt.Errorf("failed to validate referral code: %w", err)
	}

	if referralCode == nil {
		return nil, nil // Code is invalid or unusable
	}

	// Prevent self-referral
	if referralCode.GeneratedBy == newUserID {
		return nil, fmt.Errorf("users cannot use their own referral codes")
	}

	// Check if user was already referred
	existingRel, err := a.storage.GetReferralRelationshipsByReferred(newUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing referral relationships: %w", err)
	}

	if len(existingRel) > 0 {
		return nil, fmt.Errorf("user has already been referred")
	}

	// Create referral relationship
	relationship := &ReferralRelationship{
		ReferrerUserID: referralCode.GeneratedBy,
		ReferredUserID: newUserID,
		ReferralCodeID: referralCode.ID,
	}

	if err := a.storage.CreateReferralRelationship(relationship); err != nil {
		return nil, fmt.Errorf("failed to create referral relationship: %w", err)
	}

	// Increment code usage
	if err := a.storage.IncrementReferralCodeUse(referralCode.ID); err != nil {
		return nil, fmt.Errorf("failed to increment code usage: %w", err)
	}

	// Check if code should be deactivated (reached max uses)
	if referralCode.MaxUses > 0 && referralCode.CurrentUses+1 >= referralCode.MaxUses {
		if err := a.storage.DeactivateReferralCode(referralCode.ID); err != nil {
			slog.Error("Failed to deactivate referral code", "code_id", referralCode.ID, "error", err)
		}
	}

	slog.Info("Referral code used successfully",
		"code", code,
		"referrer_id", referralCode.GeneratedBy,
		"referred_id", newUserID,
		"total_uses", referralCode.CurrentUses+1)

	// Update current uses for return value
	referralCode.CurrentUses++

	return referralCode, nil
}

// GetUserReferralCodes returns all referral codes created by a user
func (a *AuthService) GetUserReferralCodes(userID uint) ([]*ReferralCode, error) {
	return a.storage.GetReferralCodesByUser(userID)
}

// GetUserReferralStats returns referral statistics for a user
func (a *AuthService) GetUserReferralStats(userID uint) (*ReferralStats, error) {
	return a.storage.GetReferralStats(userID)
}

// GetReferralRelationships returns users referred by the given user
func (a *AuthService) GetReferralRelationships(userID uint) ([]*ReferralRelationship, error) {
	return a.storage.GetReferralRelationshipsByReferrer(userID)
}

// GetTopReferrers returns the top referrers by number of successful referrals
func (a *AuthService) GetTopReferrers(limit int) ([]*ReferralStats, error) {
	return a.storage.GetTopReferrers(limit)
}

// DeactivateReferralCode deactivates a referral code
func (a *AuthService) DeactivateReferralCode(userID uint, codeID uint) error {
	// Get the code to verify ownership
	code, err := a.storage.GetReferralCodeByID(codeID)
	if err != nil {
		return fmt.Errorf("failed to get referral code: %w", err)
	}

	if code == nil {
		return fmt.Errorf("referral code not found")
	}

	if code.GeneratedBy != userID {
		return fmt.Errorf("user does not own this referral code")
	}

	return a.storage.DeactivateReferralCode(codeID)
}

// generateRandomCode generates a random referral code
func (a *AuthService) generateRandomCode() (string, error) {
	// Generate random bytes
	bytes := make([]byte, a.config.CodeLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode to base64 and clean up
	code := base64.URLEncoding.EncodeToString(bytes)

	// Remove padding and make uppercase for readability
	code = strings.TrimRight(code, "=")
	code = strings.ToUpper(code)

	// Truncate to desired length
	if len(code) > a.config.CodeLength {
		code = code[:a.config.CodeLength]
	}

	// Add prefix if configured
	if a.config.CodePrefix != "" {
		code = a.config.CodePrefix + code
	}

	return code, nil
}

// GenerateCodeOptions contains options for generating referral codes
type GenerateCodeOptions struct {
	CustomCode string     `json:"custom_code,omitempty"` // Custom code to use (if allowed)
	MaxUses    int        `json:"max_uses"`              // Maximum uses (0 = use default)
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`  // Expiration time (nil = use default)
}