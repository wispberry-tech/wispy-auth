package referrals

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Utilities provides utility functions for referral operations
type Utilities struct {
	storage Storage
	config  Config
}

// GenerateReferralCode creates a new referral code for a user
func (u *Utilities) GenerateReferralCode(userID uint, options GenerateOptions) (*ReferralCode, error) {
	// Check if user can create more codes
	if u.config.MaxCodesPerUser > 0 {
		activeCount, err := u.storage.CountActiveReferralCodes(userID)
		if err != nil {
			return nil, fmt.Errorf("failed to count active codes: %w", err)
		}

		if activeCount >= u.config.MaxCodesPerUser {
			return nil, fmt.Errorf("user has reached maximum number of referral codes (%d)", u.config.MaxCodesPerUser)
		}
	}

	// Generate or use provided code
	var code string
	var err error

	if options.CustomCode != "" && u.config.AllowCustomCodes {
		// Validate custom code format (basic validation)
		if len(options.CustomCode) < 3 || len(options.CustomCode) > 50 {
			return nil, fmt.Errorf("custom code must be between 3 and 50 characters")
		}

		// Check if code is available
		available, err := u.storage.CheckCodeAvailability(options.CustomCode)
		if err != nil {
			return nil, fmt.Errorf("failed to check code availability: %w", err)
		}

		if !available {
			return nil, fmt.Errorf("code '%s' is already taken", options.CustomCode)
		}

		code = options.CustomCode
	} else {
		// Generate random code
		code, err = u.generateRandomCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate code: %w", err)
		}

		// Ensure uniqueness
		maxAttempts := 10
		for i := 0; i < maxAttempts; i++ {
			available, err := u.storage.CheckCodeAvailability(code)
			if err != nil {
				return nil, fmt.Errorf("failed to check code availability: %w", err)
			}

			if available {
				break
			}

			// Generate new code
			code, err = u.generateRandomCode()
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
		maxUses = u.config.DefaultMaxUses
	}

	// Create the referral code record
	referralCode := &ReferralCode{
		Code:        code,
		GeneratedBy: userID,
		MaxUses:     maxUses,
		CurrentUses: 0,
		IsActive:    true,
		ExpiresAt:   options.ExpiresAt,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Store in database
	err = u.storage.CreateReferralCode(referralCode)
	if err != nil {
		return nil, fmt.Errorf("failed to create referral code: %w", err)
	}

	// Get the created code with ID populated
	return u.storage.GetReferralCodeByCode(referralCode.Code)
}

// ValidateReferralCode checks if a referral code is valid and available for use
func (u *Utilities) ValidateReferralCode(code string, userID uint) (*ReferralCode, error) {
	if code == "" {
		return nil, fmt.Errorf("referral code is required")
	}

	// Get the referral code
	referralCode, err := u.storage.GetReferralCodeByCode(code)
	if err != nil {
		return nil, fmt.Errorf("invalid referral code")
	}

	// Check if code is active
	if !referralCode.IsActive {
		return nil, fmt.Errorf("referral code is not active")
	}

	// Check if code has expired
	if referralCode.ExpiresAt != nil && time.Now().After(*referralCode.ExpiresAt) {
		return nil, fmt.Errorf("referral code has expired")
	}

	// Check if code has reached max uses
	if referralCode.MaxUses > 0 && referralCode.CurrentUses >= referralCode.MaxUses {
		return nil, fmt.Errorf("referral code has reached maximum uses")
	}

	// Prevent self-referral
	if referralCode.GeneratedBy == userID {
		return nil, fmt.Errorf("cannot use your own referral code")
	}

	// Check if user has already been referred (prevent duplicate referrals)
	relationships, err := u.storage.GetReferralRelationshipsByReferred(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check referral history: %w", err)
	}
	if len(relationships) > 0 {
		return nil, fmt.Errorf("user has already been referred")
	}

	return referralCode, nil
}

// ProcessReferralSignup processes the referral when a new user signs up
func (u *Utilities) ProcessReferralSignup(referralCode *ReferralCode, newUserID uint) error {
	// Create referral relationship
	relationship := &ReferralRelationship{
		ReferrerUserID: referralCode.GeneratedBy,
		ReferredUserID: newUserID,
		ReferralCodeID: referralCode.ID,
		CreatedAt:      time.Now(),
	}

	if err := u.storage.CreateReferralRelationship(relationship); err != nil {
		return fmt.Errorf("failed to create referral relationship: %w", err)
	}

	// Update referral code usage count
	referralCode.CurrentUses++
	referralCode.UpdatedAt = time.Now()

	// Deactivate code if it has reached max uses
	if referralCode.MaxUses > 0 && referralCode.CurrentUses >= referralCode.MaxUses {
		referralCode.IsActive = false
	}

	if err := u.storage.UpdateReferralCode(referralCode); err != nil {
		return fmt.Errorf("failed to update referral code: %w", err)
	}

	return nil
}

// GetUserReferralCodes retrieves all referral codes for a user
func (u *Utilities) GetUserReferralCodes(userID uint) ([]*ReferralCode, error) {
	return u.storage.GetReferralCodesByUser(userID)
}

// GetReferralStats retrieves referral statistics for a user
func (u *Utilities) GetReferralStats(userID uint) (*ReferralStats, error) {
	return u.storage.GetReferralStats(userID)
}

// GetReferralRelationships retrieves referral relationships for a user
func (u *Utilities) GetReferralRelationships(userID uint) ([]*ReferralRelationship, error) {
	return u.storage.GetReferralRelationshipsByReferrer(userID)
}

// GetTopReferrers retrieves top referrers leaderboard
func (u *Utilities) GetTopReferrers(limit int) ([]*ReferralStats, error) {
	return u.storage.GetTopReferrers(limit)
}

// DeactivateReferralCode deactivates a referral code
func (u *Utilities) DeactivateReferralCode(userID uint, codeID uint) error {
	// Get the referral code to verify ownership
	code, err := u.storage.GetReferralCodeByID(codeID)
	if err != nil {
		return fmt.Errorf("referral code not found")
	}

	// Verify the user owns this code
	if code.GeneratedBy != userID {
		return fmt.Errorf("not authorized to deactivate this code")
	}

	// Deactivate the code
	code.IsActive = false
	code.UpdatedAt = time.Now()

	return u.storage.UpdateReferralCode(code)
}

// IsReferralRequired checks if referral codes are required for signup
func (u *Utilities) IsReferralRequired() bool {
	return u.config.RequireReferralCode
}

// ExtractReferralFromRequest extracts referral code from HTTP request
// It checks query parameters and JSON body
func (u *Utilities) ExtractReferralFromRequest(r *http.Request) string {
	// Check query parameter first
	if code := r.URL.Query().Get("referral_code"); code != "" {
		return code
	}

	// Check form data
	if code := r.FormValue("referral_code"); code != "" {
		return code
	}

	// For JSON requests, this would need to be handled by the caller
	// since we can't read the body multiple times
	return ""
}

// generateRandomCode generates a random referral code
func (u *Utilities) generateRandomCode() (string, error) {
	// Generate random bytes
	bytes := make([]byte, u.config.CodeLength*3/4+1) // Base64 expansion
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Encode to base64 and clean up
	code := base64.URLEncoding.EncodeToString(bytes)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, "_", "")
	code = strings.ReplaceAll(code, "=", "")

	// Truncate to desired length
	if len(code) > u.config.CodeLength {
		code = code[:u.config.CodeLength]
	}

	// Add prefix if configured
	if u.config.CodePrefix != "" {
		code = u.config.CodePrefix + code
	}

	return strings.ToUpper(code), nil
}
