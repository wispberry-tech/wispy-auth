package auth

import (
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/wispberry-tech/wispy-auth/storage"
)

// ReferralCode is an alias to the storage ReferralCode type
type ReferralCode = storage.ReferralCode

// UserReferral is an alias to the storage UserReferral type
type UserReferral = storage.UserReferral

// Referral code generation and validation functions

// generateReferralCode creates a new referral code with the configured format
func (a *AuthService) generateReferralCode() string {
	config := a.securityConfig
	length := config.ReferralCodeLength
	if length <= 0 {
		length = 8 // Default length
	}

	// Generate random alphanumeric string
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, length)
	for i := range code {
		code[i] = charset[rand.Intn(len(charset))]
	}

	// Add prefix if configured
	result := string(code)
	if config.ReferralCodePrefix != "" {
		result = config.ReferralCodePrefix + result
	}

	return result
}

// GenerateReferralCodeRequest represents a request to generate a referral code
type GenerateReferralCodeRequest struct {
	UserID   uint `json:"user_id"`
	TenantID uint `json:"tenant_id"`
	MaxUses  int  `json:"max_uses,omitempty"` // Default: 1
}

// GenerateReferralCodeResponse represents the response for referral code generation
type GenerateReferralCodeResponse struct {
	Code        string     `json:"code"`
	MaxUses     int        `json:"max_uses"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	StatusCode  int        `json:"-"`
	Error       string     `json:"error,omitempty"`
}

// GenerateReferralCode creates a new referral code for a user
func (a *AuthService) GenerateReferralCode(req GenerateReferralCodeRequest) GenerateReferralCodeResponse {
	// Get user to validate they exist
	_, err := a.storage.GetUserByID(req.UserID)
	if err != nil {
		slog.Error("Failed to get user for referral code generation", "user_id", req.UserID, "error", err)
		return GenerateReferralCodeResponse{
			StatusCode: 404,
			Error:      "User not found",
		}
	}

	// Get user's role in the specified tenant to check limits
	userTenants, err := a.storage.GetUserTenants(req.UserID)
	if err != nil {
		slog.Error("Failed to get user tenants for referral code generation", "user_id", req.UserID, "error", err)
		return GenerateReferralCodeResponse{
			StatusCode: 500,
			Error:      "Failed to validate user permissions",
		}
	}

	// Find the user's role in the specified tenant
	var userRoleID uint
	var roleName string
	found := false
	for _, ut := range userTenants {
		if ut.TenantID == req.TenantID {
			userRoleID = ut.RoleID
			if ut.Role != nil {
				roleName = ut.Role.Name
			} else {
				// Get role name if not populated
				role, err := a.storage.GetRoleByID(ut.RoleID)
				if err != nil {
					slog.Error("Failed to get role for referral code generation", "role_id", ut.RoleID, "error", err)
					continue
				}
				roleName = role.Name
			}
			found = true
			break
		}
	}

	if !found {
		// Use default role if user not in tenant
		roleName = a.securityConfig.DefaultUserRoleName
		if roleName == "" {
			roleName = "default-user"
		}

		// Try to find the default role
		roles, err := a.storage.GetRolesByTenant(req.TenantID)
		if err != nil {
			slog.Error("Failed to get tenant roles", "tenant_id", req.TenantID, "error", err)
			return GenerateReferralCodeResponse{
				StatusCode: 500,
				Error:      "Failed to validate user permissions",
			}
		}

		for _, role := range roles {
			if role.Name == roleName {
				userRoleID = role.ID
				found = true
				break
			}
		}

		if !found {
			return GenerateReferralCodeResponse{
				StatusCode: 403,
				Error:      "User does not have permission to generate referral codes in this tenant",
			}
		}
	}

	// Check role-based limits
	maxInvitees := a.securityConfig.MaxInviteesPerRole[roleName]
	if maxInvitees > 0 {
		currentCount, err := a.storage.CountActiveReferralsByUserRole(req.UserID, userRoleID)
		if err != nil {
			slog.Error("Failed to count active referrals", "user_id", req.UserID, "role_id", userRoleID, "error", err)
			return GenerateReferralCodeResponse{
				StatusCode: 500,
				Error:      "Failed to validate referral limits",
			}
		}

		if currentCount >= maxInvitees {
			return GenerateReferralCodeResponse{
				StatusCode: 403,
				Error:      fmt.Sprintf("Referral limit reached. Maximum allowed: %d", maxInvitees),
			}
		}
	}

	// Generate unique code
	var code string
	var attempts int
	for attempts < 10 { // Limit attempts to prevent infinite loop
		code = a.generateReferralCode()

		// Check if code already exists
		existing, err := a.storage.GetReferralCodeByCode(code)
		if err != nil && err.Error() != "referral code not found" {
			slog.Error("Failed to check referral code uniqueness", "code", code, "error", err)
			return GenerateReferralCodeResponse{
				StatusCode: 500,
				Error:      "Failed to generate referral code",
			}
		}

		if existing == nil {
			break // Code is unique
		}

		attempts++
	}

	if attempts >= 10 {
		slog.Error("Failed to generate unique referral code after 10 attempts")
		return GenerateReferralCodeResponse{
			StatusCode: 500,
			Error:      "Failed to generate unique referral code",
		}
	}

	// Set max uses
	maxUses := req.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}

	// Calculate expiry
	var expiresAt *time.Time
	if a.securityConfig.ReferralCodeExpiry > 0 {
		expiry := time.Now().Add(a.securityConfig.ReferralCodeExpiry)
		expiresAt = &expiry
	}

	// Create referral code
	referralCode := &ReferralCode{
		Code:              code,
		GeneratedByUserID: req.UserID,
		GeneratedByRoleID: userRoleID,
		TenantID:          req.TenantID,
		MaxUses:           maxUses,
		CurrentUses:       0,
		ExpiresAt:         expiresAt,
		IsActive:          true,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	err = a.storage.CreateReferralCode(referralCode)
	if err != nil {
		slog.Error("Failed to create referral code", "code", code, "user_id", req.UserID, "error", err)
		return GenerateReferralCodeResponse{
			StatusCode: 500,
			Error:      "Failed to create referral code",
		}
	}

	// Log security event
	a.storage.CreateSecurityEvent(&SecurityEvent{
		UserID:      &req.UserID,
		TenantID:    &req.TenantID,
		EventType:   "referral_code_generated",
		Description: fmt.Sprintf("Referral code '%s' generated with %d max uses", code, maxUses),
		CreatedAt:   time.Now(),
	})

	slog.Info("Referral code generated successfully",
		"code", code,
		"user_id", req.UserID,
		"tenant_id", req.TenantID,
		"role", roleName,
		"max_uses", maxUses,
	)

	return GenerateReferralCodeResponse{
		Code:       code,
		MaxUses:    maxUses,
		ExpiresAt:  expiresAt,
		StatusCode: 201,
	}
}

// ValidateReferralCode checks if a referral code is valid and can be used
func (a *AuthService) ValidateReferralCode(code string, tenantID uint) (*ReferralCode, error) {
	if code == "" {
		return nil, fmt.Errorf("referral code is required")
	}

	// Clean up the code (remove spaces, convert to uppercase)
	code = strings.ToUpper(strings.TrimSpace(code))

	// Get referral code from storage
	referralCode, err := a.storage.GetReferralCodeByCode(code)
	if err != nil {
		slog.Warn("Invalid referral code attempted", "code", code, "tenant_id", tenantID)
		return nil, fmt.Errorf("invalid referral code")
	}

	// Check if code belongs to the same tenant
	if referralCode.TenantID != tenantID {
		slog.Warn("Referral code used in wrong tenant", "code", code, "expected_tenant", tenantID, "actual_tenant", referralCode.TenantID)
		return nil, fmt.Errorf("invalid referral code")
	}

	// Check if code is active
	if !referralCode.IsActive {
		slog.Warn("Inactive referral code attempted", "code", code)
		return nil, fmt.Errorf("referral code is no longer active")
	}

	// Check expiry
	if referralCode.ExpiresAt != nil && time.Now().After(*referralCode.ExpiresAt) {
		slog.Warn("Expired referral code attempted", "code", code, "expired_at", referralCode.ExpiresAt)
		return nil, fmt.Errorf("referral code has expired")
	}

	// Check usage limits
	if referralCode.CurrentUses >= referralCode.MaxUses {
		slog.Warn("Referral code usage limit exceeded", "code", code, "current_uses", referralCode.CurrentUses, "max_uses", referralCode.MaxUses)
		return nil, fmt.Errorf("referral code usage limit exceeded")
	}

	return referralCode, nil
}

// UseReferralCode increments the usage count and creates a referral relationship
func (a *AuthService) UseReferralCode(referralCode *ReferralCode, referredUserID uint) error {
	// Create user referral relationship
	userReferral := &UserReferral{
		ReferrerUserID: referralCode.GeneratedByUserID,
		ReferredUserID: referredUserID,
		ReferralCodeID: referralCode.ID,
		ReferrerRoleID: referralCode.GeneratedByRoleID,
		TenantID:       referralCode.TenantID,
		CreatedAt:      time.Now(),
	}

	err := a.storage.CreateUserReferral(userReferral)
	if err != nil {
		return fmt.Errorf("failed to create referral relationship: %w", err)
	}

	// Increment usage count
	referralCode.CurrentUses++
	referralCode.UpdatedAt = time.Now()

	// Deactivate if max uses reached
	if referralCode.CurrentUses >= referralCode.MaxUses {
		referralCode.IsActive = false
	}

	err = a.storage.UpdateReferralCode(referralCode)
	if err != nil {
		return fmt.Errorf("failed to update referral code usage: %w", err)
	}

	// Log security event
	a.storage.CreateSecurityEvent(&SecurityEvent{
		UserID:      &referredUserID,
		TenantID:    &referralCode.TenantID,
		EventType:   "referral_code_used",
		Description: fmt.Sprintf("User referred by code '%s' from user %d", referralCode.Code, referralCode.GeneratedByUserID),
		CreatedAt:   time.Now(),
	})

	slog.Info("Referral code used successfully",
		"code", referralCode.Code,
		"referrer_user_id", referralCode.GeneratedByUserID,
		"referred_user_id", referredUserID,
		"tenant_id", referralCode.TenantID,
	)

	return nil
}

// GetMyReferralCodes returns all referral codes generated by a user
func (a *AuthService) GetMyReferralCodes(userID uint) ([]*ReferralCode, error) {
	return a.storage.GetReferralCodesByUser(userID)
}

// GetMyReferrals returns all users referred by a user
func (a *AuthService) GetMyReferrals(userID uint) ([]*UserReferral, error) {
	return a.storage.GetUserReferralsByReferrer(userID)
}

// GetReferralStats returns referral statistics for a user
func (a *AuthService) GetReferralStats(userID uint) (totalReferred int, activeReferrals int, err error) {
	return a.storage.GetReferralStatsByUser(userID)
}