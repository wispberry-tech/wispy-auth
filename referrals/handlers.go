package referrals

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wispberry-tech/wispy-auth/core"
)

// Request and Response Types

// SignUpWithReferralRequest represents a signup request with referral code
type SignUpWithReferralRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Password     string `json:"password" validate:"required,min=8"`
	Username     string `json:"username"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	ReferralCode string `json:"referral_code"` // Optional referral code
}

// SignUpWithReferralResponse represents the response for user registration with referral
type SignUpWithReferralResponse struct {
	Token        string        `json:"token"`                   // Session token for authentication
	User         *core.User    `json:"user"`                    // Created user information
	UsedReferral bool          `json:"used_referral"`           // Whether a referral code was used
	ReferralCode *ReferralCode `json:"referral_code,omitempty"` // Details of used referral code
	StatusCode   int           `json:"-"`                       // HTTP status code (not serialized)
	Error        string        `json:"error,omitempty"`         // Error message if any
}

// GenerateReferralCodeRequest represents a request to generate a referral code
type GenerateReferralCodeRequest struct {
	CustomCode string     `json:"custom_code,omitempty"` // Custom code (if allowed)
	MaxUses    int        `json:"max_uses"`              // Maximum uses (0 = default)
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`  // Expiration time
}

// GenerateReferralCodeResponse represents the response for code generation
type GenerateReferralCodeResponse struct {
	ReferralCode *ReferralCode `json:"referral_code"`   // Generated referral code
	StatusCode   int           `json:"-"`               // HTTP status code
	Error        string        `json:"error,omitempty"` // Error message if any
}

// GetReferralCodesResponse represents the response for getting user's referral codes
type GetReferralCodesResponse struct {
	ReferralCodes []*ReferralCode `json:"referral_codes"`  // User's referral codes
	StatusCode    int             `json:"-"`               // HTTP status code
	Error         string          `json:"error,omitempty"` // Error message if any
}

// GetReferralStatsResponse represents the response for getting referral statistics
type GetReferralStatsResponse struct {
	Stats      *ReferralStats `json:"stats"`           // Referral statistics
	StatusCode int            `json:"-"`               // HTTP status code
	Error      string         `json:"error,omitempty"` // Error message if any
}

// GetReferralRelationshipsResponse represents the response for getting referral relationships
type GetReferralRelationshipsResponse struct {
	Relationships []*ReferralRelationship `json:"relationships"`   // Referral relationships
	StatusCode    int                     `json:"-"`               // HTTP status code
	Error         string                  `json:"error,omitempty"` // Error message if any
}

// GetTopReferrersResponse represents the response for getting top referrers
type GetTopReferrersResponse struct {
	TopReferrers []*ReferralStats `json:"top_referrers"`   // Top referrer statistics
	StatusCode   int              `json:"-"`               // HTTP status code
	Error        string           `json:"error,omitempty"` // Error message if any
}

// DeactivateReferralCodeResponse represents the response for deactivating a referral code
type DeactivateReferralCodeResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code
	Error      string `json:"error,omitempty"` // Error message if any
}

// SignUpWithReferralHandler processes user registration with optional referral code
func (a *AuthService) SignUpWithReferralHandler(r *http.Request) SignUpWithReferralResponse {
	var req SignUpWithReferralRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode signup with referral request", "error", err)
		return SignUpWithReferralResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	// Check if referral code is required
	if a.config.RequireReferralCode && req.ReferralCode == "" {
		return SignUpWithReferralResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Referral code is required",
		}
	}

	// Validate referral code if provided
	var referralCode *ReferralCode
	if req.ReferralCode != "" {
		validCode, err := a.storage.ValidateReferralCode(req.ReferralCode)
		if err != nil {
			slog.Error("Failed to validate referral code", "error", err)
			return SignUpWithReferralResponse{
				StatusCode: http.StatusInternalServerError,
				Error:      "Internal server error",
			}
		}

		if validCode == nil {
			return SignUpWithReferralResponse{
				StatusCode: http.StatusBadRequest,
				Error:      "Invalid or expired referral code",
			}
		}

		referralCode = validCode
	}

	// Use core signup handler first
	coreRequest := &http.Request{
		Method: r.Method,
		Header: r.Header,
	}

	// Convert to core signup request format
	coreSignupReq := core.SignUpRequest{
		Email:     req.Email,
		Password:  req.Password,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	// Recreate request body for core handler
	_, _ = json.Marshal(coreSignupReq)
	coreRequest.Body = http.NoBody
	coreRequest.Header.Set("Content-Type", "application/json")

	// This is a simplified approach - in a real implementation you might need
	// to properly handle the request body or modify the core handler to accept structs directly

	// For now, let's implement the signup logic directly but use core validation

	// Check if user already exists
	existingUser, err := a.storage.GetUserByEmailAnyProvider(req.Email)
	if err != nil {
		slog.Error("Failed to check existing user", "error", err)
		return SignUpWithReferralResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	if existingUser != nil {
		slog.Debug("User already exists", "email", req.Email)
		return SignUpWithReferralResponse{
			StatusCode: http.StatusConflict,
			Error:      "User already exists",
		}
	}

	// Create user using core functionality (simplified)
	// In practice, you'd want to call the actual core signup logic
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		return SignUpWithReferralResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	user := &core.User{
		Email:         strings.ToLower(req.Email),
		Username:      req.Username,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		PasswordHash:  hashedPassword,
		Provider:      "email",
		EmailVerified: false,
		IsActive:      true,
		IsSuspended:   false,
	}

	// Create user security record
	userSecurity := &core.UserSecurity{
		LoginAttempts:           0,
		TwoFactorEnabled:        false,
		ConcurrentSessions:      0,
		SecurityVersion:         1,
		RiskScore:               0,
		SuspiciousActivityCount: 0,
	}

	// Create user and security record atomically in a transaction
	if err := a.storage.CreateUserWithSecurity(user, userSecurity); err != nil {
		slog.Error("Failed to create user with security", "error", err)
		return SignUpWithReferralResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to create user",
		}
	}

	// Process referral code if provided
	usedReferral := false
	if referralCode != nil {
		usedCode, err := a.ValidateAndUseReferralCode(req.ReferralCode, user.ID)
		if err != nil {
			slog.Error("Failed to process referral code", "error", err, "user_id", user.ID)
			// Don't fail signup, just log the error
		} else if usedCode != nil {
			usedReferral = true
			referralCode = usedCode
		}
	}

	// Create session (simplified - in practice use core session creation)
	sessionToken, err := generateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err)
		return SignUpWithReferralResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()
	deviceFingerprint := generateDeviceFingerprint(userAgent, ip)

	session := &core.Session{
		Token:             sessionToken,
		UserID:            user.ID,
		ExpiresAt:         calculateSessionExpiry(),
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
		IPAddress:         ip,
		IsActive:          true,
		LastAccessedAt:    time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		slog.Error("Failed to create session", "error", err)
		return SignUpWithReferralResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	// Clear password hash from response
	user.PasswordHash = ""

	slog.Info("User registered successfully with referral support",
		"user_id", user.ID,
		"email", user.Email,
		"used_referral", usedReferral,
		"referral_code", req.ReferralCode)

	return SignUpWithReferralResponse{
		StatusCode:   http.StatusCreated,
		Token:        sessionToken,
		User:         user,
		UsedReferral: usedReferral,
		ReferralCode: referralCode,
	}
}

// GenerateReferralCodeHandler creates a new referral code for the authenticated user
func (a *AuthService) GenerateReferralCodeHandler(r *http.Request) GenerateReferralCodeResponse {
	user := core.GetUserFromContext(r)
	if user == nil {
		return GenerateReferralCodeResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	var req GenerateReferralCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode generate referral code request", "error", err)
		return GenerateReferralCodeResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	options := GenerateCodeOptions{
		CustomCode: req.CustomCode,
		MaxUses:    req.MaxUses,
		ExpiresAt:  req.ExpiresAt,
	}

	code, err := a.GenerateReferralCode(user.ID, options)
	if err != nil {
		slog.Error("Failed to generate referral code", "error", err, "user_id", user.ID)
		return GenerateReferralCodeResponse{
			StatusCode: http.StatusBadRequest,
			Error:      err.Error(),
		}
	}

	return GenerateReferralCodeResponse{
		StatusCode:   http.StatusCreated,
		ReferralCode: code,
	}
}

// GetReferralCodesHandler returns all referral codes for the authenticated user
func (a *AuthService) GetReferralCodesHandler(r *http.Request) GetReferralCodesResponse {
	user := core.GetUserFromContext(r)
	if user == nil {
		return GetReferralCodesResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	codes, err := a.GetUserReferralCodes(user.ID)
	if err != nil {
		slog.Error("Failed to get referral codes", "error", err, "user_id", user.ID)
		return GetReferralCodesResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	return GetReferralCodesResponse{
		StatusCode:    http.StatusOK,
		ReferralCodes: codes,
	}
}

// GetReferralStatsHandler returns referral statistics for the authenticated user
func (a *AuthService) GetReferralStatsHandler(r *http.Request) GetReferralStatsResponse {
	user := core.GetUserFromContext(r)
	if user == nil {
		return GetReferralStatsResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	stats, err := a.GetUserReferralStats(user.ID)
	if err != nil {
		slog.Error("Failed to get referral stats", "error", err, "user_id", user.ID)
		return GetReferralStatsResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	return GetReferralStatsResponse{
		StatusCode: http.StatusOK,
		Stats:      stats,
	}
}

// GetReferralRelationshipsHandler returns users referred by the authenticated user
func (a *AuthService) GetReferralRelationshipsHandler(r *http.Request) GetReferralRelationshipsResponse {
	user := core.GetUserFromContext(r)
	if user == nil {
		return GetReferralRelationshipsResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	relationships, err := a.GetReferralRelationships(user.ID)
	if err != nil {
		slog.Error("Failed to get referral relationships", "error", err, "user_id", user.ID)
		return GetReferralRelationshipsResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	return GetReferralRelationshipsResponse{
		StatusCode:    http.StatusOK,
		Relationships: relationships,
	}
}

// GetTopReferrersHandler returns the top referrers
func (a *AuthService) GetTopReferrersHandler(r *http.Request) GetTopReferrersResponse {
	// Parse limit from query parameter
	limit := 10 // default
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	topReferrers, err := a.GetTopReferrers(limit)
	if err != nil {
		slog.Error("Failed to get top referrers", "error", err)
		return GetTopReferrersResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Internal server error",
		}
	}

	return GetTopReferrersResponse{
		StatusCode:   http.StatusOK,
		TopReferrers: topReferrers,
	}
}

// DeactivateReferralCodeHandler deactivates a referral code
func (a *AuthService) DeactivateReferralCodeHandler(r *http.Request, codeID string) DeactivateReferralCodeResponse {
	user := core.GetUserFromContext(r)
	if user == nil {
		return DeactivateReferralCodeResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	// Parse code ID
	id, err := strconv.ParseUint(codeID, 10, 32)
	if err != nil {
		return DeactivateReferralCodeResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid code ID",
		}
	}

	if err := a.DeactivateReferralCode(user.ID, uint(id)); err != nil {
		slog.Error("Failed to deactivate referral code", "error", err, "user_id", user.ID, "code_id", id)
		return DeactivateReferralCodeResponse{
			StatusCode: http.StatusBadRequest,
			Error:      err.Error(),
		}
	}

	return DeactivateReferralCodeResponse{
		StatusCode: http.StatusOK,
		Message:    "Referral code deactivated successfully",
	}
}
