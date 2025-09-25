package referrals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/wispberry-tech/wispy-auth/core"
)

// RequireReferral middleware ensures that a referral code is provided and valid
func (m *MiddlewareProvider) RequireReferral(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract referral code from request
		var referralCode string

		// Check different sources for referral code
		if r.Method == "GET" {
			referralCode = r.URL.Query().Get("referral_code")
		} else {
			// Try to parse JSON body to extract referral code
			var body map[string]interface{}
			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&body); err == nil {
				if code, exists := body["referral_code"]; exists {
					if codeStr, ok := code.(string); ok {
						referralCode = codeStr
					}
				}
			}
		}

		if referralCode == "" {
			http.Error(w, "Referral code is required", http.StatusBadRequest)
			return
		}

		// Get user from context (if authenticated)
		user := core.GetUserFromContext(r)
		var userID uint = 0
		if user != nil {
			userID = user.ID
		}

		// Validate referral code
		utils := &Utilities{storage: m.storage, config: m.config}
		validCode, err := utils.ValidateReferralCode(referralCode, userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid referral code: %s", err.Error()), http.StatusBadRequest)
			return
		}

		// Add referral code to context
		ctx := context.WithValue(r.Context(), "referral_code", validCode)
		next(w, r.WithContext(ctx))
	}
}

// OptionalReferral middleware validates a referral code if provided, but doesn't require it
func (m *MiddlewareProvider) OptionalReferral(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract referral code from request
		var referralCode string

		// Check different sources for referral code
		if r.Method == "GET" {
			referralCode = r.URL.Query().Get("referral_code")
		} else {
			// Try to parse JSON body to extract referral code
			var body map[string]interface{}
			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&body); err == nil {
				if code, exists := body["referral_code"]; exists {
					if codeStr, ok := code.(string); ok {
						referralCode = codeStr
					}
				}
			}
		}

		// If no referral code provided, continue without validation
		if referralCode == "" {
			next(w, r)
			return
		}

		// Get user from context (if authenticated)
		user := core.GetUserFromContext(r)
		var userID uint = 0
		if user != nil {
			userID = user.ID
		}

		// Validate referral code
		utils := &Utilities{storage: m.storage, config: m.config}
		validCode, err := utils.ValidateReferralCode(referralCode, userID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid referral code: %s", err.Error()), http.StatusBadRequest)
			return
		}

		// Add referral code to context
		ctx := context.WithValue(r.Context(), "referral_code", validCode)
		next(w, r.WithContext(ctx))
	}
}

// ValidateReferral middleware only validates referral codes but doesn't extract them
func (m *MiddlewareProvider) ValidateReferral(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// This middleware assumes the referral code is already in context
		if code := getReferralCodeFromContext(r); code != nil {
			// Get user from context
			user := core.GetUserFromContext(r)
			var userID uint = 0
			if user != nil {
				userID = user.ID
			}

			// Re-validate the code (in case of state changes)
			utils := &Utilities{storage: m.storage, config: m.config}
			_, err := utils.ValidateReferralCode(code.Code, userID)
			if err != nil {
				http.Error(w, fmt.Sprintf("Referral code validation failed: %s", err.Error()), http.StatusBadRequest)
				return
			}
		}

		next(w, r)
	}
}

// TrackReferralUsage middleware tracks when referral codes are used
func (m *MiddlewareProvider) TrackReferralUsage(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Call the next handler first
		next(w, r)

		// After successful handler execution, track referral usage if applicable
		referralCode := getReferralCodeFromContext(r)
		if referralCode == nil {
			return
		}

		user := core.GetUserFromContext(r)
		if user == nil {
			return
		}

		// Process the referral usage
		utils := &Utilities{storage: m.storage, config: m.config}
		err := utils.ProcessReferralSignup(referralCode, user.ID)
		if err != nil {
			// Log error but don't fail the request since it's already processed
			// You might want to use proper logging here
			fmt.Printf("Failed to process referral usage: %v\n", err)
		}
	}
}

// Helper functions

// getReferralCodeFromContext retrieves the referral code from request context
func getReferralCodeFromContext(r *http.Request) *ReferralCode {
	if code, ok := r.Context().Value("referral_code").(*ReferralCode); ok {
		return code
	}
	return nil
}

// GetReferralCodeFromContext is a public helper for other packages
func GetReferralCodeFromContext(r *http.Request) *ReferralCode {
	return getReferralCodeFromContext(r)
}

// ReferralCodeRequired middleware can be used to ensure referral system requirements
func (m *MiddlewareProvider) ReferralCodeRequired() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !m.config.RequireReferralCode {
				next(w, r)
				return
			}

			// Check if referral code is in context
			if getReferralCodeFromContext(r) == nil {
				http.Error(w, "Referral code is required for this action", http.StatusBadRequest)
				return
			}

			next(w, r)
		}
	}
}

// WithReferralTracking adds referral tracking to any handler
func (m *MiddlewareProvider) WithReferralTracking(userIDParam string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r)

			// Extract user ID from URL parameters
			userIDStr := r.URL.Query().Get(userIDParam)
			if userIDStr == "" {
				return
			}

			userID, err := strconv.ParseUint(userIDStr, 10, 32)
			if err != nil {
				return
			}

			// Track referral if code is in context
			if referralCode := getReferralCodeFromContext(r); referralCode != nil {
				utils := &Utilities{storage: m.storage, config: m.config}
				err := utils.ProcessReferralSignup(referralCode, uint(userID))
				if err != nil {
					fmt.Printf("Failed to process referral: %v\n", err)
				}
			}
		}
	}
}
