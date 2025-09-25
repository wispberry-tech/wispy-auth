package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/wispberry-tech/wispy-auth/core"
	"github.com/wispberry-tech/wispy-auth/referrals"
	referralstorage "github.com/wispberry-tech/wispy-auth/referrals/storage"
)

// SignupRequest represents the signup request with optional referral code
type SignupRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	Username     string `json:"username"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	ReferralCode string `json:"referral_code"` // Optional referral code
}

// SignupResponse represents the signup response
type SignupResponse struct {
	Token        string                  `json:"token"`
	User         *core.User              `json:"user"`
	UsedReferral bool                    `json:"used_referral"`
	ReferralCode *referrals.ReferralCode `json:"referral_code,omitempty"`
	Error        string                  `json:"error,omitempty"`
}

func main() {
	// Initialize storage that implements both core.Storage and referrals.Storage
	storage, err := referralstorage.NewSQLiteStorage("app.db")
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}
	defer storage.Close()

	// Initialize core auth service
	coreConfig := core.Config{
		Storage:        storage,
		SecurityConfig: core.DefaultSecurityConfig(),
	}
	authService, err := core.NewAuthService(coreConfig)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}

	// Initialize referrals module (independent of core)
	referralsConfig := referrals.DefaultConfig()
	referralsModule, err := referrals.NewReferralsModule(storage, referralsConfig)
	if err != nil {
		log.Fatal("Failed to create referrals module:", err)
	}
	defer referralsModule.Close()

	// Get referrals utilities for manual integration
	referralsUtils := referralsModule.GetUtilities()

	// Setup routes with manual referral integration
	http.HandleFunc("/signup", signupWithReferralHandler(authService, referralsUtils))
	http.HandleFunc("/referrals/generate", generateReferralHandler(referralsUtils))
	http.HandleFunc("/referrals/stats", getReferralStatsHandler(referralsUtils))

	log.Println("Server starting on :8080")
	log.Println("Example endpoints:")
	log.Println("POST /signup - Sign up with optional referral code")
	log.Println("POST /referrals/generate - Generate a new referral code")
	log.Println("GET /referrals/stats - Get your referral statistics")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// signupWithReferralHandler demonstrates the exact manual integration pattern
func signupWithReferralHandler(authService *core.AuthService, referralsUtils *referrals.Utilities) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SignupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(SignupResponse{Error: "Invalid request format"})
			return
		}

		var validReferral *referrals.ReferralCode
		var err error

		// STEP 1: Check referral if provided
		if req.ReferralCode != "" {
			validReferral, err = referralsUtils.ValidateReferralCode(req.ReferralCode, 0)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(SignupResponse{
					Error: "Invalid referral code: " + err.Error(),
				})
				return
			}
		} else if referralsUtils.IsReferralRequired() {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(SignupResponse{
				Error: "Referral code is required",
			})
			return
		}

		// STEP 2: Call core signup (unmodified)
		result := authService.SignUpHandler(r)
		if result.StatusCode != http.StatusCreated {
			// Forward the core signup error as-is
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(SignupResponse{Error: result.Error})
			return
		}

		// STEP 3: Process referral after successful signup
		usedReferral := false
		if validReferral != nil {
			err = referralsUtils.ProcessReferralSignup(validReferral, result.User.ID)
			if err != nil {
				// Log error but don't fail the signup since user was created successfully
				log.Printf("Failed to process referral: %v", err)
			} else {
				usedReferral = true
				log.Printf("Referral processed successfully for user %d", result.User.ID)
			}
		}

		// STEP 4: Return success response with referral information
		response := SignupResponse{
			Token:        result.Token,
			User:         result.User,
			UsedReferral: usedReferral,
		}
		if usedReferral {
			response.ReferralCode = validReferral
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}
}

// generateReferralHandler demonstrates creating referral codes
func generateReferralHandler(referralsUtils *referrals.Utilities) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In a real app, get user ID from authentication middleware
		userID := uint(1) // Placeholder - replace with actual user ID from JWT/session

		var req referrals.GenerateOptions
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request format"})
			return
		}

		code, err := referralsUtils.GenerateReferralCode(userID, req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(code)
	}
}

// getReferralStatsHandler demonstrates getting referral statistics
func getReferralStatsHandler(referralsUtils *referrals.Utilities) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In a real app, get user ID from authentication middleware
		userID := uint(1) // Placeholder - replace with actual user ID from JWT/session

		stats, err := referralsUtils.GetReferralStats(userID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(stats)
	}
}
