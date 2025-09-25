package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/wispberry-tech/wispy-auth/core"
	"github.com/wispberry-tech/wispy-auth/referrals"
	referralstorage "github.com/wispberry-tech/wispy-auth/referrals/storage"
)

func main() {
	// Set up logging
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	// Create storage with referral support
	storage, err := referralstorage.NewInMemorySQLiteStorage()
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}
	defer storage.Close()

	// Configure core authentication service
	coreConfig := core.Config{
		Storage:        storage,
		SecurityConfig: core.DefaultSecurityConfig(),
		OAuthProviders: map[string]core.OAuthProviderConfig{
			"google": core.NewGoogleOAuthProvider(
				os.Getenv("GOOGLE_CLIENT_ID"),
				os.Getenv("GOOGLE_CLIENT_SECRET"),
				"http://localhost:8080/auth/google/callback",
			),
		},
	}

	// Create core auth service
	coreAuthService, err := core.NewAuthService(coreConfig)
	if err != nil {
		log.Fatal("Failed to create core auth service:", err)
	}
	defer coreAuthService.Close()

	// Configure referrals extension
	referralConfig := referrals.Config{
		CodeLength:          8,
		CodePrefix:          "REF",
		AllowCustomCodes:    true,
		MaxCodesPerUser:     5,
		DefaultMaxUses:      0, // Unlimited uses
		DefaultExpiry:       0, // Never expires
		RequireReferralCode: false,
	}

	// Create enhanced auth service with referrals
	authService := referrals.NewAuthService(coreAuthService, storage, referralConfig)

	// Create HTTP mux
	mux := http.NewServeMux()

	// Core authentication endpoints (enhanced with referral support)
	mux.HandleFunc("POST /signup", handleSignUp(authService))
	mux.HandleFunc("POST /signin", handleSignIn(coreAuthService)) // Use core signin
	mux.HandleFunc("POST /logout", handleLogout(coreAuthService))
	mux.HandleFunc("GET /validate", handleValidate(coreAuthService))

	// OAuth endpoints (use core)
	mux.HandleFunc("GET /auth/{provider}", handleOAuthInit(coreAuthService))
	mux.HandleFunc("GET /auth/{provider}/callback", handleOAuthCallback(coreAuthService))

	// Referral-specific endpoints (protected)
	mux.Handle("POST /referrals/generate", authService.AuthMiddleware(http.HandlerFunc(handleGenerateReferralCode(authService))))
	mux.Handle("GET /referrals/codes", authService.AuthMiddleware(http.HandlerFunc(handleGetReferralCodes(authService))))
	mux.Handle("GET /referrals/stats", authService.AuthMiddleware(http.HandlerFunc(handleGetReferralStats(authService))))
	mux.Handle("GET /referrals/relationships", authService.AuthMiddleware(http.HandlerFunc(handleGetReferralRelationships(authService))))
	mux.Handle("POST /referrals/codes/{id}/deactivate", authService.AuthMiddleware(http.HandlerFunc(handleDeactivateReferralCode(authService))))

	// Public referral endpoints
	mux.HandleFunc("GET /referrals/top", handleGetTopReferrers(authService))

	// Protected endpoints (use core middleware)
	mux.Handle("GET /profile", authService.AuthMiddleware(http.HandlerFunc(handleProfile)))

	// Public endpoints
	mux.HandleFunc("GET /", handleHome)
	mux.HandleFunc("GET /health", handleHealth)

	slog.Info("Starting server on :8080")
	slog.Info("Available endpoints:")
	slog.Info("  POST /signup - User registration with referral support")
	slog.Info("  POST /signin - User authentication")
	slog.Info("  POST /logout - User logout")
	slog.Info("  GET /validate - Token validation")
	slog.Info("  GET /auth/google - Google OAuth")
	slog.Info("  POST /referrals/generate - Generate referral code (protected)")
	slog.Info("  GET /referrals/codes - Get user's referral codes (protected)")
	slog.Info("  GET /referrals/stats - Get referral statistics (protected)")
	slog.Info("  GET /referrals/relationships - Get referral relationships (protected)")
	slog.Info("  GET /referrals/top - Get top referrers (public)")
	slog.Info("  GET /profile - Get user profile (protected)")
	slog.Info("  GET / - Home page")
	slog.Info("  GET /health - Health check")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// Enhanced signup handler with referral support
func handleSignUp(authService *referrals.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.SignUpWithReferralHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

// Core authentication handlers
func handleSignIn(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.SignInHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleLogout(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.LogoutHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleValidate(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.ValidateHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

// OAuth handlers
func handleOAuthInit(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		result := authService.OAuthInitHandler(r, provider)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleOAuthCallback(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		result := authService.OAuthCallbackHandler(r, provider)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

// Referral handlers
func handleGenerateReferralCode(authService *referrals.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.GenerateReferralCodeHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleGetReferralCodes(authService *referrals.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.GetReferralCodesHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleGetReferralStats(authService *referrals.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.GetReferralStatsHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleGetReferralRelationships(authService *referrals.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.GetReferralRelationshipsHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleGetTopReferrers(authService *referrals.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.GetTopReferrersHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

func handleDeactivateReferralCode(authService *referrals.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		codeID := r.PathValue("id")
		result := authService.DeactivateReferralCodeHandler(r, codeID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	}
}

// Protected profile handler
func handleProfile(w http.ResponseWriter, r *http.Request) {
	user := core.GetUserFromContext(r)

	response := map[string]interface{}{
		"message": "This is your profile",
		"user":    user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Public handlers
func handleHome(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "Welcome to Wispy Auth with Referrals Extension",
		"endpoints": map[string]string{
			"POST /signup":                          "User registration with referral support",
			"POST /signin":                          "User authentication",
			"POST /logout":                          "User logout",
			"GET /validate":                         "Token validation",
			"GET /auth/google":                      "Google OAuth",
			"POST /referrals/generate":              "Generate referral code (protected)",
			"GET /referrals/codes":                  "Get user's referral codes (protected)",
			"GET /referrals/stats":                  "Get referral statistics (protected)",
			"GET /referrals/relationships":          "Get referral relationships (protected)",
			"POST /referrals/codes/{id}/deactivate": "Deactivate referral code (protected)",
			"GET /referrals/top":                    "Get top referrers (public)",
			"GET /profile":                          "Get user profile (protected)",
			"GET /health":                           "Health check",
		},
		"example_requests": map[string]interface{}{
			"signup": map[string]interface{}{
				"method": "POST",
				"url":    "/signup",
				"body": map[string]string{
					"email":         "user@example.com",
					"password":      "SecurePass123",
					"first_name":    "John",
					"last_name":     "Doe",
					"referral_code": "REF12345678", // Optional
				},
			},
			"generate_referral": map[string]interface{}{
				"method":  "POST",
				"url":     "/referrals/generate",
				"headers": map[string]string{"Authorization": "Bearer <your-token>"},
				"body": map[string]interface{}{
					"custom_code": "MYCUSTOMCODE", // Optional
					"max_uses":    10,             // Optional, 0 = unlimited
				},
			},
		},
		"referral_features": []string{
			"Generate custom or random referral codes",
			"Track referral usage and statistics",
			"Set usage limits and expiration dates",
			"View referral relationships",
			"Leaderboard of top referrers",
			"Optional or required referral codes for signup",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":     "healthy",
		"service":    "wispy-auth-referrals",
		"version":    "1.0.0",
		"extensions": []string{"referrals"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}