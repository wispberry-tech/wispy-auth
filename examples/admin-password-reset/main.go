package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/wispberry-tech/wispy-auth/core"
	"github.com/wispberry-tech/wispy-auth/core/storage"
)

func main() {
	// Set up logging
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	// Create in-memory SQLite storage for demo
	storage, err := storage.NewInMemorySQLiteStorage()
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}
	defer storage.Close()

	// Configure authentication service
	config := core.Config{
		Storage:        storage,
		SecurityConfig: core.DefaultSecurityConfig(),
		OAuthProviders: map[string]core.OAuthProviderConfig{
			"google": core.NewGoogleOAuthProvider(
				os.Getenv("GOOGLE_CLIENT_ID"),
				os.Getenv("GOOGLE_CLIENT_SECRET"),
				"http://localhost:8080/auth/google/callback",
			),
			"github": core.NewGitHubOAuthProvider(
				os.Getenv("GITHUB_CLIENT_ID"),
				os.Getenv("GITHUB_CLIENT_SECRET"),
				"http://localhost:8080/auth/github/callback",
			),
		},
	}

	// Create auth service
	authService, err := core.NewAuthService(config)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}
	defer authService.Close()

	// Create HTTP mux
	mux := http.NewServeMux()

	// Authentication endpoints
	mux.HandleFunc("POST /signup", handleSignUp(authService))
	mux.HandleFunc("POST /signin", handleSignIn(authService))
	mux.HandleFunc("POST /logout", handleLogout(authService))
	mux.HandleFunc("GET /validate", handleValidate(authService))

	// Password reset endpoints
	mux.HandleFunc("POST /forgot-password", handleForgotPassword(authService))
	mux.HandleFunc("POST /reset-password", handleResetPassword(authService))
	mux.Handle("POST /change-password", authService.AuthMiddleware(http.HandlerFunc(handleChangePassword(authService))))

	// OAuth endpoints
	mux.HandleFunc("GET /auth/{provider}", handleOAuthInit(authService))
	mux.HandleFunc("GET /auth/{provider}/callback", handleOAuthCallback(authService))

	// Protected endpoints
	mux.Handle("GET /profile", authService.AuthMiddleware(http.HandlerFunc(handleProfile)))
	mux.Handle("GET /sessions", authService.AuthMiddleware(http.HandlerFunc(handleSessions(authService))))

	// Public endpoints
	mux.HandleFunc("GET /", handleHome)
	mux.HandleFunc("GET /health", handleHealth)

	// Apply rate limiting middleware to all routes
	handler := authService.RateLimitMiddleware(mux)

	slog.Info("Starting server on :8080")
	slog.Info("Available endpoints:")
	slog.Info("  POST /signup - User registration")
	slog.Info("  POST /signin - User authentication")
	slog.Info("  POST /logout - User logout")
	slog.Info("  GET /validate - Token validation")
	slog.Info("  POST /forgot-password - Request password reset")
	slog.Info("  POST /reset-password - Reset password with token")
	slog.Info("  POST /change-password - Change password (protected)")
	slog.Info("  GET /auth/google - Google OAuth")
	slog.Info("  GET /auth/github - GitHub OAuth")
	slog.Info("  GET /profile - Get user profile (protected)")
	slog.Info("  GET /sessions - Get user sessions (protected)")
	slog.Info("  GET / - Home page")
	slog.Info("  GET /health - Health check")

	// Create HTTP server with timeouts for security
	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("Server starting on :8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// handleSignUp handles user registration
func handleSignUp(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.SignUpHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode signup response", "error", err)
		}
	}
}

// handleSignIn handles user authentication
func handleSignIn(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.SignInHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode signin response", "error", err)
		}
	}
}

// handleLogout handles user logout
func handleLogout(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.LogoutHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode logout response", "error", err)
		}
	}
}

// handleValidate handles token validation
func handleValidate(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.ValidateHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode validate response", "error", err)
		}
	}
}

// handleOAuthInit handles OAuth initialization
func handleOAuthInit(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		result := authService.OAuthInitHandler(r, provider)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode OAuth init response", "error", err)
		}
	}
}

// handleOAuthCallback handles OAuth callbacks
func handleOAuthCallback(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		result := authService.OAuthCallbackHandler(r, provider)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode OAuth callback response", "error", err)
		}
	}
}

// handleProfile handles protected profile endpoint
func handleProfile(w http.ResponseWriter, r *http.Request) {
	user := core.GetUserFromContext(r)

	response := map[string]interface{}{
		"message": "This is your profile",
		"user":    user,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode profile response", "error", err)
	}
}

// handleSessions handles user session listing
func handleSessions(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.GetSessionsHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode sessions response", "error", err)
		}
	}
}

// handleHome handles the home page
func handleHome(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "Welcome to Wispy Auth Core Demo",
		"endpoints": map[string]string{
			"POST /signup":     "User registration",
			"POST /signin":     "User authentication",
			"POST /logout":     "User logout",
			"GET /validate":    "Token validation",
			"GET /auth/google": "Google OAuth",
			"GET /auth/github": "GitHub OAuth",
			"GET /profile":     "Get user profile (protected)",
			"GET /sessions":    "Get user sessions (protected)",
			"GET /health":      "Health check",
		},
		"example_requests": map[string]interface{}{
			"signup": map[string]interface{}{
				"method": "POST",
				"url":    "/signup",
				"body": map[string]string{
					"email":      "user@example.com",
					"password":   "SecurePass123!",
					"first_name": "John",
					"last_name":  "Doe",
				},
			},
			"signin": map[string]interface{}{
				"method": "POST",
				"url":    "/signin",
				"body": map[string]string{
					"email":    "user@example.com",
					"password": "SecurePass123!",
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode home response", "error", err)
	}
}

// handleForgotPassword handles password reset requests
func handleForgotPassword(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.ForgotPasswordHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode forgot password response", "error", err)
		}
	}
}

// handleResetPassword handles password reset confirmations
func handleResetPassword(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.ResetPasswordHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode reset password response", "error", err)
		}
	}
}

// handleChangePassword handles password change requests
func handleChangePassword(authService *core.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := authService.ChangePasswordHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Error("Failed to encode change password response", "error", err)
		}
	}
}

// handleHealth handles health check
func handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "healthy",
		"service": "wispy-auth-core",
		"version": "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("Failed to encode health response", "error", err)
	}
}
