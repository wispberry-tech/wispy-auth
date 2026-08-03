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
	store, err := storage.NewInMemorySQLiteStorage()
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}
	defer store.Close()

	// Configure authentication service
	config := core.Config{
		Storage:        store,
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

	// Authentication endpoints — handlers are now http.HandlerFunc directly
	mux.HandleFunc("POST /signup", authService.SignUpHandler)
	mux.HandleFunc("POST /signin", authService.SignInHandler)
	mux.HandleFunc("POST /logout", authService.LogoutHandler)
	mux.HandleFunc("GET /validate", authService.ValidateHandler)

	// Password reset endpoints
	mux.HandleFunc("POST /forgot-password", authService.ForgotPasswordHandler)
	mux.HandleFunc("POST /reset-password", authService.ResetPasswordHandler)
	mux.Handle("POST /change-password", authService.AuthMiddleware(http.HandlerFunc(authService.ChangePasswordHandler)))

	// OAuth endpoints — wrap inline for the extra provider parameter
	mux.HandleFunc("GET /auth/{provider}", func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		authService.OAuthInitHandler(w, r, provider)
	})
	mux.HandleFunc("GET /auth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		authService.OAuthCallbackHandler(w, r, provider)
	})

	// Protected endpoints
	mux.Handle("GET /profile", authService.AuthMiddleware(http.HandlerFunc(handleProfile)))
	mux.Handle("GET /sessions", authService.AuthMiddleware(http.HandlerFunc(authService.GetSessionsHandler)))

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
