package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"

	auth "github.com/wispberry-tech/wispy-auth"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize email service
	emailService := NewEmailService()

	// Initialize auth service with enhanced security
	cfg := auth.Config{
		DatabaseDSN: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		
		// Use default storage configuration
		StorageConfig: auth.DefaultStorageConfig(),
		
		// Enhanced security configuration
		SecurityConfig: auth.SecurityConfig{
			// Password policy
			MinPasswordLength:   8,
			RequireUppercase:    true,
			RequireLowercase:    true,
			RequireNumbers:      true,
			RequireSpecialChars: false,
			
			// Login protection
			MaxLoginAttempts:     5,
			LoginLockoutDuration: 15 * time.Minute,
			
			// Session security
			SessionTimeout:       24 * time.Hour,
			MaxActiveSessions:    5,
			
			// Email verification
			RequireEmailVerification: true,
			EmailVerificationExpiry:  24 * time.Hour,
			
			// Password reset
			PasswordResetExpiry: 1 * time.Hour,
			
			// Rate limiting
			EnableRateLimiting:   true,
			RateLimitWindow:      1 * time.Minute,
			RateLimitMaxRequests: 60,
		},
		
		// OAuth providers
		OAuthProviders: map[string]auth.OAuthProviderConfig{
			"google": {
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/auth/oauth/callback?provider=google",
			},
			"github": {
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/auth/oauth/callback?provider=github",
			},
			"discord": {
				ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
				ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/auth/oauth/callback?provider=discord",
			},
		},
	}

	authService, err := auth.NewAuthService(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}

	// Initialize Chi router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	
	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:3001"}, // Add your frontend URLs
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Auth routes
	r.Route("/auth", func(r chi.Router) {
		r.Post("/signup", handleSignUp(authService, emailService))
		r.Post("/signin", handleSignIn(authService, emailService))
		r.Get("/validate", handleValidate(authService))
		r.Post("/forgot-password", handleForgotPassword(authService, emailService))
		r.Post("/reset-password", handleResetPassword(authService))
		r.Post("/verify-email", handleVerifyEmail(authService))
		
		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware(authService))
			r.Post("/resend-verification", handleResendVerification(authService, emailService))
			r.Get("/sessions", handleGetSessions(authService))
			r.Delete("/sessions/{sessionID}", handleRevokeSession(authService))
			r.Post("/logout-all", handleRevokeAllSessions(authService))
		})
		
		// OAuth routes
		r.Get("/oauth", handleOAuth(authService))
		r.Get("/oauth/callback", handleOAuthCallback(authService))
		
		// Utility routes
		r.Get("/providers", handleGetProviders())
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on :%s", port)
	log.Printf("Health check: http://localhost:%s/health", port)
	log.Printf("Auth endpoints: http://localhost:%s/auth/*", port)
	
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// Helper function to extract IP address
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

// Helper function to extract user from token
func extractUserFromToken(authService *auth.AuthService, token string) (*auth.User, error) {
	response := authService.HandleValidate(token)
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	return response.User, nil
}

// Middleware for authentication
func authMiddleware(authService *auth.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if token == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Remove Bearer prefix if present
			if strings.HasPrefix(token, "Bearer ") {
				token = token[7:]
			}

			response := authService.HandleValidate(token)
			if response.Error != "" {
				http.Error(w, response.Error, response.StatusCode)
				return
			}

			// Add user to request context (optional)
			ctx := context.WithValue(r.Context(), userContextKey, response.User)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}