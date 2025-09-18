package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
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

	// Initialize auth service with enhanced security and built-in email integration
	cfg := auth.Config{
		DatabaseDSN: os.Getenv("DATABASE_URL"), // Use PostgreSQL from environment

		// Built-in email service integration - configured once, works everywhere!
		EmailService: emailService,

		// Use default storage configuration
		StorageConfig: auth.DefaultStorageConfig(),
		
		// Enable auto-migrations for easy setup
		AutoMigrate: true,
		
		// Development mode (affects cookie security)
		DevelopmentMode: true,

		// Enhanced security configuration
		SecurityConfig: auth.SecurityConfig{
			// Email verification
			RequireEmailVerification: true,
			VerificationTokenExpiry:  24 * time.Hour,

			// Password policy
			PasswordMinLength:      8,
			PasswordRequireUpper:   true,
			PasswordRequireLower:   true,
			PasswordRequireNumber:  true,
			PasswordRequireSpecial: false,
			PasswordResetExpiry:    1 * time.Hour,

			// Login protection
			MaxLoginAttempts: 7,
			LockoutDuration:  60 * time.Minute,
			SessionLifetime:  24 * time.Hour,
			RequireTwoFactor: false,
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

	// Mount auth routes with the new simplified API - maximum control & DX!
	r.Route("/api/auth", func(r chi.Router) {
		// Public routes - single API, maximum simplicity!
		r.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
			result := authService.SignUpHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
		
		r.Post("/signin", func(w http.ResponseWriter, r *http.Request) {
			result := authService.SignInHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
		
		r.Get("/validate", func(w http.ResponseWriter, r *http.Request) {
			result := authService.ValidateHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
		
		r.Post("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
			result := authService.ForgotPasswordHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
		
		r.Post("/reset-password", func(w http.ResponseWriter, r *http.Request) {
			result := authService.ResetPasswordHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
		
		r.Post("/verify-email", func(w http.ResponseWriter, r *http.Request) {
			result := authService.VerifyEmailHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})

		// OAuth routes
		r.Get("/oauth", func(w http.ResponseWriter, r *http.Request) {
			provider := r.URL.Query().Get("provider")
			result := authService.OAuthHandler(w, r, provider)
			if result.URL != "" {
				http.Redirect(w, r, result.URL, http.StatusTemporaryRedirect)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
		
		r.Get("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
			provider := r.URL.Query().Get("provider")
			code := r.URL.Query().Get("code")
			state := r.URL.Query().Get("state")
			result := authService.OAuthCallbackHandler(r, provider, code, state)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
		
		r.Get("/providers", func(w http.ResponseWriter, r *http.Request) {
			result := authService.GetProvidersHandler(r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
		})

		// Protected routes - use auth middleware
		r.Group(func(r chi.Router) {
			r.Use(authService.RequireAuth())
			
			r.Post("/resend-verification", func(w http.ResponseWriter, r *http.Request) {
				result := authService.ResendVerificationHandler(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(result.StatusCode)
				json.NewEncoder(w).Encode(result)
			})
			
			r.Get("/sessions", func(w http.ResponseWriter, r *http.Request) {
				result := authService.GetSessionsHandler(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(result.StatusCode)
				json.NewEncoder(w).Encode(result)
			})
			
			r.Delete("/sessions/{sessionID}", func(w http.ResponseWriter, r *http.Request) {
				sessionID := chi.URLParam(r, "sessionID")
				result := authService.RevokeSessionHandler(r, sessionID)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(result.StatusCode)
				json.NewEncoder(w).Encode(result)
			})
			
			r.Post("/logout-all", func(w http.ResponseWriter, r *http.Request) {
				result := authService.RevokeAllSessionsHandler(r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(result.StatusCode)
				json.NewEncoder(w).Encode(result)
			})
		})
	})

	// Example of custom routes with middleware
	r.Group(func(r chi.Router) {
		r.Use(authService.RequireAuth())
		
		r.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
			user := auth.MustGetUserFromContext(r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(user)
		})

		// Admin only routes
		r.Group(func(r chi.Router) {
			r.Use(authService.RequireRole("admin"))
			
			r.Get("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
				// Admin functionality here
				json.NewEncoder(w).Encode(map[string]string{
					"message": "Admin access granted!",
				})
			})
		})
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


