package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/ncruces/go-sqlite3"

	auth "github.com/wispberry-tech/wispy-auth"
	"github.com/wispberry-tech/wispy-auth/storage"
)

// MockEmailService implements auth.EmailService for testing
type MockEmailService struct{}

func (m *MockEmailService) SendVerificationEmail(email, token string) error {
	fmt.Printf("📧 Verification email sent to %s\n", email)
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(email, token string) error {
	fmt.Printf("🔐 Password reset email sent to %s\n", email)
	return nil
}

func (m *MockEmailService) SendWelcomeEmail(email, name string) error {
	fmt.Printf("👋 Welcome email sent to %s (%s)\n", email, name)
	return nil
}

func main() {
	fmt.Println("🚀 Starting OAuth Integration Example...")

	// Check for environment variables
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	if googleClientID == "" || googleClientSecret == "" {
		fmt.Println("⚠️  Warning: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET not set")
		fmt.Println("   OAuth will use mock credentials for demonstration")
		googleClientID = "mock-client-id"
		googleClientSecret = "mock-client-secret"
	}

	// Initialize SQLite database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Create storage
	sqliteStorage, err := storage.NewSQLiteStorage(db)
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	// Configure auth service with OAuth providers
	config := auth.Config{
		Storage:      sqliteStorage,
		EmailService: &MockEmailService{},
		SecurityConfig: auth.SecurityConfig{
			SessionDuration:          24 * time.Hour,
			RequireEmailVerification: false,
		},
		OAuthProviders: map[string]auth.OAuthProviderConfig{
			// Google OAuth2
			"google": auth.NewGoogleOAuthProvider(
				googleClientID,
				googleClientSecret,
				"http://localhost:8080/auth/callback/google",
			),
			// GitHub OAuth2
			"github": auth.NewGitHubOAuthProvider(
				os.Getenv("GITHUB_CLIENT_ID"),
				os.Getenv("GITHUB_CLIENT_SECRET"),
				"http://localhost:8080/auth/callback/github",
			),
			// Custom enterprise provider example
			"company-sso": auth.NewCustomOAuthProvider(
				os.Getenv("COMPANY_CLIENT_ID"),
				os.Getenv("COMPANY_CLIENT_SECRET"),
				"http://localhost:8080/auth/callback/company",
				"https://sso.company.com/oauth2/authorize",
				"https://sso.company.com/oauth2/token",
				[]string{"profile", "email", "groups"},
			),
		},
		AutoMigrate: true,
	}

	// Initialize auth service
	authService, err := auth.NewAuthService(config)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// OAuth initiation routes
	r.Get("/auth/{provider}", func(w http.ResponseWriter, r *http.Request) {
		result := authService.InitiateOAuthHandler(r)
		if result.StatusCode == 302 {
			http.Redirect(w, r, result.RedirectURL, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	})

	// OAuth callback routes
	r.Get("/auth/callback/{provider}", func(w http.ResponseWriter, r *http.Request) {
		result := authService.HandleOAuthCallbackHandler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.StatusCode)
		json.NewEncoder(w).Encode(result)
	})

	// Traditional signup/signin (also available)
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

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(authService.RequireAuth())

		r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
			user := auth.MustGetUserFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user":     user,
				"message":  "OAuth authentication successful!",
				"provider": user.Provider,
			})
		})

		r.Post("/signout", func(w http.ResponseWriter, r *http.Request) {
			result := authService.SignOutHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
	})

	// Provider list endpoint
	r.Get("/providers", func(w http.ResponseWriter, r *http.Request) {
		providers := []map[string]string{
			{"name": "google", "url": "/auth/google"},
			{"name": "github", "url": "/auth/github"},
			{"name": "company-sso", "url": "/auth/company-sso"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": providers,
			"message":   "Available OAuth providers",
		})
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	fmt.Println("📱 Server starting on http://localhost:8080")
	fmt.Println("\n🧪 Try these OAuth flows:")
	fmt.Println("• Visit http://localhost:8080/providers to see available providers")
	fmt.Println("• Visit http://localhost:8080/auth/google to start Google OAuth")
	fmt.Println("• Visit http://localhost:8080/auth/github to start GitHub OAuth")
	fmt.Println("\n💡 Set environment variables for real OAuth:")
	fmt.Println("export GOOGLE_CLIENT_ID=your_google_client_id")
	fmt.Println("export GOOGLE_CLIENT_SECRET=your_google_client_secret")
	fmt.Println("export GITHUB_CLIENT_ID=your_github_client_id")
	fmt.Println("export GITHUB_CLIENT_SECRET=your_github_client_secret")

	log.Fatal(http.ListenAndServe(":8080", r))
}