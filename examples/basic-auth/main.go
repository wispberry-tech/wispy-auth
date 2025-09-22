package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/ncruces/go-sqlite3"

	auth "github.com/wispberry-tech/wispy-auth"
	"github.com/wispberry-tech/wispy-auth/storage"
)

// MockEmailService implements auth.EmailService for testing
type MockEmailService struct{}

func (m *MockEmailService) SendVerificationEmail(email, token string) error {
	fmt.Printf("📧 Verification email sent to %s with token: %s\n", email, token)
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(email, token string) error {
	fmt.Printf("🔐 Password reset email sent to %s with token: %s\n", email, token)
	return nil
}

func (m *MockEmailService) SendWelcomeEmail(email, name string) error {
	fmt.Printf("👋 Welcome email sent to %s (%s)\n", email, name)
	return nil
}

func (m *MockEmailService) Send2FACode(email, code string) error {
	fmt.Printf("🔐 2FA code sent to %s: %s\n", email, code)
	return nil
}

func (m *MockEmailService) Send2FAEnabled(email string) error {
	fmt.Printf("🔒 2FA enabled notification sent to %s\n", email)
	return nil
}

func (m *MockEmailService) Send2FADisabled(email string) error {
	fmt.Printf("🔓 2FA disabled notification sent to %s\n", email)
	return nil
}

func main() {
	fmt.Println("🚀 Starting Basic Auth Example...")

	// Create SQLite database and run migrations
	fmt.Println("📁 Setting up database...")

	// Open database connection
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Run migrations
	fmt.Println("📁 Running database migrations...")
	migrationFile := "../../sql/sqlite_scaffold.sql"
	migrationSQL, err := os.ReadFile(migrationFile)
	if err != nil {
		log.Fatal("Failed to read migration file:", err)
	}

	// Execute migration SQL
	_, err = db.Exec(string(migrationSQL))
	if err != nil {
		log.Fatal("Failed to run migrations:", err)
	}

	fmt.Println("✅ Database migrations completed")

	// Create storage with the prepared database
	sqliteStorage, err := storage.NewSQLiteStorageFromDB(db)
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	// Configure auth service with security settings
	// Start with default configuration and customize as needed
	config := auth.DefaultConfig()
	config.Storage = sqliteStorage
	config.EmailService = &MockEmailService{}

	// Override default settings for this example
	config.SecurityConfig.RequireEmailVerification = false // Disabled for this simple example

	// Initialize auth service
	authService, err := auth.NewAuthService(config)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Public routes
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
			user := auth.MustGetUserFromContext(r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user":    user,
				"message": "This is your profile!",
			})
		})

		r.Post("/signout", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Signed out successfully (session invalidated)",
				"success": true,
			})
		})
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	fmt.Println("📱 Server starting on http://localhost:8080")
	fmt.Println("\n🧪 Try these commands:")
	fmt.Println("curl -X POST http://localhost:8080/signup -H 'Content-Type: application/json' -d '{\"email\":\"test@example.com\",\"password\":\"Password123\"}'")
	fmt.Println("curl -X POST http://localhost:8080/signin -H 'Content-Type: application/json' -d '{\"email\":\"test@example.com\",\"password\":\"Password123\"}'")
	fmt.Println("curl -X GET http://localhost:8080/profile -H 'Authorization: Bearer YOUR_TOKEN'")

	log.Fatal(http.ListenAndServe(":8080", r))
}
