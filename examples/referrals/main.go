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
	fmt.Println("🚀 Starting Referral System Example...")

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
	sqliteStorage, err := storage.NewSQLiteStorage(":memory:")
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	// Configure auth service with referral system
	config := auth.Config{
		Storage:      sqliteStorage,
		EmailService: &MockEmailService{},
		SecurityConfig: auth.SecurityConfig{
			// Basic settings
			PasswordMinLength:        8,
			SessionLifetime:          24 * time.Hour,
			RequireEmailVerification: false,

			// Referral System Configuration
			RequireReferralCode: false,        // Optional for signup (set to true to require)
			DefaultUserRoleName: "user",       // Default role for new users

			// Role-based invitation limits
			MaxInviteesPerRole: map[string]int{
				"user":     5,    // Basic users: 5 invites
				"premium":  20,   // Premium users: 20 invites
				"admin":    100,  // Admins: 100 invites
			},

			// Referral code settings
			ReferralCodeLength: 8,
			ReferralCodePrefix: "REF",
			ReferralCodeExpiry: 30 * 24 * time.Hour, // 30 days
		},
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

	// Protected routes (require authentication)
	r.Group(func(r chi.Router) {
		r.Use(authService.RequireAuth())

		// User profile
		r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
			user := auth.MustGetUserFromContext(r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user":    user,
				"message": "Welcome to the referral system demo!",
			})
		})

		// Generate referral code
		r.Post("/referrals/generate", func(w http.ResponseWriter, r *http.Request) {
			result := authService.GenerateReferralCodeHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})

		// Get my referral codes
		r.Get("/referrals/codes", func(w http.ResponseWriter, r *http.Request) {
			result := authService.GetMyReferralCodesHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})

		// Get my referrals (people I've referred)
		r.Get("/referrals/users", func(w http.ResponseWriter, r *http.Request) {
			result := authService.GetMyReferralsHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})

		// Get referral statistics
		r.Get("/referrals/stats", func(w http.ResponseWriter, r *http.Request) {
			result := authService.GetReferralStatsHandler(r)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	fmt.Println("📱 Server starting on http://localhost:8080")
	fmt.Println("\n🧪 Try this referral flow:")
	fmt.Println("1. Sign up first user:")
	fmt.Println(`   curl -X POST http://localhost:8080/signup -H 'Content-Type: application/json' -d '{"email":"alice@example.com","password":"Password123"}'`)
	fmt.Println("2. Generate referral code:")
	fmt.Println(`   curl -X POST http://localhost:8080/referrals/generate -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d '{}'`)
	fmt.Println("3. Sign up with referral code:")
	fmt.Println(`   curl -X POST http://localhost:8080/signup -H 'Content-Type: application/json' -d '{"email":"bob@example.com","password":"Password123","referral_code":"REF12345678"}'`)
	fmt.Println("4. Check referral stats:")
	fmt.Println(`   curl -X GET http://localhost:8080/referrals/stats -H 'Authorization: Bearer TOKEN'`)

	log.Fatal(http.ListenAndServe(":8080", r))
}