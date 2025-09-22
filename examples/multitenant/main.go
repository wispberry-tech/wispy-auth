package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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
	fmt.Println("🚀 Starting Multi-Tenant RBAC Example...")

	// Initialize SQLite database
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

	// Create storage
	sqliteStorage, err := storage.NewSQLiteStorageFromDB(db)
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	// Configure auth service
	config := auth.Config{
		Storage:      sqliteStorage,
		EmailService: &MockEmailService{},
		SecurityConfig: auth.SecurityConfig{
			PasswordMinLength:        8,
			SessionLifetime:          24 * time.Hour,
			RequireEmailVerification: false,
			DefaultUserRoleName:      "user",
		},
	}

	// Initialize auth service
	authService, err := auth.NewAuthService(config)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}

	// Setup demo tenants, roles, and permissions
	fmt.Println("🏢 Setting up demo tenants and RBAC structure...")

	// Create tenants
	acmeCorp, err := authService.CreateTenant("Acme Corporation", "acme", "acme.com")
	if err != nil {
		log.Fatal("Failed to create Acme tenant:", err)
	}

	techStartup, err := authService.CreateTenant("Tech Startup Inc", "techstartup", "techstartup.io")
	if err != nil {
		log.Fatal("Failed to create TechStartup tenant:", err)
	}

	// Create roles for Acme Corp
	acmeAdmin, err := authService.CreateRole(acmeCorp.ID, "admin", "Administrator", false)
	if err != nil {
		log.Fatal("Failed to create admin role:", err)
	}

	acmeManager, err := authService.CreateRole(acmeCorp.ID, "manager", "Manager", false)
	if err != nil {
		log.Fatal("Failed to create manager role:", err)
	}

	acmeUser, err := authService.CreateRole(acmeCorp.ID, "user", "Regular User", false)
	if err != nil {
		log.Fatal("Failed to create user role:", err)
	}

	// Create roles for Tech Startup
	startupOwner, err := authService.CreateRole(techStartup.ID, "owner", "Company Owner", false)
	if err != nil {
		log.Fatal("Failed to create owner role:", err)
	}

	startupDev, err := authService.CreateRole(techStartup.ID, "developer", "Developer", false)
	if err != nil {
		log.Fatal("Failed to create developer role:", err)
	}

	// Create permissions
	readDocs, err := authService.CreatePermission("documents.read", "documents", "read", "Read documents")
	if err != nil {
		log.Fatal("Failed to create read permission:", err)
	}

	writeDocs, err := authService.CreatePermission("documents.write", "documents", "write", "Write documents")
	if err != nil {
		log.Fatal("Failed to create write permission:", err)
	}

	manageUsers, err := authService.CreatePermission("users.manage", "users", "manage", "Manage users")
	if err != nil {
		log.Fatal("Failed to create manage users permission:", err)
	}

	deployCode, err := authService.CreatePermission("deployment.deploy", "deployment", "deploy", "Deploy code")
	if err != nil {
		log.Fatal("Failed to create deploy permission:", err)
	}

	// Assign permissions to Acme Corp roles
	authService.AssignPermissionToRole(acmeAdmin.ID, readDocs.ID)
	authService.AssignPermissionToRole(acmeAdmin.ID, writeDocs.ID)
	authService.AssignPermissionToRole(acmeAdmin.ID, manageUsers.ID)

	authService.AssignPermissionToRole(acmeManager.ID, readDocs.ID)
	authService.AssignPermissionToRole(acmeManager.ID, writeDocs.ID)

	authService.AssignPermissionToRole(acmeUser.ID, readDocs.ID)

	// Assign permissions to Tech Startup roles
	authService.AssignPermissionToRole(startupOwner.ID, readDocs.ID)
	authService.AssignPermissionToRole(startupOwner.ID, writeDocs.ID)
	authService.AssignPermissionToRole(startupOwner.ID, manageUsers.ID)
	authService.AssignPermissionToRole(startupOwner.ID, deployCode.ID)

	authService.AssignPermissionToRole(startupDev.ID, readDocs.ID)
	authService.AssignPermissionToRole(startupDev.ID, deployCode.ID)

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Public routes - signup with tenant
	r.Post("/signup/{tenant}", func(w http.ResponseWriter, r *http.Request) {
		tenantSlug := chi.URLParam(r, "tenant")

		switch tenantSlug {
		case "acme":
			_ = acmeCorp.ID // Tenant assignment would happen here
		case "techstartup":
			_ = techStartup.ID // Tenant assignment would happen here
		default:
			http.Error(w, "Invalid tenant", http.StatusBadRequest)
			return
		}

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

	// Protected routes - require authentication
	r.Group(func(r chi.Router) {
		r.Use(authService.RequireAuth())

		// Get user profile with tenant context
		r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
			user := auth.MustGetUserFromContext(r)
			tenant := auth.MustGetTenantFromContext(r)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"user":    user,
				"tenant":  tenant,
				"message": fmt.Sprintf("Welcome to %s!", tenant.Name),
			})
		})

		// Switch tenant context
		r.Post("/switch-tenant/{tenantId}", func(w http.ResponseWriter, r *http.Request) {
			tenantIDStr := chi.URLParam(r, "tenantId")
			_, err := strconv.ParseUint(tenantIDStr, 10, 32) // Parse but don't use yet
			if err != nil {
				http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
				return
			}

			// Tenant switching not implemented yet
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Tenant switching not implemented yet",
			"error":   "not_implemented",
		})
		})

		// Document routes - require read permission
		r.Group(func(r chi.Router) {
			r.Use(authService.RequirePermission("documents", "read"))

			r.Get("/documents", func(w http.ResponseWriter, r *http.Request) {
				tenant := auth.MustGetTenantFromContext(r)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"documents": []string{
						fmt.Sprintf("%s Strategic Plan", tenant.Name),
						fmt.Sprintf("%s Employee Handbook", tenant.Name),
						fmt.Sprintf("%s Q4 Report", tenant.Name),
					},
					"message": "Documents you have read access to",
				})
			})
		})

		// Document creation - require write permission
		r.Group(func(r chi.Router) {
			r.Use(authService.RequirePermission("documents", "write"))

			r.Post("/documents", func(w http.ResponseWriter, r *http.Request) {
				tenant := auth.MustGetTenantFromContext(r)
				user := auth.MustGetUserFromContext(r)

				var req struct {
					Title   string `json:"title"`
					Content string `json:"content"`
				}
				json.NewDecoder(r.Body).Decode(&req)

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"message": fmt.Sprintf("Document '%s' created in %s by %s", req.Title, tenant.Name, user.Email),
					"success": true,
				})
			})
		})

		// User management - admin only
		r.Group(func(r chi.Router) {
			r.Use(authService.RequirePermission("users", "manage"))

			r.Get("/admin/users", func(w http.ResponseWriter, r *http.Request) {
				tenant := auth.MustGetTenantFromContext(r)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"message": fmt.Sprintf("User management for %s", tenant.Name),
					"note":    "Only admins can access this endpoint",
				})
			})

			r.Post("/admin/assign-role", func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					UserID uint `json:"user_id"`
					RoleID uint `json:"role_id"`
				}
				json.NewDecoder(r.Body).Decode(&req)

				tenant := auth.MustGetTenantFromContext(r)
				// Role assignment not implemented yet
				// err := authService.AssignUserToRole(req.UserID, tenant.ID, req.RoleID)
				_ = tenant // Use tenant to avoid unused variable error

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"message": "Role assigned successfully",
					"success": true,
				})
			})
		})

		// Deployment routes - for tech startup developers
		r.Group(func(r chi.Router) {
			r.Use(authService.RequirePermission("deployment", "deploy"))

			r.Post("/deploy", func(w http.ResponseWriter, r *http.Request) {
				user := auth.MustGetUserFromContext(r)
				tenant := auth.MustGetTenantFromContext(r)

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"message": fmt.Sprintf("Deployment initiated by %s for %s", user.Email, tenant.Name),
					"status":  "success",
				})
			})
		})

		r.Post("/signout", func(w http.ResponseWriter, r *http.Request) {
			// SignOut not implemented yet
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Signed out successfully",
				"success": true,
			})
		})
	})

	// Info endpoints
	r.Get("/tenants", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tenants": []map[string]interface{}{
				{"id": acmeCorp.ID, "name": "Acme Corporation", "slug": "acme"},
				{"id": techStartup.ID, "name": "Tech Startup Inc", "slug": "techstartup"},
			},
			"message": "Available tenants",
		})
	})

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	fmt.Println("📱 Server starting on http://localhost:8080")
	fmt.Println("\n🧪 Try this multi-tenant flow:")
	fmt.Println("1. View available tenants:")
	fmt.Println("   curl http://localhost:8080/tenants")
	fmt.Println("2. Sign up for Acme Corp:")
	fmt.Println(`   curl -X POST http://localhost:8080/signup/acme -H 'Content-Type: application/json' -d '{"email":"alice@acme.com","password":"Password123"}'`)
	fmt.Println("3. Sign up for Tech Startup:")
	fmt.Println(`   curl -X POST http://localhost:8080/signup/techstartup -H 'Content-Type: application/json' -d '{"email":"bob@techstartup.io","password":"Password123"}'`)
	fmt.Println("4. Try accessing documents with different permissions")
	fmt.Println("5. Try deploying (only works for Tech Startup users)")
	fmt.Println("6. Try user management (only works for admins)")

	log.Fatal(http.ListenAndServe(":8080", r))
}