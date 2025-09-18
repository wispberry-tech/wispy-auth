# Wispy Auth

A production-ready Go authentication library with comprehensive security features, flexible architecture, and multi-tenant support. Built with pure SQL (PostgreSQL) for maximum performance and compatibility.

## 🚀 Features

### Core Authentication
- ✅ **Email/Password authentication** with advanced security
- ✅ **Multiple OAuth2 providers** (Google, GitHub, Discord)
- ✅ **Session token generation & validation**
- ✅ **Password hashing with bcrypt**
- ✅ **Multiple provider support per user**

### 🔒 Advanced Security Features
- ✅ **Password reset flow** with secure token generation
- ✅ **Email verification system** with customizable expiry
- ✅ **Account lockout mechanism** with configurable attempts
- ✅ **Login attempt tracking** and security audit logging
- ✅ **Session management** with device tracking
- ✅ **IP address logging** and location tracking
- ✅ **Device fingerprinting** for enhanced security
- ✅ **Security event auditing** for comprehensive logging
- ✅ **Configurable security policies** (password strength, lockout duration, etc.)
- ✅ **Two-factor authentication ready** (infrastructure in place)

### 🏢 Multi-Tenant Architecture
- ✅ **Complete multi-tenant support** with roles & permissions
- ✅ **Role-based access control (RBAC)**
- ✅ **Granular permission system**
- ✅ **Tenant isolation** and management
- ✅ **Flexible tenant assignment**

### 🛠 Developer Experience
- ✅ **Pure SQL implementation** (no ORM dependencies)
- ✅ **Flexible database schema support**
- ✅ **Simplified HTTP handlers** with structured responses
- ✅ **Configurable table and column names**
- ✅ **Comprehensive error handling**
- ✅ **Production-ready defaults**
- ✅ **Built-in email integration**

## 📦 Installation

```bash
go get github.com/wispberry-tech/wispy-auth
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file:

```bash
# Database (PostgreSQL)
DATABASE_URL=postgresql://username:password@localhost:5432/auth_db


# Google OAuth
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret

# Discord OAuth
DISCORD_CLIENT_ID=your-discord-oauth-client-id
DISCORD_CLIENT_SECRET=your-discord-oauth-client-secret
```

## 🚦 Quick Start

The following is a quick start example. For a more complete, production-ready example, see the `example` directory.

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	auth "github.com/wispberry-tech/wispy-auth"
)

// Implement your email service
type YourEmailService struct{}

func (e *YourEmailService) SendVerificationEmail(email, token string) error {
	log.Printf("📧 Sending verification email to %s with token %s", email, token)
	return nil
}

func (e *YourEmailService) SendPasswordResetEmail(email, token string) error {
	log.Printf("📧 Sending password reset email to %s with token %s", email, token)
	return nil
}

func (e *YourEmailService) SendWelcomeEmail(email, name string) error {
	log.Printf("📧 Sending welcome email to %s (%s)", name, email)
	return nil
}

func main() {
	// Initialize email service
	emailService := &YourEmailService{}

	// Initialize with security-enhanced configuration
	cfg := auth.Config{
		DatabaseDSN: os.Getenv("DATABASE_URL"),
		
		// Built-in email service integration
		EmailService: emailService,

		// Storage configuration with flexible schema
		StorageConfig: auth.DefaultStorageConfig(),
		
		// Enhanced security configuration
		SecurityConfig: auth.DefaultSecurityConfig(),
		
		// OAuth providers
		OAuthProviders: map[string]auth.OAuthProviderConfig{
			"google": {
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/api/auth/oauth/callback?provider=google",
			},
			// Add other providers as needed...
		},
	}

	// Initialize auth service
	authService, err := auth.NewAuthService(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}

	// Initialize Chi router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Mount auth routes with the new simplified API
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
		
		// OAuth with redirect handling  
		r.Get("/oauth", func(w http.ResponseWriter, r *http.Request) {
			provider := r.URL.Query().Get("provider")
			result := authService.OAuthHandler(w, r, provider)
			if result.URL != "" {
				http.Redirect(w, r, result.URL, http.StatusTemporaryRedirect)
				return
			}
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(result)
		})

		// ... other routes follow the same pattern
	})

	// Your protected app routes
	r.Group(func(r chi.Router) {
		r.Use(authService.RequireAuth())
		
		r.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
			user := auth.MustGetUserFromContext(r)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(user)
		})
		
		// Admin routes with role protection
		r.Group(func(r chi.Router) {
			r.Use(authService.RequireRole("admin"))
			
			r.Get("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{
					"message": "Admin access granted!",
				})
			})
		})
	})

	log.Println("🚀 Server starting on :8080")
	log.Println("📍 Auth endpoints: http://localhost:8080/api/auth/*")
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

**Your authentication system is ready with a great developer experience:**

✅ **Simplified Handlers** - One line per endpoint, `authService.SignUpHandler(r)` and you're done!  
✅ **Full Control** - You control the HTTP response, status code, and encoding.
✅ **Built-in Email Integration** - Configure your email service once, and it works for verification, password resets, and welcome emails.
✅ **Zero Boilerplate** - Each handler handles validation, emails, and errors automatically.
✅ **Enterprise Security** - Built-in protection, audit logging, and compliance features.
✅ **Production Ready** - OAuth, sessions, multi-tenant, RBAC out of the box.

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/signup` | User registration |
| POST | `/api/auth/signin` | User login |
| GET | `/api/auth/validate` | Validate session token |
| POST | `/api/auth/forgot-password` | Request password reset |
| POST | `/api/auth/reset-password` | Reset password with token |
| POST | `/api/auth/verify-email` | Verify email address with token |
| GET | `/api/auth/oauth` | OAuth redirect (e.g., `/api/auth/oauth?provider=google`) |
| GET | `/api/auth/oauth/callback` | OAuth callback |
| GET | `/api/auth/providers` | List available OAuth providers |
| POST | `/api/auth/resend-verification` | Resend verification email (protected) |
| GET | `/api/auth/sessions` | List user sessions (protected) |
| DELETE | `/api/auth/sessions/{id}` | Revoke specific session (protected) |
| POST | `/api/auth/logout-all` | Revoke all sessions (protected) |

## 🎯 Simplified HTTP Handlers

### 🚀 Perfect Balance: Control + Simplicity

Mount auth routes exactly where you want them with **perfect control**:

```go
// Mount routes exactly where you want them - super flexible!
r.Route("/api/auth", func(r chi.Router) {
    // Public routes - perfect balance of control and simplicity!
    r.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignUpHandler(r)         // ✅ Returns structured response
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)               // ✅ You control the HTTP response
        json.NewEncoder(w).Encode(result)              // ✅ You choose how to encode
    })
    
    r.Post("/signin", func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignInHandler(r)         // ✅ Complete login logic
        w.Header().Set("Content-Type", "application/json") 
        w.WriteHeader(result.StatusCode)
        json.NewEncoder(w).Encode(result)
    })
    
    r.Post("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
        result := authService.ForgotPasswordHandler(r) // ✅ Handles validation + emails
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode) 
        json.NewEncoder(w).Encode(result)
    })
    
    // OAuth with redirect handling  
    r.Get("/oauth", func(w http.ResponseWriter, r *http.Request) {
        provider := r.URL.Query().Get("provider")
        result := authService.OAuthHandler(w, r, provider)
        if result.URL != "" {
            http.Redirect(w, r, result.URL, http.StatusTemporaryRedirect) // ✅ You control redirects
            return
        }
        w.WriteHeader(result.StatusCode)
        json.NewEncoder(w).Encode(result)
    })
})

// You can still add custom logic around the handlers
r.Post("/auth/register", func(w http.ResponseWriter, r *http.Request) {
    result := authService.SignUpHandler(r)
    // Add custom business logic here
    if result.User != nil {
        // createUserProfile(result.User.ID)           // ✅ Your custom logic
        // trackSignupEvent(result.User.Email)         // ✅ Your analytics
    }
    w.WriteHeader(result.StatusCode)
    json.NewEncoder(w).Encode(result)
})
```

### 🛡️ Built-in Middleware Protection

Create protected routes with role/permission-based access:

```go
// Your app routes with auth protection
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuth())  // Basic authentication
    
    r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
        user := auth.MustGetUserFromContext(r)  // Get authenticated user
        json.NewEncoder(w).Encode(user)
    })
    
    // Admin-only routes
    r.Group(func(r chi.Router) {
        r.Use(authService.RequireRole("admin"))
        
        r.Get("/admin/users", adminUsersHandler)
        r.Delete("/admin/users/{id}", deleteUserHandler)
    })
    
    // Permission-based routes
    r.Group(func(r chi.Router) {
        r.Use(authService.RequirePermission("billing.manage"))
        
        r.Get("/billing", billingHandler)
        r.Post("/billing/invoice", createInvoiceHandler)
    })
})
```

### 🎨 Every Handler Includes

Each handler method automatically handles:

- ✅ **Input validation** using `go-playground/validator`
- ✅ **JSON request/response** parsing and formatting
- ✅ **Error handling** with proper HTTP status codes
- ✅ **Email integration** (verification, password reset, welcome)
- ✅ **Security features** (IP tracking, rate limiting, etc.)
- ✅ **Async email sending** to prevent blocking

### 🔧 Custom Integration

Need more control? You can still call the core service methods directly:

```go
// Custom signup with your own business logic
r.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
    // Parse request however you want
    var req MyCustomSignUpRequest
    json.NewDecoder(r.Body).Decode(&req)
    
    // Call the auth service directly
    user, err := authService.SignUp(auth.SignUpRequest{
        Email:     req.Email,
        Password:  req.Password,
        Username:  req.Username,
        FirstName: req.FirstName,
        LastName:  req.LastName,
    })
    
    // Handle response with your custom logic
    if err != nil {
        // Your custom error handling
        return
    }
    
    // Your custom success logic
    // createUserProfile(user.ID, req.AdditionalData)
    // sendWelcomeSlackMessage(req.Email)
    
    json.NewEncoder(w).Encode(user)
})
```

## 🔒 Security Features

### Password Reset Flow
```go
// 1. Initiate password reset (via handler)
// POST /api/auth/forgot-password with {"email": "user@example.com"}
// The handler calls authService.InitiatePasswordReset and sends an email.

// 2. Reset password with token (via handler)
// POST /api/auth/reset-password with {"token": "...", "new_password": "..."}
// The handler calls authService.ResetPassword.
```

### Email Verification
```go
// 1. Resend verification email (via handler, protected route)
// POST /api/auth/resend-verification

// 2. Verify email with token (via handler)
// POST /api/auth/verify-email with {"token": "..."}
```

### Session Management
```go
// Get all user sessions (via handler, protected route)
// GET /api/auth/sessions

// Revoke specific session (via handler, protected route)
// DELETE /api/auth/sessions/{sessionID}

// Revoke all sessions (logout everywhere) (via handler, protected route)
// POST /api/auth/logout-all
```

### Security Event Logging
All security-related events are automatically logged to the `security_events` table:
- Login attempts (successful/failed)
- Account lockouts
- Password resets
- Email verifications
- Session creation/termination

## 🗄 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    username VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50),
    provider_id VARCHAR(255),
    
    -- Email Security
    email_verified BOOLEAN DEFAULT false,
    email_verified_at TIMESTAMP,
    verification_token TEXT,
    
    -- Password Security
    password_reset_token TEXT,
    password_reset_expires_at TIMESTAMP,
    password_changed_at TIMESTAMP,
    
    -- Login Security
    login_attempts INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP,
    locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    
    -- Location & Device Tracking
    last_known_ip VARCHAR(45),
    last_login_location VARCHAR(255),
    
    -- Two-Factor Authentication (ready)
    two_factor_enabled BOOLEAN DEFAULT false,
    two_factor_secret TEXT,
    backup_codes TEXT, -- JSON array
    
    -- Account Security
    is_active BOOLEAN DEFAULT true,
    is_suspended BOOLEAN DEFAULT false,
    suspended_at TIMESTAMP,
    suspend_reason TEXT,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Sessions Table
```sql
CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP,
    csrf_token TEXT,
    
    -- Device & Location Tracking
    device_fingerprint VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    location VARCHAR(255),
    
    -- Security Features
    is_active BOOLEAN DEFAULT true,
    last_activity TIMESTAMP,
    requires_two_factor BOOLEAN DEFAULT false,
    two_factor_verified BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Security Events Table
```sql
CREATE TABLE security_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    tenant_id INTEGER, -- For multi-tenant setups
    event_type VARCHAR(50) NOT NULL, -- login_success, login_failed, etc.
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    metadata JSONB, -- Additional context
    created_at TIMESTAMP DEFAULT NOW()
);
```

## 🏢 Multi-Tenant Support

### Enable Multi-Tenant Mode
```go
cfg.StorageConfig.MultiTenant = auth.MultiTenantConfig{
    Enabled:         true,
    DefaultTenantID: 1,
    
    // Customize table names if needed
    TenantsTable:         "tenants",
    RolesTable:           "roles",
    PermissionsTable:     "permissions",
    RolePermissionsTable: "role_permissions",
    UserTenantsTable:     "user_tenants",
}
```

### Multi-Tenant Operations
```go
// Create tenant
tenant, err := authService.CreateTenant("Acme Corp", "acme", "acme.example.com")

// Create roles
adminRole, err := authService.CreateRole(tenant.ID, "admin", "Administrator", false)
memberRole, err := authService.CreateRole(tenant.ID, "member", "Team Member", false)

// Create permissions
userReadPerm, err := authService.CreatePermission("users.read", "users", "read", "Read users")
userWritePerm, err := authService.CreatePermission("users.write", "users", "write", "Manage users")

// Assign permissions to roles
authService.AssignPermissionToRole(adminRole.ID, userReadPerm.ID)
authService.AssignPermissionToRole(adminRole.ID, userWritePerm.ID)

// Assign user to tenant with role
authService.AssignUserToTenant(userID, tenant.ID, adminRole.ID)

// Check permissions
hasPermission, err := authService.UserHasPermission(userID, tenant.ID, "users.write")
```

## 📊 Response Types

All handlers return structured response types:

```go
type SignUpResponse struct {
    Token                      string `json:"token"`
    User                       *User  `json:"user"`
    RequiresEmailVerification bool   `json:"requires_email_verification"`
    StatusCode                int    `json:"-"`
    Error                     string `json:"error,omitempty"`
}

type SignInResponse struct {
    Token            string     `json:"token"`
    User             *User      `json:"user"`
    SessionID        string     `json:"session_id"`
    Requires2FA      bool       `json:"requires_2fa"`
    SessionExpiresAt time.Time  `json:"session_expires_at"`
    StatusCode       int        `json:"-"`
    Error            string     `json:"error,omitempty"`
}
```

## ⚙️ Configuration Options

### Security Configuration
```go
type SecurityConfig struct {
	// Email verification
	RequireEmailVerification bool
	VerificationTokenExpiry  time.Duration

	// Password security
	PasswordMinLength      int
	PasswordRequireUpper   bool
	PasswordRequireLower   bool
	PasswordRequireNumber  bool
	PasswordRequireSpecial bool
	PasswordResetExpiry    time.Duration

	// Login security
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	SessionLifetime  time.Duration
	RequireTwoFactor bool
}
```

### Flexible Schema Configuration
```go
cfg.StorageConfig = auth.StorageConfig{
    UsersTable:    "members",           // Your existing user table
    SessionsTable: "auth_sessions",     // Your session table
    SecurityEventsTable: "audit_log",  // Your security events table
    
    UserColumns: auth.UserColumnMapping{
        ID:           "member_id",      // Your primary key column
        Email:        "email_address",  // Your email column
        PasswordHash: "pwd_hash",       // Your password column
        Username:     "username",      // Your username column
        FirstName:    "first_name",    // Your first name column
        LastName:     "last_name",     // Your last name column
        // ... map all required fields to your schema
    },
    // ... other column mappings
}
```

## 🔐 Security Best Practices

1. **Always use HTTPS** in production
3. **Monitor security events** for suspicious activity
4. **Implement rate limiting** at the application level
5. **Use strong password policies**
6. **Enable email verification** for new accounts
7. **Set appropriate session timeouts**
8. **Implement proper logging and monitoring**

## 🚀 Production Recommendations

1. **Database**: Use connection pooling and read replicas
2. **Caching**: Consider Redis for session storage in high-traffic applications
3. **Monitoring**: Set up security event alerts
4. **Backup**: Regular database backups with encryption
5. **Updates**: Keep dependencies updated
6. **Testing**: Comprehensive security testing

## 🛡️ Chi Middleware Support

The library includes comprehensive middleware for the [Chi router](https://github.com/go-chi/chi) with authentication, role-based, permission-based, and tenant-based protection.

### Basic Authentication Middleware

```go
package main

import (
    "github.com/go-chi/chi/v5"
    auth "github.com/wispberry-tech/wispy-auth"
)

func main() {
    r := chi.NewRouter()
    
    // Initialize auth service...
    
    // Protected routes requiring authentication
    r.Group(func(r chi.Router) {
        r.Use(authService.RequireAuth())
        
        r.Get("/profile", getUserProfile)
        r.Put("/profile", updateUserProfile)
        r.Get("/dashboard", getDashboard)
    })
}
```

### Role-Based Protection

```go
// Protect routes requiring specific roles
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuthAndRole("admin", "moderator"))
    
    r.Get("/admin", adminDashboard)
    r.Delete("/users/{userID}", deleteUser)
})

// Role-based protection in specific tenant
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuthRoleAndTenant(tenantID, "admin"))
    
    r.Get("/tenant/{tenantID}/settings", getTenantSettings)
    r.Put("/tenant/{tenantID}/settings", updateTenantSettings)
})
```

### Permission-Based Protection

```go
// Protect routes requiring specific permissions
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuthAndPermission("users.read", "users.write"))
    
    r.Get("/users", listUsers)
    r.Post("/users", createUser)
})

// Permission-based protection in specific tenant
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuthPermissionAndTenant(tenantID, "billing.manage"))
    
    r.Get("/tenant/{tenantID}/billing", getBilling)
    r.Post("/tenant/{tenantID}/billing/invoice", createInvoice)
})
```

### Tenant-Based Protection

```go
// Ensure user belongs to a specific tenant
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuthAndTenant(tenantID))
    
    r.Get("/tenant/{tenantID}/data", getTenantData)
    r.Post("/tenant/{tenantID}/resources", createResource)
})

// Dynamic tenant extraction from URL or headers
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuth())
    r.Use(authService.RequireTenant()) // Extracts from X-Tenant-ID header or URL params
    
    r.Get("/data", getTenantSpecificData)
})
```

### Custom Middleware Configuration

```go
// Custom token extraction and error handling
config := auth.MiddlewareConfig{
    TokenExtractor: func(r *http.Request) string {
        // Custom logic: check cookie, query param, etc.
        if token := r.Header.Get("X-API-Key"); token != "" {
            return token
        }
        return r.URL.Query().Get("token")
    },
    
    TenantExtractor: func(r *http.Request) uint {
        // Extract tenant from subdomain
        host := r.Host
        if strings.Contains(host, ".") {
            subdomain := strings.Split(host, ".")[0]
            // return getTenantIDBySubdomain(subdomain)
        }
        return 0
    },
    
    ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
        // Custom error response format
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(statusCode)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": false,
            "error": err.Error(),
            "code": statusCode,
            "timestamp": time.Now().UTC(),
        })
    },
    
    SkipAuth: func(r *http.Request) bool {
        // Skip auth for health checks, webhooks, etc.
        return r.URL.Path == "/health" || 
               r.URL.Path == "/webhooks/stripe" ||
               strings.HasPrefix(r.URL.Path, "/public/")
    },
}

r.Use(authService.RequireAuth(config))
```

### Context Helper Functions

Extract authenticated user and tenant data from request context:

```go
func getUserProfile(w http.ResponseWriter, r *http.Request) {
    // Get authenticated user from context
    user, ok := auth.GetUserFromContext(r)
    if !ok {
        http.Error(w, "User not found in context", http.StatusInternalServerError)
        return
    }
    
    // Get tenant from context (if using tenant middleware)
    tenant, ok := auth.GetTenantFromContext(r)
    if ok {
        log.Printf("User %d accessing tenant %s", user.ID, tenant.Name)
    }
    
    // Or just get tenant ID
    if tenantID, ok := auth.GetTenantIDFromContext(r); ok {
        log.Printf("User %d in tenant %d", user.ID, tenantID)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

// Panic-style helpers for when you're certain context is set
func adminDashboard(w http.ResponseWriter, r *http.Request) {
    user := auth.MustGetUserFromContext(r)    // Panics if not found
    tenant := auth.MustGetTenantFromContext(r) // Panics if not found
    
    // Handle admin dashboard logic...
}
```

### Middleware Chaining

```go
// Chain multiple middleware together
r.Group(func(r chi.Router) {
    r.Use(authService.Chain(
        authService.RequireAuth(),
        authService.RequireTenant(),
        authService.RequireRole("admin", "manager"),
    ))
    
    r.Get("/management", managementPanel)
})

// Or use convenience combinations
r.Group(func(r chi.Router) {
    // Combines auth + role checking
    r.Use(authService.RequireAuthAndRole("admin"))
    r.Get("/admin", adminPanel)
})

r.Group(func(r chi.Router) {
    // Combines auth + permission checking
    r.Use(authService.RequireAuthAndPermission("reports.view"))
    r.Get("/reports", viewReports)
})

r.Group(func(r chi.Router) {
    // Combines auth + tenant checking
    r.Use(authService.RequireAuthAndTenant(tenantID))
    r.Get("/tenant-data", getTenantData)
})
```

### Available Middleware Functions

| Middleware | Purpose | Usage |
|------------|---------|-------|
| `RequireAuth()` | Basic authentication | Validates session token |
| `RequireRole(roles...)` | Role-based protection | Check user has any of the specified roles |
| `RequireRoleInTenant(tenantID, roles...)` | Tenant-specific role protection | Check role in specific tenant |
| `RequirePermission(permissions...)` | Permission-based protection | Check user has all specified permissions |
| `RequirePermissionInTenant(tenantID, permissions...)` | Tenant-specific permission protection | Check permissions in specific tenant |
| `RequireTenant(tenantID...)` | Tenant membership validation | Ensure user belongs to tenant |
| `Chain(middlewares...)` | Combine multiple middleware | Execute middleware in sequence |

### Convenience Combinations

| Middleware | Combines |
|------------|----------|
| `RequireAuthAndRole(roles...)` | `RequireAuth()` + `RequireRole()` |
| `RequireAuthAndPermission(permissions...)` | `RequireAuth()` + `RequirePermission()` |
| `RequireAuthAndTenant(tenantID...)` | `RequireAuth()` + `RequireTenant()` |
| `RequireAuthRoleAndTenant(tenantID, roles...)` | `RequireAuth()` + `RequireRoleInTenant()` |
| `RequireAuthPermissionAndTenant(tenantID, permissions...)` | `RequireAuth()` + `RequirePermissionInTenant()` |

## 📚 Dependencies

```go
require (
    github.com/go-chi/chi/v5 v5.0.12
    github.com/go-playground/validator/v10 v10.22.1
    github.com/golang-jwt/jwt/v5 v5.3.0
    github.com/jackc/pgx/v5 v5.6.0
    github.com/pquerna/otp v1.5.0
    golang.org/x/crypto v0.42.0
    golang.org/x/oauth2 v0.31.0
)
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

**Wispy Auth** - Production-ready authentication with security at its core. 🛡️