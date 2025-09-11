# Nucleus Auth

A production-ready Go authentication library with comprehensive security features, flexible architecture, and multi-tenant support. Built with pure SQL (PostgreSQL) for maximum performance and compatibility.

## 🚀 Features

### Core Authentication
- ✅ **Email/Password authentication** with advanced security
- ✅ **Multiple OAuth2 providers** (Google, GitHub, Discord)
- ✅ **JWT token generation & validation**
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
- ✅ **Clean response-based handlers** (no HTTP coupling in library)
- ✅ **Configurable table and column names**
- ✅ **Comprehensive error handling**
- ✅ **Production-ready defaults**

## 📦 Installation

```bash
go get github.com/wispberry-tech/nucleus-auth
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file:

```bash
# Database (PostgreSQL)
DATABASE_URL=postgresql://username:password@localhost:5432/auth_db

# JWT Secret (change this in production!)
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters-long

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

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/wispberry-tech/nucleus-auth"
)

func main() {
	// Initialize with security-enhanced configuration
	cfg := auth.Config{
		DatabaseDSN: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		
		// Storage configuration with flexible schema
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
		},
		
		// OAuth providers
		OAuthProviders: map[string]auth.OAuthProviderConfig{
			"google": {
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/auth/oauth/callback?provider=google",
			},
			// Add other providers as needed...
		},
	}

	// Initialize auth service
	authService, err := auth.NewAuthService(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}

	// Set up routes with new handler pattern
	http.HandleFunc("/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		var req auth.SignUpRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		
		// Extract security context
		ip := extractIP(r)
		userAgent := r.Header.Get("User-Agent")
		
		// Call handler - returns structured response
		response := authService.HandleSignUp(req, ip, userAgent)
		
		// Handle response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		
		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}
		
		// Send verification email if needed
		if response.RequiresEmailVerification {
			// Your email sending logic here
			sendVerificationEmail(response.User.Email, response.User.VerificationToken)
		}
		
		json.NewEncoder(w).Encode(response)
	})

	// Other routes following the same pattern...
	setupAuthRoutes(authService)

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func extractIP(r *http.Request) string {
	// Extract IP from X-Forwarded-For, X-Real-IP, or RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
```

## 🎯 Handler Architecture

The library uses a clean response-based architecture that separates authentication logic from HTTP handling:

### Before (Old HTTP-coupled handlers):
```go
// ❌ Old way - tightly coupled to HTTP
authService.SignUpHandler(w, r) // Handles HTTP directly
```

### After (New response-based handlers):
```go
// ✅ New way - returns structured responses
response := authService.HandleSignUp(request, ip, userAgent)

// You handle HTTP response and additional logic
w.WriteHeader(response.StatusCode)
if response.RequiresEmailVerification {
    sendVerificationEmail(response.User.Email) // Your email logic
}
json.NewEncoder(w).Encode(response)
```

### Available Handlers

```go
// Authentication
response := authService.HandleSignUp(signUpRequest, ip, userAgent)
response := authService.HandleSignIn(signInRequest, ip, userAgent)
response := authService.HandleValidate(token)

// Password Management
response := authService.HandleForgotPassword(forgotRequest)
response := authService.HandleResetPassword(resetRequest)

// Email Verification
response := authService.HandleResendVerification(token)
response := authService.HandleVerifyEmail(verifyRequest)

// Session Management
response := authService.HandleGetSessions(token)
response := authService.HandleRevokeSession(sessionID)
response := authService.HandleRevokeAllSessions(token)

// OAuth
response := authService.HandleGetOAuth(provider)
response := authService.HandleOAuthCallbackRequest(provider, code)
```

## 🔒 Security Features

### Password Reset Flow
```go
// 1. Initiate password reset
response := authService.HandleForgotPassword(auth.ForgotPasswordRequest{
    Email: "user@example.com",
})

// 2. Send reset email (your implementation)
if response.StatusCode == 200 {
    sendPasswordResetEmail(email, resetToken) // Your email logic
}

// 3. Reset password with token
response := authService.HandleResetPassword(auth.ResetPasswordRequest{
    Token:       "reset-token-from-email",
    NewPassword: "newSecurePassword123",
})
```

### Email Verification
```go
// 1. Send verification email
response := authService.HandleResendVerification(userToken)

// 2. Verify email with token
response := authService.HandleVerifyEmail(auth.VerifyEmailRequest{
    Token: "verification-token-from-email",
})
```

### Session Management
```go
// Get all user sessions
response := authService.HandleGetSessions(userToken)

// Revoke specific session
response := authService.HandleRevokeSession("session-id")

// Revoke all sessions (logout everywhere)
response := authService.HandleRevokeAllSessions(userToken)
```

### Security Event Logging
All security-related events are automatically logged:
- Login attempts (successful/failed)
- Account lockouts
- Password resets
- Email verifications
- Session creation/termination

## 🗄 Database Schema

### Enhanced Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    name VARCHAR(255),
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

### Enhanced Sessions Table
```sql
CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP,
    
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
    TenantsTable:         "organizations",
    RolesTable:          "roles",
    PermissionsTable:    "permissions",
    RolePermissionsTable: "role_permissions",
    UserTenantsTable:    "user_tenants",
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
    // Password Policy
    MinPasswordLength   int
    RequireUppercase    bool
    RequireLowercase    bool
    RequireNumbers      bool
    RequireSpecialChars bool
    
    // Login Protection
    MaxLoginAttempts     int
    LoginLockoutDuration time.Duration
    
    // Session Security
    SessionTimeout              time.Duration
    MaxActiveSessions           int
    RequireDeviceVerification   bool
    
    // Two-Factor Authentication
    Force2FA       bool
    Allow2FABypass bool
    
    // Email Security
    RequireEmailVerification bool
    EmailVerificationExpiry  time.Duration
    
    // Password Reset
    PasswordResetExpiry time.Duration
    
    // Rate Limiting
    EnableRateLimiting   bool
    RateLimitWindow      time.Duration
    RateLimitMaxRequests int
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
        Name:         "full_name",      // Your name column
        // ... map all required fields to your schema
    },
    // ... other column mappings
}
```

## 🔐 Security Best Practices

1. **Always use HTTPS** in production
2. **Rotate JWT secrets** regularly
3. **Monitor security events** for suspicious activity
4. **Implement rate limiting** at the application level
5. **Use strong password policies**
6. **Enable email verification** for new accounts
7. **Set appropriate session timeouts**
8. **Implement proper logging and monitoring**

## 🚀 Production Recommendations

1. **Database**: Use connection pooling and read replicas
2. **Caching**: Implement Redis for session storage
3. **Monitoring**: Set up security event alerts
4. **Backup**: Regular database backups with encryption
5. **Updates**: Keep dependencies updated
6. **Testing**: Comprehensive security testing

## 📚 Dependencies

```go
require (
    github.com/jackc/pgx/v5 v5.6.0
    golang.org/x/crypto v0.42.0
    golang.org/x/oauth2 v0.31.0
)
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.

---

**Nucleus Auth** - Production-ready authentication with security at its core. 🛡️