# 🔐 Wispy Auth

**Enterprise-grade Go authentication library with comprehensive security features, multi-tenant architecture, and referral system.**

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-comprehensive-brightgreen)](./docs/)

Built with pure SQL (PostgreSQL/SQLite) for maximum performance, security, and compatibility. No ORM dependencies, maximum control.

---

## 🚀 Why Wispy Auth?

- **🏢 Enterprise-Ready**: Multi-tenant architecture with RBAC out of the box
- **🔒 Security-First**: Separated user/security tables, 25+ security fields, comprehensive audit logging
- **🎯 Referral System**: Built-in referral codes with role-based limits
- **⚡ High Performance**: Pure SQL implementation, no ORM overhead
- **🛠 Developer-Friendly**: Structured HTTP responses, minimal setup required
- **🔧 Highly Configurable**: Customize everything from table names to security policies

---

## 📦 Installation

```bash
go get github.com/wispberry-tech/wispy-auth
```

## 🎯 Quick Start

```go
package main

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/go-chi/chi/v5"
    auth "github.com/wispberry-tech/wispy-auth"
)

func main() {
    // Configure the auth service
    config := auth.Config{
        DatabaseDSN: "postgresql://user:pass@localhost/db",
        EmailService: &YourEmailService{}, // Implement auth.EmailService
        SecurityConfig: auth.SecurityConfig{
            RequireEmailVerification: true,
            PasswordMinLength:        8,
            MaxLoginAttempts:         5,
            LockoutDuration:          15 * time.Minute,
            SessionLifetime:          24 * time.Hour,

            // Referral System (NEW!)
            DefaultUserRoleName: "default-user",
            MaxInviteesPerRole: map[string]int{
                "default-user": 5,
                "premium":      20,
                "admin":        100,
            },
        },
        // Dynamic OAuth providers
        OAuthProviders: map[string]auth.OAuthProviderConfig{
            "google": auth.NewGoogleOAuthProvider(
                "your-client-id",
                "your-client-secret",
                "http://localhost:8080/oauth/callback",
            ),
        },
    }

    authService, err := auth.NewAuthService(config)
    if err != nil {
        panic(err)
    }

    r := chi.NewRouter()

    // Simple, powerful handlers
    r.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignUpHandler(r)  // Single line!
        w.WriteHeader(result.StatusCode)
        json.NewEncoder(w).Encode(result)
    })

    r.Post("/signin", func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignInHandler(r)
        w.WriteHeader(result.StatusCode)
        json.NewEncoder(w).Encode(result)
    })

    // Protected routes with middleware
    r.Group(func(r chi.Router) {
        r.Use(authService.RequireAuth())

        r.Post("/referrals/generate", func(w http.ResponseWriter, r *http.Request) {
            result := authService.GenerateReferralCodeHandler(r)
            w.WriteHeader(result.StatusCode)
            json.NewEncoder(w).Encode(result)
        })
    })

    http.ListenAndServe(":8080", r)
}
```

---

## 🌟 Core Features

### 🔐 Authentication & Security

| Feature | Description | Status |
|---------|-------------|---------|
| **Email/Password Auth** | Secure authentication with bcrypt hashing | ✅ |
| **OAuth2 Integration** | Dynamic provider support (Google, GitHub, Discord, custom) | ✅ |
| **Session Management** | JWT-like tokens with device tracking | ✅ |
| **Password Reset** | Secure token-based password reset flow | ✅ |
| **Email Verification** | Configurable email verification system | ✅ |
| **Account Lockout** | Brute force protection with configurable attempts | ✅ |
| **Security Auditing** | Comprehensive security event logging | ✅ |
| **Two-Factor Authentication** | Complete 2FA implementation with email codes and backup codes | ✅ |

### 🏢 Multi-Tenant Architecture

| Feature | Description | Status |
|---------|-------------|---------|
| **Tenant Management** | Complete multi-tenant organization support | ✅ |
| **Role-Based Access Control** | Granular RBAC with custom roles and permissions | ✅ |
| **Tenant Isolation** | Complete data isolation between tenants | ✅ |
| **Permission System** | Fine-grained permission management | ✅ |
| **Default Roles** | Automatic role assignment for new users | ✅ |

### 🎯 Referral System (NEW!)

| Feature | Description | Status |
|---------|-------------|---------|
| **Role-Based Limits** | Different invitation limits per user role | ✅ |
| **Configurable Codes** | Custom length, prefix, and expiry settings | ✅ |
| **Referral Tracking** | Complete audit trail of referral relationships | ✅ |
| **Management API** | Generate, view, and manage referral codes | ✅ |
| **Optional/Required** | Can be made mandatory or optional for signup | ✅ |

### 🛠 Developer Experience

| Feature | Description | Status |
|---------|-------------|---------|
| **Pure SQL** | No ORM dependencies, maximum performance | ✅ |
| **Separated Architecture** | Clean user/security separation for performance | ✅ |
| **Structured Responses** | Consistent HTTP response handling | ✅ |
| **Configurable Schema** | Customize table and column names | ✅ |
| **Comprehensive Examples** | Production-ready examples and documentation | ✅ |
| **Built-in Email Integration** | Interface-based email service integration | ✅ |

---

## 📚 Complete API Reference

### 🔑 Authentication Endpoints

```go
// User Registration
r.Post("/signup", authService.SignUpHandler)
// Body: {"email": "user@example.com", "password": "pass123", "referral_code": "REF12345"}

// User Login
r.Post("/signin", authService.SignInHandler)
// Body: {"email": "user@example.com", "password": "pass123"}

// Token Validation
r.Get("/validate", authService.ValidateHandler)
// Headers: Authorization: Bearer <token>

// Password Reset Flow
r.Post("/forgot-password", authService.ForgotPasswordHandler)
r.Post("/reset-password", authService.ResetPasswordHandler)

// Email Verification
r.Post("/verify-email", authService.VerifyEmailHandler)
r.Post("/resend-verification", authService.ResendVerificationHandler)

// Two-Factor Authentication
r.Post("/2fa/enable", authService.Enable2FAHandler)
r.Post("/2fa/send-code", authService.Send2FACodeHandler)
r.Post("/2fa/verify", authService.Verify2FACodeHandler)
r.Post("/2fa/backup-codes", authService.Generate2FABackupCodesHandler)
r.Post("/2fa/disable", authService.Disable2FAHandler)
```

### 📱 Session Management

```go
// Get User Sessions
r.Get("/sessions", authService.GetSessionsHandler)

// Revoke Specific Session
r.Delete("/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
    sessionID := chi.URLParam(r, "id")
    result := authService.RevokeSessionHandler(r, sessionID)
    w.WriteHeader(result.StatusCode)
    json.NewEncoder(w).Encode(result)
})

// Revoke All Sessions
r.Delete("/sessions", authService.RevokeAllSessionsHandler)
```

### 🌐 OAuth Integration

```go
// Initiate OAuth Flow
r.Get("/oauth/{provider}", func(w http.ResponseWriter, r *http.Request) {
    provider := chi.URLParam(r, "provider")
    result := authService.OAuthHandler(w, r, provider)
    // Handles redirect automatically
})

// OAuth Callback
r.Get("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
    provider := r.URL.Query().Get("provider")
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    result := authService.OAuthCallbackHandler(r, provider, code, state)
    w.WriteHeader(result.StatusCode)
    json.NewEncoder(w).Encode(result)
})

// Get Available Providers
r.Get("/oauth/providers", authService.GetProvidersHandler)
```

### 🎯 Referral System

```go
// Generate Referral Code
r.Post("/referrals/generate", authService.GenerateReferralCodeHandler)
// Body: {"tenant_id": 1, "max_uses": 5}

// Get My Referral Codes
r.Get("/referrals/my-codes", authService.GetMyReferralCodesHandler)

// Get My Referrals (users I referred)
r.Get("/referrals/my-referrals", authService.GetMyReferralsHandler)

// Get Referral Statistics
r.Get("/referrals/stats", authService.GetReferralStatsHandler)
```

---

## 🛡️ Security Configuration

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

    // Two-Factor Authentication
    TwoFactorCodeLength  int
    TwoFactorCodeExpiry  time.Duration
    BackupCodeCount      int
    MaxTwoFactorAttempts int
    TwoFactorLockout     time.Duration

    // Referral System
    RequireReferralCode  bool
    DefaultUserRoleName  string
    MaxInviteesPerRole   map[string]int
    ReferralCodeLength   int
    ReferralCodePrefix   string
    ReferralCodeExpiry   time.Duration
}
```

### Example Security Configuration

```go
SecurityConfig: auth.SecurityConfig{
    // Strong password requirements
    PasswordMinLength:      12,
    PasswordRequireUpper:   true,
    PasswordRequireLower:   true,
    PasswordRequireNumber:  true,
    PasswordRequireSpecial: true,

    // Account security
    MaxLoginAttempts: 3,
    LockoutDuration:  30 * time.Minute,
    SessionLifetime:  2 * time.Hour,

    // Email verification
    RequireEmailVerification: true,
    VerificationTokenExpiry:  24 * time.Hour,

    // Two-Factor Authentication
    RequireTwoFactor:         false,
    TwoFactorCodeLength:      6,
    TwoFactorCodeExpiry:      5 * time.Minute,
    BackupCodeCount:          8,
    MaxTwoFactorAttempts:     3,
    TwoFactorLockout:         15 * time.Minute,

    // Referral system
    RequireReferralCode: false,
    DefaultUserRoleName: "member",
    MaxInviteesPerRole: map[string]int{
        "member":    5,
        "premium":   25,
        "admin":     0, // Unlimited
    },
    ReferralCodeLength: 8,
    ReferralCodePrefix: "INVITE",
    ReferralCodeExpiry: 7 * 24 * time.Hour,
}
```

---

## 🔐 Two-Factor Authentication

### Enable 2FA for Users

```go
// Enable 2FA for a user
r.Post("/2fa/enable", func(w http.ResponseWriter, r *http.Request) {
    result := authService.Enable2FAHandler(r)
    w.WriteHeader(result.StatusCode)
    json.NewEncoder(w).Encode(result)
})

// Send 2FA code via email
r.Post("/2fa/send-code", func(w http.ResponseWriter, r *http.Request) {
    result := authService.Send2FACodeHandler(r)
    w.WriteHeader(result.StatusCode)
    json.NewEncoder(w).Encode(result)
})

// Verify 2FA code
r.Post("/2fa/verify", func(w http.ResponseWriter, r *http.Request) {
    result := authService.Verify2FACodeHandler(r)
    w.WriteHeader(result.StatusCode)
    json.NewEncoder(w).Encode(result)
})
```

### Backup Codes

```go
// Generate backup codes
r.Post("/2fa/backup-codes", func(w http.ResponseWriter, r *http.Request) {
    result := authService.Generate2FABackupCodesHandler(r)
    w.WriteHeader(result.StatusCode)
    json.NewEncoder(w).Encode(result)
})

// Response contains securely hashed backup codes
// {"backup_codes": ["CODE1", "CODE2", ...], "count": 8}
```

### 2FA Configuration

```go
SecurityConfig: auth.SecurityConfig{
    // Enable/disable 2FA requirement
    RequireTwoFactor: false,

    // Code settings
    TwoFactorCodeLength: 6,          // 6-digit codes
    TwoFactorCodeExpiry: 5 * time.Minute,

    // Backup codes
    BackupCodeCount: 8,              // Generate 8 backup codes

    // Security settings
    MaxTwoFactorAttempts: 3,         // Max attempts before lockout
    TwoFactorLockout: 15 * time.Minute,
}
```

### API Usage Flow

```bash
# 1. Enable 2FA for authenticated user
curl -X POST /2fa/enable \
  -H "Authorization: Bearer <token>" \
  -d '{"email":"user@example.com"}'

# 2. Request a 2FA code
curl -X POST /2fa/send-code \
  -H "Authorization: Bearer <token>" \
  -d '{"email":"user@example.com"}'

# 3. Verify the code
curl -X POST /2fa/verify \
  -H "Authorization: Bearer <token>" \
  -d '{"email":"user@example.com","code":"123456"}'

# 4. Generate backup codes (one-time operation)
curl -X POST /2fa/backup-codes \
  -H "Authorization: Bearer <token>" \
  -d '{"email":"user@example.com"}'

# 5. Disable 2FA if needed
curl -X POST /2fa/disable \
  -H "Authorization: Bearer <token>" \
  -d '{"email":"user@example.com","code":"123456"}'
```

### Security Features

- **Rate Limiting**: Maximum attempts before temporary lockout
- **Time-based Expiry**: Codes expire after configurable time
- **Backup Codes**: BCrypt-hashed one-time use codes for account recovery
- **Audit Logging**: All 2FA events logged to security_events table
- **Email Notifications**: Users notified when 2FA is enabled/disabled

---

## 🔧 OAuth Provider Configuration

### Built-in Provider Helpers

```go
OAuthProviders: map[string]auth.OAuthProviderConfig{
    // Helper functions for common providers
    "google": auth.NewGoogleOAuthProvider(
        "client-id", "client-secret", "redirect-url",
    ),
    "github": auth.NewGitHubOAuthProvider(
        "client-id", "client-secret", "redirect-url",
    ),
    "discord": auth.NewDiscordOAuthProvider(
        "client-id", "client-secret", "redirect-url",
    ),
}
```

### Custom Providers

```go
OAuthProviders: map[string]auth.OAuthProviderConfig{
    // Enterprise providers
    "microsoft": auth.NewCustomOAuthProvider(
        clientID, clientSecret, redirectURL,
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        []string{"openid", "profile", "email", "User.Read"},
    ),

    // Custom SSO
    "company-sso": auth.NewCustomOAuthProvider(
        clientID, clientSecret, redirectURL,
        "https://sso.company.com/oauth2/authorize",
        "https://sso.company.com/oauth2/token",
        []string{"profile", "email", "groups"},
    ),
}
```

---

## 🏗️ Multi-Tenant Setup

### Creating Tenants

```go
// Create a new tenant
tenant, err := authService.CreateTenant("Acme Corp", "acme", "acme.com")

// Create roles for the tenant
adminRole, err := authService.CreateRole(tenant.ID, "admin", "Administrator")
userRole, err := authService.CreateRole(tenant.ID, "user", "Regular User")

// Create permissions
readPerm, err := authService.CreatePermission("read", "documents", "read")
writePerm, err := authService.CreatePermission("write", "documents", "write")

// Assign permissions to roles
err = authService.AssignPermissionToRole(adminRole.ID, readPerm.ID)
err = authService.AssignPermissionToRole(adminRole.ID, writePerm.ID)
err = authService.AssignPermissionToRole(userRole.ID, readPerm.ID)
```

### Middleware with Tenant Context

```go
// Require authentication + specific permission
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuth())
    r.Use(authService.RequirePermission("documents", "read"))

    r.Get("/documents", getDocumentsHandler)
})

// In your handler
func getDocumentsHandler(w http.ResponseWriter, r *http.Request) {
    user := auth.MustGetUserFromContext(r.Context())
    tenant := auth.MustGetTenantFromContext(r.Context())

    // User and tenant are guaranteed to be available
    log.Printf("User %s accessing documents in tenant %s", user.Email, tenant.Name)
}
```

---

## 🎯 Referral System Usage

### Basic Setup

```go
// Configure referral system
SecurityConfig: auth.SecurityConfig{
    RequireReferralCode:  false,  // Optional referrals
    DefaultUserRoleName:  "user",
    ReferralCodeLength:   8,
    ReferralCodePrefix:   "REF",
    ReferralCodeExpiry:   30 * 24 * time.Hour,
    MaxInviteesPerRole: map[string]int{
        "user":     5,    // Basic users: 5 invites
        "premium":  20,   // Premium users: 20 invites
        "admin":    100,  // Admins: 100 invites
    },
}
```

### API Usage Flow

```bash
# 1. User signs up and gets authenticated
curl -X POST /signup -d '{"email":"user@test.com","password":"pass123"}'

# 2. User generates referral code
curl -X POST /referrals/generate \
  -H "Authorization: Bearer <token>" \
  -d '{"tenant_id":1,"max_uses":5}'

# Response: {"code":"REF12345678","max_uses":5,"expires_at":"2024-10-21T..."}

# 3. New user signs up with referral code
curl -X POST /signup -d '{
  "email":"friend@test.com",
  "password":"pass123",
  "referral_code":"REF12345678"
}'

# 4. Original user can view their referrals
curl -X GET /referrals/my-referrals \
  -H "Authorization: Bearer <token>"
```

### Role-Based Limits

```go
// Check how many invites a user can still send
stats, err := authService.GetReferralStats(userID)
// Returns: totalReferred, activeReferrals, error

// Generate code (automatically checks limits)
response := authService.GenerateReferralCode(auth.GenerateReferralCodeRequest{
    UserID:   userID,
    TenantID: tenantID,
    MaxUses:  5,
})
// Will return 403 if user has reached their role's limit
```

---

## 📊 Database Schema

The library creates and manages these tables with a clean, separated architecture:

### Core Authentication
- `users` - Core user identity (email, username, password, provider info)
- `user_security` - Security tracking (login attempts, 2FA, audit fields)
- `sessions` - Session management with device tracking
- `security_events` - Comprehensive audit logging

### Multi-Tenant System
- `tenants` - Organization/tenant management
- `roles` - Role definitions per tenant
- `permissions` - System-wide permissions
- `user_tenants` - User-tenant-role relationships
- `role_permissions` - Role-permission assignments

### Referral System
- `referral_codes` - Generated referral codes with metadata
- `user_referrals` - Referral relationship tracking

### OAuth Integration
- `oauth_states` - OAuth CSRF protection

---

## 📂 Examples

Comprehensive examples are provided in the `/example` directory:

### 🏗️ [`example/app/`](./example/app/) - Complete Web Application
Production-ready example with:
- Full authentication flow
- Database integration
- Email service implementation
- Multi-tenant setup
- Security best practices

```bash
cd example/app
go mod tidy
go run main.go services.go
# Visit http://localhost:8080
```

### 🔐 [`example/oauth/`](./example/oauth/) - OAuth Integration
Dynamic OAuth provider examples:
- Google, GitHub, Discord
- Custom enterprise providers
- Mixed configuration approaches

```bash
cd example/oauth
go mod tidy
go run main.go
```

### 🎯 [`example/referrals/`](./example/referrals/) - Referral System
Referral system demonstration:
- Role-based invitation limits
- Referral code generation and tracking
- Management API endpoints

```bash
cd example/referrals
go mod tidy
go run main.go
# Visit http://localhost:8080
```

### 🧪 [`example/testing/`](./example/testing/) - Testing Patterns
Testing examples with:
- In-memory SQLite for isolated tests
- Mock services
- Configuration validation

```bash
cd example/testing
go mod tidy
go run oauth_dynamic_demo.go
```

---

## 🔒 Security Features

### Separated Security Architecture
**Core User Table**: Contains only essential identity fields (email, username, password_hash, provider)
**User Security Table**: Contains 25+ security tracking fields:
- Email verification status and timestamps
- Password security (reset tokens, change tracking)
- Login security (attempts, lockout, last login tracking)
- Device and location tracking
- Two-factor authentication infrastructure
- Account status and suspension handling
- Referral system integration

### Security Events Auditing
All security-related actions are automatically logged:
- Login attempts (success/failure)
- Password changes and resets
- Email verification events
- Account lockouts and unlocks
- Session creation and termination
- Suspicious activity detection
- Referral code generation and usage

### Built-in Protection
- **Brute Force Protection**: Configurable login attempt limits
- **CSRF Protection**: OAuth state validation with secure tokens
- **Session Security**: Device fingerprinting and IP tracking
- **Password Security**: Configurable strength requirements
- **SQL Injection Protection**: Prepared statements throughout
- **Timing Attack Protection**: Constant-time comparisons

---

## 📈 Performance

- **Pure SQL**: No ORM overhead, direct database queries
- **Prepared Statements**: All queries use prepared statements for security and performance
- **Connection Pooling**: Built-in PostgreSQL connection pooling
- **Minimal Dependencies**: Only essential dependencies for maximum compatibility
- **Memory Efficient**: Struct-based responses, minimal allocations

---

## 🛠 Configuration Options

### Database Configuration
```go
type StorageConfig struct {
    // Customize table names
    UsersTable          string `json:"users_table"`
    SessionsTable       string `json:"sessions_table"`
    SecurityEventsTable string `json:"security_events_table"`

    // Customize column mappings
    UserColumns    UserColumnMapping    `json:"user_columns"`
    SessionColumns SessionColumnMapping `json:"session_columns"`

    // Multi-tenant settings
    MultiTenant MultiTenantConfig `json:"multi_tenant"`
}
```

### Email Service Integration
```go
type EmailService interface {
    SendVerificationEmail(email, token string) error
    SendPasswordResetEmail(email, token string) error
    SendWelcomeEmail(email, name string) error

    // Two-Factor Authentication
    Send2FACode(email, code string) error
    Send2FAEnabled(email string) error
    Send2FADisabled(email string) error
}

// Implement this interface with your email provider
type YourEmailService struct {
    // Your email service configuration
}

func (e *YourEmailService) SendVerificationEmail(email, token string) error {
    // Send verification email using your preferred service
    // (SendGrid, SES, Mailgun, etc.)
    return nil
}
```

---

## 🚀 Deployment

### Environment Variables
```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Email Service (implement based on your provider)
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
```

### Docker Support
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]
```

### Production Checklist
- ✅ Configure strong password requirements
- ✅ Enable email verification
- ✅ Set up proper session lifetimes
- ✅ Configure account lockout policies
- ✅ Implement proper email service
- ✅ Set up database backups
- ✅ Configure HTTPS/TLS
- ✅ Monitor security events
- ✅ Set up rate limiting (if needed)

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

- 📖 **Documentation**: Check the comprehensive examples in `/example`
- 🐛 **Issues**: [GitHub Issues](https://github.com/wispberry-tech/wispy-auth/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/wispberry-tech/wispy-auth/discussions)

---

## 🗺 Roadmap

### Current Version (v1.0)
- ✅ Core authentication (email/password, OAuth)
- ✅ Multi-tenant architecture with RBAC
- ✅ Referral system with role-based limits
- ✅ Comprehensive security features
- ✅ Production-ready examples

### Future Versions
- 🔄 WebAuthn/Passkey support
- 🔄 Advanced 2FA methods (TOTP, SMS)
- 🔄 Social login providers expansion
- 🔄 Mobile app integration examples
<!-- - 🔄 Admin dashboard for user management -->
<!-- - 🔄 Advanced analytics and reporting -->
<!-- - 🔄 Rate limiting and DDoS protection -->

---

<div align="center">

<!-- **Built with ❤️ for the Go community** -->

[⭐ Star us on GitHub](https://github.com/wispberry-tech/wispy-auth) • [📖 Read the Docs](./docs/) • [🚀 Get Started](#-quick-start)

</div>