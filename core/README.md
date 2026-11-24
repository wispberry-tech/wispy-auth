# Wispy Auth Core


## Features

- **Email/Password Authentication** - Secure signup and signin with password strength validation
- **OAuth2 Support** - Google, GitHub, and Discord OAuth providers
- **Session Management** - Secure session tokens with device tracking
- **Security Tracking** - Login attempts, account lockout, security events
- **SQLite & PostgreSQL** - Multiple database backends
- **Middleware** - Easy integration with any HTTP router
- **OpenAPI 3.0 Spec** - Embedded specification of all built-in endpoints with a one-line serve handler
- **No Required External Services** - Email and other notifications are host-provided

## Quick Start

```go
package main

import (
    "github.com/wispberry-tech/wispy-auth/core"
    "github.com/wispberry-tech/wispy-auth/core/storage"
)

func main() {
    // Create storage
    storage, err := storage.NewInMemorySQLiteStorage()
    if err != nil {
        log.Fatal(err)
    }
    defer storage.Close()

    // Configure auth service
    config := core.Config{
        Storage:        storage,
        SecurityConfig: core.DefaultSecurityConfig(),
        OAuthProviders: map[string]core.OAuthProviderConfig{
            "google": core.NewGoogleOAuthProvider(
                "your-client-id",
                "your-client-secret",
                "http://localhost:8080/auth/google/callback",
            ),
        },
    }

    // Create auth service
    authService, err := core.NewAuthService(config)
    if err != nil {
        log.Fatal(err)
    }
    defer authService.Close()

    // Use with any HTTP router
    mux := http.NewServeMux()

    // Authentication endpoints
    mux.HandleFunc("POST /signup", authService.SignUpHandler)
    mux.HandleFunc("POST /signin", authService.SignInHandler)

    // Protected routes
    mux.Handle("GET /profile", authService.AuthMiddleware(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := core.GetUserFromContext(r)
            w.Header().Set("Content-Type", "application/json")
            if err := json.NewEncoder(w).Encode(user); err != nil {
                slog.Error("Failed to encode profile response", "error", err)
            }
        }),
    ))

    http.ListenAndServe(":8080", mux)
}
```

## API Endpoints

### Authentication
- `POST /signup` - User registration
- `POST /signin` - User login
- `POST /logout` - User logout
- `GET /validate` - Token validation

### Password Management
- `POST /forgot-password` - Request password reset
- `POST /reset-password` - Reset password with token
- `POST /change-password` - Change password (authenticated)

**Note:** Password reset functionality must be enabled in the security configuration:

```go
config := core.Config{
    Storage: storage,
    SecurityConfig: core.SecurityConfig{
        AllowUserPasswordReset: true, // Enable user self-service password reset
        // ... other settings
    },
}
```

If `AllowUserPasswordReset` is `false` (default), the forgot password endpoint will return a 403 Forbidden error.

### OAuth
- `GET /auth/{provider}` - Initialize OAuth flow
- `GET /auth/{provider}/callback` - OAuth callback

### Protected Routes
- `GET /profile` - Get user profile
- `GET /sessions` - Get user sessions

### Two-Factor & Tokens
- `POST /2fa/enable` - Start 2FA enablement (sends email code)
- `POST /2fa/enable/verify` - Confirm code and activate 2FA
- `POST /2fa/disable` - Disable 2FA
- `POST /2fa/login` - Complete sign-in with a 2FA/backup code
- `POST /2fa/backup-codes` - List backup codes (requires current password)
- `POST /2fa/backup-codes/regenerate` - Generate new backup codes
- `POST /refresh-token` - Exchange a refresh token for a new session

## OpenAPI

The library ships an OpenAPI 3.0.3 specification of its built-in endpoints, embedded in `core/openapi.json` and served by `core.OpenAPIHandler()`:

```go
mux.Handle("GET /swagger/doc.json", core.OpenAPIHandler())
```

The handler is a plain `http.Handler` — it works with any router. The spec documents the endpoints at the canonical paths listed above; wire the handlers to those paths so the spec matches your server, then point any OpenAPI viewer (Swagger UI, Redoc, Scalar) at the served URL.

Each operation carries an `x-handler` extension naming its `AuthService` method, and `TestSpecCoversAllHandlers` fails the build if a handler is added without documentation — the spec cannot silently drift from the code.

### Password Reset API

#### Request Password Reset
```http
POST /forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "If an account with this email exists, a password reset link has been sent.",
  "token": "reset_token_here"  // Only in development
}
```

#### Reset Password
```http
POST /reset-password
Content-Type: application/json

{
  "token": "reset_token_from_email",
  "password": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "message": "Password has been successfully reset"
}
```

#### Change Password (Authenticated)
```http
POST /change-password
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "current_password": "OldPassword123!",
  "new_password": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "message": "Password has been successfully changed"
}
```

## Configuration

### Security Config
```go
config := core.SecurityConfig{
    // Password security
    PasswordMinLength:        8,
    PasswordRequireUpper:     true,
    PasswordRequireLower:     true,
    PasswordRequireNumber:    true,
    PasswordRequireSpecial:   true,
    AllowUserPasswordReset:   false, // Default: users cannot reset their own passwords
    
    // Authentication security
    MaxLoginAttempts:         5,
    LockoutDuration:          15 * time.Minute,
    SessionLifetime:          24 * time.Hour,
    RequireTwoFactor:         false,
}
```

### OAuth Providers
```go
oauthProviders := map[string]core.OAuthProviderConfig{
    "google": core.NewGoogleOAuthProvider(clientID, secret, redirectURL),
    "github": core.NewGitHubOAuthProvider(clientID, secret, redirectURL),
    "discord": core.NewDiscordOAuthProvider(clientID, secret, redirectURL),
    "custom": core.NewCustomOAuthProvider(clientID, secret, redirectURL, authURL, tokenURL, scopes),
}
```

## Storage Backends

### SQLite (Recommended for development)
```go
// In-memory (testing)
storage, err := storage.NewInMemorySQLiteStorage()

// File-based
storage, err := storage.NewSQLiteStorage("./auth.db")
```

### PostgreSQL (Recommended for production)
```go
storage, err := storage.NewPostgresStorage("postgresql://user:pass@localhost/db")
```

## Database Schema

All primary keys and foreign keys use UUIDs. SQLite stores them as `TEXT` and
PostgreSQL stores them as native `UUID` values. Storage initialization upgrades
the previous integer-key schema while preserving user UUIDs and library-owned
data. Go models and storage methods use `github.com/google/uuid.UUID` for IDs.
Applications that reference Wispy Auth IDs from their own tables must
migrate those foreign keys before initializing the new library version; the
upgrade rejects SQLite schemas where it detects broken references.

The core module uses these tables:

- `users` - Core user identity and authentication
- `user_security` - Security tracking and sensitive data
- `sessions` - Session management with device tracking
- `security_events` - Comprehensive security audit log
- `oauth_states` - Single-use OAuth state tokens
- `password_reset_tokens` - Password reset flow tokens
- `two_factor_codes` - Temporary 2FA verification codes
- `two_factor_backup_codes` - One-time use 2FA backup codes
- `refresh_tokens` - Session renewal tokens

## Example Application

Run the example application:

```bash
cd examples/admin-password-reset
go run main.go
```

The server will start on `:8080` with full authentication functionality.

## Migration from Full Library

The core module provides the same essential authentication features as the full library, but without:

- Multi-tenant support
- Role-based access control (RBAC)
- Referral system
- Complex middleware

This results in a much simpler, focused library that's easier to understand and integrate.
