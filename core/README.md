# Wispy Auth Core


## Features

- **Email/Password Authentication** - Secure signup and signin with password strength validation
- **OAuth2 Support** - Google, GitHub, and Discord OAuth providers
- **Session Management** - Secure session tokens with device tracking
- **Security Tracking** - Login attempts, account lockout, security events
- **SQLite & PostgreSQL** - Multiple database backends
- **Middleware** - Easy integration with any HTTP router
- **Zero Dependencies** - No external services required

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
    mux.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignUpHandler(r)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode signup response", "error", err)
        }
    })

    mux.HandleFunc("POST /signin", func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignInHandler(r)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode signin response", "error", err)
        }
    })

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

The core module uses a simplified schema with only essential tables:

- `users` - Core user identity and authentication
- `user_security` - Security tracking and sensitive data
- `sessions` - Session management with device tracking
- `security_events` - Comprehensive security audit log
- `oauth_states` - OAuth CSRF protection

## Example Application

Run the example application:

```bash
cd examples/core
go run main.go
```

The server will start on `:8080` with full authentication functionality.

## Migration from Full Library

The core module provides the same essential authentication features as the full library, but without:

- Multi-tenant support
- Role-based access control (RBAC)
- Email service integration
- Referral system
- Complex middleware

This results in a much simpler, focused library that's easier to understand and integrate.