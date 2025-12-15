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

### OAuth
- `GET /auth/{provider}` - Initialize OAuth flow
- `GET /auth/{provider}/callback` - OAuth callback

### Protected Routes
- `GET /profile` - Get user profile
- `GET /sessions` - Get user sessions

## Configuration

### Security Config
```go
config := core.SecurityConfig{
    PasswordMinLength:        8,
    PasswordRequireUpper:     true,
    PasswordRequireLower:     true,
    PasswordRequireNumber:    true,
    PasswordRequireSpecial:   true,
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