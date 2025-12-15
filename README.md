# Wispy Auth

A comprehensive, production-ready authentication library for Go applications with a focus on security, flexibility, and ease of use.

## 🚀 Features

### Core Authentication
- **Email/Password Authentication** - Secure user registration and login with configurable password requirements
- **Multi-Provider OAuth2** - Built-in support for Google, GitHub, Discord, and custom OAuth providers
- **Session Management** - Secure JWT-like session tokens with device tracking and automatic expiration
- **Security Tracking** - Comprehensive audit logging, failed login attempt tracking, and account lockout protection

### Advanced Security
- **Account Lockout Protection** - Configurable failed login attempt limits with automatic unlocking
- **Rate Limiting** - IP-based rate limiting to prevent abuse and brute force attacks
- **Device Fingerprinting** - Track user sessions across different devices and browsers
- **Security Event Logging** - Detailed audit trails for all authentication events
- **Password Security** - Bcrypt hashing with configurable complexity requirements
- **CSRF Protection** - Built-in OAuth state validation and CSRF token management

### Database Support
- **SQLite** - Perfect for development, testing, and small deployments
- **PostgreSQL** - Production-ready with connection pooling and advanced features
- **Extensible Storage** - Clean interface for adding custom database backends

## 📦 Installation

```bash
go get github.com/wispberry-tech/wispy-auth/core
```

## 🏁 Quick Start

### Basic Setup

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"

    "github.com/wispberry-tech/wispy-auth/core"
    "github.com/wispberry-tech/wispy-auth/core/storage"
)

func main() {
    // Create storage
    storage, err := storage.NewInMemorySQLiteStorage()
    if err != nil {
        log.Fatal("Failed to create storage:", err)
    }
    defer storage.Close()

    // Configure auth service
    config := core.Config{
        Storage:        storage,
        SecurityConfig: core.DefaultSecurityConfig(),
        OAuthProviders: map[string]core.OAuthProviderConfig{
            "google": core.NewGoogleOAuthProvider(
                "your-google-client-id",
                "your-google-client-secret", 
                "https://yourapp.com/auth/google/callback",
            ),
            "github": core.NewGitHubOAuthProvider(
                "your-github-client-id",
                "your-github-client-secret",
                "https://yourapp.com/auth/github/callback", 
            ),
        },
    }

    // Create auth service
    authService, err := core.NewAuthService(config)
    if err != nil {
        log.Fatal("Failed to create auth service:", err)
    }
    defer authService.Close()

    // Set up routes
    mux := http.NewServeMux()

    // Authentication endpoints
    mux.HandleFunc("POST /signup", handleSignUp(authService))
    mux.HandleFunc("POST /signin", handleSignIn(authService))
    mux.HandleFunc("POST /logout", handleLogout(authService))
    mux.HandleFunc("GET /validate", handleValidate(authService))

    // OAuth endpoints  
    mux.HandleFunc("GET /auth/{provider}", handleOAuthInit(authService))
    mux.HandleFunc("GET /auth/{provider}/callback", handleOAuthCallback(authService))

    // Protected endpoints
    mux.Handle("GET /profile", authService.AuthMiddleware(
        http.HandlerFunc(handleProfile),
    ))

    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", mux)
}

// Handler functions
func handleSignUp(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignUpHandler(r)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode signup response", "error", err)
        }
    }
}

func handleSignIn(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignInHandler(r)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode signin response", "error", err)
        }
    }
}

func handleLogout(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        result := authService.LogoutHandler(r)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode logout response", "error", err)
        }
    }
}

func handleValidate(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        result := authService.ValidateHandler(r)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode validate response", "error", err)
        }
    }
}

func handleOAuthInit(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        provider := r.PathValue("provider")
        result := authService.OAuthInitHandler(r, provider)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode OAuth init response", "error", err)
        }
    }
}

func handleOAuthCallback(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        provider := r.PathValue("provider")
        result := authService.OAuthCallbackHandler(r, provider)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(result.StatusCode)
        if err := json.NewEncoder(w).Encode(result); err != nil {
            slog.Error("Failed to encode OAuth callback response", "error", err)
        }
    }
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
    user := core.GetUserFromContext(r)
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(user); err != nil {
        slog.Error("Failed to encode profile response", "error", err)
    }
}
```

## 🔧 Configuration

### Security Configuration

```go
config := core.Config{
    Storage: storage,
    SecurityConfig: core.SecurityConfig{
        // Password requirements
        PasswordMinLength:      8,
        PasswordRequireUpper:   true,
        PasswordRequireLower:   true, 
        PasswordRequireNumber:  true,
        PasswordRequireSpecial: true,
        
        // Account lockout settings
        MaxLoginAttempts: 5,
        LockoutDuration:  15 * time.Minute,
        
        // Session management
        SessionLifetime: 24 * time.Hour,
        
        // Two-factor authentication
        RequireTwoFactor:         false,
        TwoFactorCodeExpiry:      5 * time.Minute,
        Max2FAAttempts:           3,
        TwoFactorLockoutDuration: 15 * time.Minute,

        // Rate limiting
        EnableRateLimiting: true,
        RateLimitRequests:  10,
        RateLimitWindow:    1 * time.Minute,
    },
}
```

### OAuth Provider Configuration

```go
oauthProviders := map[string]core.OAuthProviderConfig{
    "google": core.NewGoogleOAuthProvider(
        clientID, 
        clientSecret, 
        redirectURL,
    ),
    "github": core.NewGitHubOAuthProvider(
        clientID, 
        clientSecret, 
        redirectURL,
    ),
    "discord": core.NewDiscordOAuthProvider(
        clientID, 
        clientSecret, 
        redirectURL,
    ),
    // Custom provider
    "custom": core.NewCustomOAuthProvider(
        clientID,
        clientSecret, 
        redirectURL,
        "https://provider.com/oauth/authorize",
        "https://provider.com/oauth/token",
        []string{"read:user", "user:email"},
    ),
}
```

## 🗄️ Database Support

### SQLite (Development & Small Apps)

```go
// In-memory (testing)
storage, err := storage.NewInMemorySQLiteStorage()

// File-based (development)
storage, err := storage.NewSQLiteStorage("./data/auth.db")
```

### PostgreSQL (Production)

```go
import "github.com/wispberry-tech/wispy-auth/core/storage"

config := storage.PostgresConfig{
    Host:     "localhost",
    Port:     5432,
    Database: "myapp",
    Username: "user",
    Password: "password",
    SSLMode:  "require",
}

storage, err := storage.NewPostgresStorage(config)
```

## 🔒 Security Features

### Comprehensive Audit Logging

All authentication events are automatically logged:

- User registration and login attempts
- Failed login attempts with IP tracking
- Account lockout and unlock events  
- Password changes and resets
- OAuth authentication events
- Session creation and termination

### Account Protection

- **Rate Limiting**: Configurable failed login attempt limits
- **Account Lockout**: Automatic temporary account locking
- **Device Tracking**: Monitor sessions across devices
- **IP Tracking**: Record IP addresses for security events
- **Session Management**: Secure token-based sessions with expiration

## 🚀 Production Deployment

### Environment Variables

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=production_app
DB_USER=app_user
DB_PASSWORD=secure_password

# OAuth Providers
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Security
SESSION_LIFETIME=24h
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=30m
```

### Docker Deployment

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]
```

## 📊 Monitoring & Observability

### Metrics

The library provides built-in logging using Go's `slog` package:

- Authentication success/failure rates
- Session creation and validation metrics  
- Account lockout events
- OAuth provider usage statistics

### Health Checks

```go
// Health check endpoint
mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
    if err := authService.GetStorage().Ping(); err != nil {
        w.WriteHeader(http.StatusServiceUnavailable)
        if err := json.NewEncoder(w).Encode(map[string]string{
            "status": "unhealthy",
            "error":  err.Error(),
        }); err != nil {
            slog.Error("Failed to encode unhealthy response", "error", err)
        }
        return
    }
    
    w.WriteHeader(http.StatusOK)
    if err := json.NewEncoder(w).Encode(map[string]string{
        "status": "healthy",
    }); err != nil {
        slog.Error("Failed to encode health response", "error", err)
    }
})
```

## 🧪 Testing

The library includes comprehensive test coverage with examples:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test suites
go test -run TestAuth ./core
```

### CI/CD

This project uses GitHub Actions for continuous integration:

- **Automated Testing**: Runs on every push and pull request
- **Security Scanning**: Uses gosec to detect security vulnerabilities
- **Code Coverage**: Reports test coverage to Codecov
- **Code Formatting**: Ensures consistent Go code formatting

### Test Examples

```go
func TestUserRegistration(t *testing.T) {
    storage, _ := storage.NewInMemorySQLiteStorage()
    authService, _ := core.NewAuthService(core.Config{
        Storage: storage,
        SecurityConfig: core.DefaultSecurityConfig(),
    })
    
    // Test user registration
    req := httptest.NewRequest("POST", "/signup", strings.NewReader(`{
        "email": "test@example.com",
        "password": "SecurePassword123!",
        "first_name": "Test",
        "last_name": "User"
    }`))
    
    response := authService.SignUpHandler(req)
    assert.Equal(t, http.StatusCreated, response.StatusCode)
    assert.NotEmpty(t, response.Token)
    assert.Equal(t, "test@example.com", response.User.Email)
}
```

## 📚 Documentation

- **[Core API Reference](./core/README.md)** - Complete core authentication API
- **[Examples](./examples/)** - Working examples and demos

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/wispberry-tech/wispy-auth.git
cd wispy-auth

# Install dependencies
go mod download

# Run tests
go test ./...

# Run with coverage
go test -cover ./...
```

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Comprehensive GoDoc documentation
- **Examples**: Working examples in `/examples` directory
- **Issues**: GitHub Issues for bug reports and feature requests
- **Discussions**: GitHub Discussions for questions and community support

## 🗺️ Roadmap

### Upcoming Features

- [ ] **Multi-Factor Authentication** - TOTP and SMS-based 2FA
- [ ] **Social Login Extensions** - Twitter, LinkedIn, Microsoft providers
- [x] **Rate Limiting** - Basic IP-based rate limiting implemented
- [ ] **Webhook Support** - Custom webhooks for authentication events

### Performance Improvements

- [ ] **Connection Pooling** - Advanced database connection management
- [ ] **Caching Layer** - Redis integration for session and user caching  
- [ ] **Background Jobs** - Async processing for email sending and cleanup
- [ ] **Metrics Collection** - Prometheus metrics integration

---

**Wispy Auth** - Secure, flexible, and production-ready authentication for Go applications.