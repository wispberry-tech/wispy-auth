# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Wispy Auth** is a comprehensive, security-focused authentication library for Go applications. It provides email/password authentication, OAuth2 support (Google, GitHub, Discord), session management, account lockout protection, and detailed security audit logging.

**Status**: Under active development, not yet production-ready.

## Quick Commands

### Development Setup
```bash
go mod download          # Install dependencies
```

### Testing
```bash
go test ./...                          # Run all tests
go test -v -race -coverprofile=coverage.out ./...  # Tests with coverage & race detection
go test -run TestAuth ./core           # Run specific test suite
go test -run TestUserRegistration ./   # Run specific test
```

### Code Quality
```bash
gofmt -s -l .            # Check formatting (shows unformatted files)
gofmt -s -w .            # Auto-format all files
go install github.com/securego/gosec/v2/cmd/gosec@latest  # Install security scanner
gosec ./...              # Run security scan
```

### Building & Running
```bash
go build ./...           # Build the library
cd examples/core && go run main.go  # Run the example application (starts on :8080)
```

### Releasing
```bash
./release                # Interactive script to create and push version tags (e.g., v1.0.0)
# Alternatively: git tag v1.0.0 && git push origin v1.0.0
```

## Architecture Overview

### Core Components

**AuthService** (`core/auth.go`)
- Central service implementing all authentication logic
- Configured with `Config` struct (security, storage, OAuth providers)
- Handler-based API: each endpoint has a `*Handler` method returning `*AuthResponse`
- Manages sessions, OAuth flows, password management, and security events

**Storage Layer** (`core/storage/`)
- Abstract interface for database backends
- **SQLite** (`storage/sqlite.go`) — Development and small deployments; supports in-memory and file-based
- **PostgreSQL** (`storage/postgres.go`) — Production-ready with connection pooling
- Encapsulates all database operations; no direct SQL in core logic

**Handler System** (`core/handlers.go`, `core/oauth_handlers.go`)
- Return-based design: `SignUpHandler(r *http.Request) *AuthResponse` (not middleware-style)
- Handlers decode JSON, validate, call AuthService methods, return response with HTTP status code
- Allows maximum control over HTTP responses; works with any HTTP router

**Middleware** (`core/middleware.go`)
- `AuthMiddleware(next http.Handler) http.Handler` — validates session tokens; injects user into request context
- `GetUserFromContext(r *http.Request) *User` — extracts authenticated user from context

**Security & Audit** (`core/auth.go`, `core/handlers.go`)
- Failed login tracking, account lockout with configurable duration
- Rate limiting (IP-based, configurable requests per window)
- Comprehensive `SecurityEvent` logging — registration, login attempts, lockout, password changes, OAuth events, etc.
- Password hashing via bcrypt (golang.org/x/crypto)
- Device fingerprinting and session management

### Database Schema

Five core tables (all backends share the same schema):

1. **users** — Core user identity: email, username, name, password hash, OAuth provider info, verification status
2. **user_security** — Sensitive security tracking: login attempts, lockout status, password change dates, 2FA settings, device fingerprints, risk scores
3. **sessions** — Session tokens with device/IP tracking, expiration, device fingerprints
4. **security_events** — Audit log: all auth events (sign-up, login, lockout, password reset, OAuth, etc.) with timestamps, IPs, event types, and metadata
5. **oauth_states** — OAuth CSRF protection: state tokens tied to providers and expiration times

All databases initialize schema automatically on first connection (idempotent SQL in `core/sql/`).

### Configuration

**SecurityConfig** controls:
- Password requirements (length, upper/lower/number/special case)
- User self-service password reset (`AllowUserPasswordReset`)
- Login attempt limits and lockout duration
- Session lifetime
- Two-factor authentication (optional; partial implementation in `twofactor.go`)
- Rate limiting (requests per window)

**OAuthProviderConfig** — Maps provider name (e.g., "google") to OAuth client ID, secret, and redirect URL. Built-in providers: Google, GitHub, Discord, and custom.

## Project Structure

```
core/
├── auth.go                  # AuthService, SecurityConfig, Config, User/UserSecurity/Session/SecurityEvent types
├── auth_test.go             # Unit tests for auth service
├── auth_extended_test.go    # Extended test suite
├── handlers.go              # HTTP handler functions (signup, signin, logout, validate, password reset)
├── handlers_test.go         # Handler tests
├── handlers.go.backup       # Previous version (backup)
├── oauth.go                 # OAuth2 constants and helper setup
├── oauth_handlers.go        # OAuth initialization and callback handlers
├── middleware.go            # AuthMiddleware, GetUserFromContext
├── common.go                # Utility functions and constants
├── email_service.go         # EmailService interface
├── email_service_mock.go    # Mock email service for testing
├── email_service_smtp.go    # SMTP email service implementation
├── twofactor.go             # Two-factor authentication (partial implementation)
├── storage.go               # Storage interface and data types
├── storage/
│   ├── sqlite.go            # SQLite backend implementation
│   ├── postgres.go          # PostgreSQL backend implementation
│   └── storage_test.go      # Storage tests
├── sql/
│   └── *.sql                # Database schema migrations
└── README.md                # Core module documentation

examples/
├── core/main.go             # Full example HTTP server with all auth endpoints
└── admin-password-reset.md  # Documentation on admin-side password reset flow

.github/workflows/
├── ci.yml                   # CI: tests, code formatting, security scan (gosec)
└── release.yml              # Release: tags trigger auto-release with GitHub Actions

LICENSE, README.md, CONTRIBUTING.md, go.mod, go.sum
```

## Key Patterns & Guidelines

### Adding New Features

1. **Handler Logic in AuthService** — All business logic goes in `AuthService` methods (e.g., `SignUpHandler`, `SignInHandler`)
2. **Handlers Call Service** — HTTP handlers in `handlers.go` parse requests, call AuthService, and return responses
3. **Storage Abstraction** — New data operations go in the `Storage` interface (both SQLite and PostgreSQL implement)
4. **Audit Logging** — Use `LogSecurityEvent()` for all authentication actions

### Testing

- Use `storage.NewInMemorySQLiteStorage()` for unit tests (in-memory, no disk I/O)
- Tests cover success and failure paths
- Run `go test ./...` frequently; CI enforces test pass before merge
- Coverage is tracked via Codecov on every push

### Code Quality Standards

- **Formatting**: `gofmt` enforced; CI fails if code is not formatted
- **Security**: `gosec` checks for common vulnerabilities; CI will report warnings
- **Naming**: Follow Go conventions (short, exported for public APIs, lowercase for internal)
- **Error Handling**: Return errors for API-level failures; log warnings/errors appropriately with slog

## Database Setup

### SQLite (Development)
```go
// In-memory (fast tests)
storage, err := storage.NewInMemorySQLiteStorage()

// File-based (persistent)
storage, err := storage.NewSQLiteStorage("./data/auth.db")
```

### PostgreSQL (Production)
```go
config := storage.PostgresConfig{
    Host: "localhost", Port: 5432, Database: "myapp",
    Username: "user", Password: "pass", SSLMode: "require",
}
storage, err := storage.NewPostgresStorage(config)
```

Both automatically initialize schema on first connection.

## CI/CD

- **CI Workflow** (on push/PR to main): Runs tests with coverage, code formatting check, and security scan (gosec)
- **Release Workflow** (on version tags): Builds, tests, and creates GitHub release with release notes
- Use `./release` script or `git tag v1.0.0 && git push origin v1.0.0` to trigger release

## Common Development Tasks

### Running the Example Server
```bash
cd examples/core && go run main.go
# Server on http://localhost:8080
# Includes signup, signin, logout, OAuth, password reset endpoints
```

### Adding a New OAuth Provider
1. Add provider config to `OAuthProviders` map in `Config`
2. Use `NewGoogleOAuthProvider`, `NewGitHubOAuthProvider`, `NewDiscordOAuthProvider`, or `NewCustomOAuthProvider` with correct endpoints and scopes
3. Handler already supports dynamic provider names: `/auth/{provider}` and `/auth/{provider}/callback`

### Debugging Security Issues
- Check `security_events` table for audit trail of what happened
- Use `user_security` table to check lockout status, login attempts, device fingerprints
- Examine logs for failed requests and why they were rejected

### Updating Security Configuration
- Modify `SecurityConfig` fields in your app's `Config` initialization
- No code changes needed in core library; configuration is dynamic per AuthService instance

## Notes

- **Dependency-Light**: Minimal external dependencies (validator, pgx, go-sqlite3, oauth2, crypto)
- **Multi-Database**: Same codebase works with SQLite or PostgreSQL; storage interface abstracts differences
- **No External Services**: OAuth only requires client credentials; email is pluggable (mock or SMTP)
- **Active Development**: Not yet production-ready; breaking changes possible
- **Return-Based Handlers**: Core design philosophy—return responses, don't write HTTP directly; max flexibility
