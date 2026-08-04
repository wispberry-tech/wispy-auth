## Project Overview

**Wispy Auth** is a comprehensive, security-focused authentication library for Go applications. It provides email/password authentication, OAuth2 support (Google, GitHub, Discord), session management, account lockout protection, and detailed security audit logging.

**Status**: Under active development, not yet production-ready.

## Rules!
- when creating a plan include a concise but complete TLDR at the top for easy scanning use bullet points for taks/issues etc.
- never commit or push changes unless told to!

## Architecture Overview

### Core Components

**AuthService** (`core/auth.go`)
- Central service implementing all authentication logic
- Configured with `Config` struct (security, storage, OAuth providers)
- Handler-based API: each endpoint has a `*Handler` method writing JSON responses directly
- Manages sessions, OAuth flows, password management, and security events

**Storage Layer** (`core/storage/`)
- Abstract interface for database backends
- **SQLite** (`storage/sqlite.go`) — Development and small deployments; supports in-memory and file-based
- **PostgreSQL** (`storage/postgres.go`) — Production-ready with connection pooling
- Encapsulates all database operations; no direct SQL in core logic

**Handler System** (`core/handlers.go`, `core/oauth_handlers.go`)
- Handler-based API: `SignUpHandler(w http.ResponseWriter, r *http.Request)` decodes JSON, validates, calls the AuthService, and writes a JSON response
- Handlers decode JSON, validate, call AuthService methods, and write JSON responses with HTTP status codes
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
2. **user_security** — Sensitive security tracking: login attempts, lockout status, password change dates, 2FA settings
3. **sessions** — Session tokens with device/IP tracking, expiration, device fingerprints
4. **security_events** — Audit log: all auth events (sign-up, login, lockout, password reset, OAuth, etc.) with timestamps, IPs, event types, and metadata
5. **oauth_states** — Single-use OAuth state tokens tied to providers and expiration times

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
├── oauth_handlers.go        # OAuth initialization and callback handlers
├── middleware.go            # AuthMiddleware, GetUserFromContext
├── common.go                # Utility functions and constants
├── notifications.go         # Notification types and handler hook
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
└── admin-password-reset/
    ├── main.go              # Runnable example server (admin password reset flow on :8080)
    └── readme.md            # Documentation on admin-side password reset flow

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
cd examples/admin-password-reset && go run main.go
# Server on http://localhost:8080
# Admin-side password reset flow (login, OAuth, password reset endpoints)
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
- **No External Services**: OAuth only requires client credentials; email is pluggable (notification handler)
- **Active Development**: Not yet production-ready; breaking changes possible
- **Handler-Based API**: handlers write JSON responses directly; works with any HTTP router
