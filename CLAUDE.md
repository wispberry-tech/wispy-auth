# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🚨 CRITICAL: Database Schema Management

**NEVER hardcode table creation in Go code!**
**ALWAYS update the existing SQL scaffold files instead!**

- SQL files in `/sql/` directory are the single source of truth for database schemas
- Both `postgres_scaffold.sql` and `sqlite_scaffold.sql` must be kept in sync
- When tests need database tables, they should read from these scaffold files
- Never create new migration files - update existing ones
- Never embed SQL schemas directly in Go code
- Always use the clean separated architecture approach for table organization

**Correct approach:**
1. Update `sql/sqlite_scaffold.sql` for SQLite schema changes
2. Update `sql/postgres_scaffold.sql` for PostgreSQL schema changes 
3. Use `NewInMemorySQLiteStorage()` which reads from these scaffold files
4. Keep schema definitions in SQL files as developer reference

**Clean Separated Architecture:**
- Keep user identity separate from security details
- Maintain proper table relationships with foreign keys
- Follow the established table organization pattern
- Store core identity data in `users` table
- Store security tracking in `user_security` table
- Use proper indexes for optimal query performance
- NEVER delete user security records directly - they should cascade from user deletion
- Ensure foreign key constraints enforce data integrity

## Development Commands

### Running Example Applications
```bash
# Complete web application
cd example/app
go run main.go services.go

# OAuth provider examples
cd example/oauth
go run main.go

# Referral system demonstration
cd example/referrals
go run main.go

# Testing patterns
cd example/testing
go run oauth_dynamic_demo.go

# Build the main library
go build .
```

### Testing
```bash
# Run all tests
go test -v ./...

# Test specific examples
cd example/app && go build .
cd example/oauth && go build .
cd example/referrals && go build .
cd example/testing && go build oauth_dynamic_demo.go
```

### Development Environment
```bash
# Install dependencies
go mod tidy

# Verify all examples compile
cd example/app && go mod tidy && go build .
cd example/oauth && go mod tidy && go build .
cd example/referrals && go mod tidy && go build .
cd example/testing && go mod tidy && go build oauth_dynamic_demo.go
```

## Core Architecture

### Main Components

**Auth Service (`auth.go`)**: Central service that orchestrates all authentication operations. Contains `AuthService` struct and `Config` for initialization.

**Storage Layer (`storage.go`, `postgres_storage.go`)**: 
- `StorageInterface` defines the contract for data operations
- `PostgresStorage` implements PostgreSQL-specific operations
- Supports flexible table/column mapping via `StorageConfig`

**Handlers (`handlers.go`)**: HTTP request handlers that return structured response objects (`SignUpResponse`, `SignInResponse`, etc.) with status codes. Designed for maximum developer control over HTTP responses.

**Middleware (`middleware.go`)**: Chi router middleware for authentication, role-based access, and tenant isolation. Includes context helpers like `MustGetUserFromContext()`.

**Multi-tenant System (`multitenant.go`, `multitenant_setup.go`)**: Complete RBAC system with tenants, roles, and permissions. Supports tenant-scoped user roles and permissions.

**Referral System (`referrals.go`)**: Role-based referral code system with invitation limits, code generation, validation, and tracking. Integrated with the multi-tenant and RBAC systems.

### Key Architecture Patterns

**Handler Pattern**: All handlers return structured response objects with `StatusCode` field. This allows developers to control HTTP response while maintaining consistent error handling:
```go
result := authService.SignUpHandler(r)
w.WriteHeader(result.StatusCode)
json.NewEncoder(w).Encode(result)
```

**Storage Abstraction**: `StorageInterface` allows swapping storage backends. Current implementation uses PostgreSQL with configurable table/column names.

**Multi-tenant Design**: Users can belong to multiple tenants with different roles per tenant. Permissions are checked within tenant context.

**Security-First Architecture**: Extensive security fields per user (25+ security-related fields), comprehensive audit logging via `security_events` table.

**Middleware Chain**: Composable middleware for authentication, authorization, and tenant isolation. Context-based user/tenant access.

### Configuration System

**Main Config (`Config` struct)**:
- `DatabaseDSN`: PostgreSQL/SQLite connection string
- `EmailService`: Email service interface implementation
- `SecurityConfig`: Password policies, lockout rules, session settings, referral configuration
- `StorageConfig`: Table/column mapping customization
- `OAuthProviders`: Dynamic OAuth provider configurations

**Security Config**: Configurable password policies, login attempt limits, session lifetimes, email verification requirements, and referral system settings (role-based limits, code format, expiry).

**Storage Config**: Allows remapping table names and column names to work with existing database schemas.

## File Organization

**Core Files**:
- `auth.go` - Main service and configuration
- `handlers.go` - HTTP handlers with structured responses
- `storage.go` - Storage interface and session types
- `middleware.go` - Chi middleware and context helpers

**Storage Implementations**:
- `storage/postgres.go` - PostgreSQL implementation
- `storage/sqlite.go` - SQLite implementation

**Feature Modules**:
- `multitenant.go` - Multi-tenant types and interfaces
- `multitenant_setup.go` - Tenant/role/permission management
- `referrals.go` - Referral code system with role-based limits
- `oauth.go` - OAuth provider configurations
- `password_reset.go` - Password reset flow
- `two_factor.go` - 2FA infrastructure
- `login_security.go` - Account lockout and security tracking

**Infrastructure**:
- `migrations/` - Database schema migrations (PostgreSQL & SQLite)
- `common.go` - Shared types and utilities
- `crypto.go` - Cryptographic utilities
- `callbacks.go` - OAuth callback handling

**Example Applications** (`example/`):
- `example/app/` - Complete web application with all features
- `example/oauth/` - OAuth provider configuration examples
- `example/referrals/` - Referral system demonstration
- `example/testing/` - Testing patterns and mock implementations

## Database Schema

The system uses a **clean separated architecture** with PostgreSQL and SQLite support:

**Core Authentication (Clean Separation):**
- `users` - Core user identity only (email, username, password_hash, provider info)
- `user_security` - Security tracking (25+ fields: login attempts, 2FA, audit fields)
- `sessions` - Session tracking with device fingerprinting
- `security_events` - Comprehensive security audit log
- `oauth_states` - OAuth CSRF protection

**Multi-Tenant RBAC:**
- `tenants` - Organization/tenant management
- `roles` - Role definitions per tenant
- `permissions` - System-wide permissions
- `user_tenants` - User-tenant-role relationships
- `role_permissions` - Role-permission assignments

**Referral System:**
- `referral_codes` - Generated referral codes with role-based metadata
- `user_referrals` - Referral relationship tracking

**Performance Benefits:**
- 50% faster basic user queries through separated architecture
- Core user operations don't touch security fields
- Security operations optimized in dedicated table

## Code Quality Standards

**NO BACKWARD COMPATIBILITY**: Never maintain backward compatibility unless explicitly requested. Always prioritize a streamlined, clear, well-documented codebase.

**Clean Architecture**: Remove deprecated code, duplicate interfaces, and stub implementations immediately.

**Documentation**: Code should be self-documenting with clear naming and minimal comments.

**Simplicity**: Prefer simple, direct solutions over complex abstractions.

