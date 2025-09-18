# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Running the Example Application
```bash
# Start the example server
cd example
go run main.go services.go

# Or using the Makefile
make run

# Build the application
make build

# Run with migrations
make dev
```

### Testing
```bash
# Run all tests
go test -v ./...

# Run specific test file
go run test/test_api.go
```

### Database Operations
```bash
# Run database migrations (from example directory)
cd example/migrations
go run migrate.go

# Or using make
make migrate
```

### Development Environment
```bash
# Install dependencies
go mod tidy

# Setup environment file
make setup-env
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
- `DatabaseDSN`: PostgreSQL connection string
- `EmailService`: Email service interface implementation
- `SecurityConfig`: Password policies, lockout rules, session settings
- `StorageConfig`: Table/column mapping customization
- `OAuthProviders`: OAuth provider configurations

**Security Config**: Configurable password policies, login attempt limits, session lifetimes, and email verification requirements.

**Storage Config**: Allows remapping table names and column names to work with existing database schemas.

## File Organization

**Core Files**:
- `auth.go` - Main service and configuration
- `handlers.go` - HTTP handlers with structured responses  
- `storage.go` - Storage interface and session types
- `postgres_storage.go` - PostgreSQL implementation
- `middleware.go` - Chi middleware and context helpers

**Feature Modules**:
- `multitenant.go` - Multi-tenant types and interfaces
- `multitenant_setup.go` - Tenant/role/permission management
- `oauth.go` - OAuth provider configurations
- `password_reset.go` - Password reset flow
- `two_factor.go` - 2FA infrastructure
- `login_security.go` - Account lockout and security tracking

**Infrastructure**:
- `migrations.go` - Database schema migrations
- `common.go` - Shared types and utilities
- `crypto.go` - Cryptographic utilities

**Example Application** (`example/`): Complete working example showing integration patterns, email service implementation, and routing setup.

## Database Schema

The system uses PostgreSQL with these core tables:
- `users` - User accounts with 25+ security fields
- `sessions` - Session tracking with device fingerprinting
- `security_events` - Comprehensive security audit log
- `tenants`, `roles`, `permissions` - Multi-tenant RBAC system
- `user_tenants`, `role_permissions` - Relationship tables

Auto-migration is supported via `AutoMigrate: true` in config.