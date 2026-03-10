# Wispy Auth - Implementation Plan

## Overview
This plan addresses all critical issues and implements missing functionality while maintaining backward compatibility. The library will remain dependency-light and router-agnostic.

## Status: 🚧 In Progress (Phase 1 Complete, Phase 2 In Progress)

## Completed Work Summary:

### ✅ Phase 1: Critical Security Fixes
1. ✅ **Debug logging secured** - Removed sensitive logging from `extractTokenFromRequest()`
2. ✅ **Configuration validation** - Added `validateSecurityConfig()` with comprehensive validation
3. ✅ **Password reset token security** - Only returns token in debug mode
4. ✅ **Automated cleanup jobs** - Background goroutine for cleaning expired data

### 🔄 Phase 2: Email Service & 2FA (Days 2-3)
1. ✅ **Email service interface** - Created `core/email_service.go`
2. ✅ **SMTP email implementation** - Created `core/email_service_smtp.go`
3. 📋 **Mock email service** - Need to create
4. ✅ **2FA database schema** - Added `TwoFactorCode`, `TwoFactorBackupCode`, `RefreshToken` structs
5. ✅ **2FA SQL tables** - Added to both SQLite and PostgreSQL schemas
6. ✅ **Storage interface updates** - Added all 2FA and refresh token methods
7. ✅ **SQLite storage implementation** - Implemented all 2FA and refresh token methods
8. ✅ **PostgreSQL storage implementation** - Implemented all 2FA and refresh token methods
9. 📋 **2FA business logic** - Need to create `core/twofactor.go`
10. 📋 **2FA request/response types** - Need to add to handlers.go
11. 📋 **2FA handlers** - Need to create in handlers.go
12. 📋 **Integrate 2FA into login flow** - Need to modify SignInHandler

### ✅ Phase 3: Database & Infrastructure (Days 4-5)
1. 📋 **Database migration system** - Need to create
2. ✅ **Compound indexes** - Added to both SQLite and PostgreSQL schemas
3. ✅ **Make hardcoded values configurable** - Added to SecurityConfig
4. ✅ **Redis rate limiting** - Not needed per user request
5. 📋 **Refresh token mechanism** - Partially done (storage layer complete, handlers needed)

### 📋 Phase 4: User Experience (Days 6-7)
1. 📋 **Refresh token handlers** - Need to implement in handlers.go
2. 📋 **Standardize time handling** - Need to implement

### 📋 Phase 5: Code Quality & Polish (Days 8-9)
1. 📋 **Custom error types** - Need to create
2. 📋 **Improved input validation** - Need to implement
3. 📋 **Standardize documentation** - Need to update
4. 📋 **Monitoring/metrics integration** - Need to implement

## Next Steps:
- Create mock email service
- Implement 2FA business logic (twofactor.go)
- Implement 2FA handlers
- Integrate 2FA into login flow
- Implement refresh token handlers
- Create mock storage for testing
- Update all tests
- Create migration system
- Create documentation

---

## Phase 1: Critical Security Fixes (Day 1)

### 1.1 Secure Debug Logging ✅ **COMPLETED**
- Removed sensitive logging from `extractTokenFromRequest()`
- Removed unused `log/slog` import from `core/common.go`

### 1.2 Configuration Validation ✅ **COMPLETED**
**File:** `core/auth.go`
- Add validation function
- Add `DebugMode` to Config struct
- Call validation in `NewAuthService()`
- Add cleanup goroutine support
- Add email service support to Config and AuthService

### 1.3 Password Reset Token Security ✅ **COMPLETED**
**File:** `core/handlers.go`
- Modified `ForgotPasswordHandler` to check DebugMode
- Only return token in debug mode with warning log

### 1.4 Automated Cleanup Jobs 🔄 **IN PROGRESS**
**File:** `core/auth.go`

**Changes:**
- Add validation function
- Add `DebugMode` to Config struct
- Call validation in `NewAuthService()`

### 1.3 Password Reset Token Security 📋 **PENDING**
**File:** `core/handlers.go`
- Modify `ForgotPasswordHandler` to check DebugMode
- Only return token in debug mode

### 1.4 Automated Cleanup Jobs ✅ **COMPLETED**
**File:** `core/auth.go`
- Added cleanup goroutine
- Added cleanup interval configuration
- Modified `Close()` method

**File:** `core/storage.go`
- Added `CleanupExpiredOAuthStates()` to Storage interface
- Added `CleanupExpired2FACodes()` to Storage interface
- Added `CleanupExpiredRefreshTokens()` to Storage interface

**File:** `core/storage/sqlite.go`
- Implemented `CleanupExpiredOAuthStates()`
- Implemented `CleanupExpired2FACodes()`
- Implemented `CleanupExpiredRefreshTokens()`

**File:** `core/storage/postgres.go`
- Implemented `CleanupExpiredOAuthStates()`
- Implemented `CleanupExpired2FACodes()`
- Implemented `CleanupExpiredRefreshTokens()`

---

## Phase 2: Email Service & 2FA (Days 2-3)

### 2.1 Email Service Interface ✅ **COMPLETED**
**New File:** `core/email_service.go`
- Define `EmailService` interface
- Define `EmailServiceConfig` struct

### 2.2 SMTP Email Implementation 📋 **PENDING**
**New File:** `core/email_service_smtp.go`
- Implement SMTP email sending
- Support TLS and authentication
- Template formatting

### 2.3 Mock Email for Testing 📋 **PENDING**
**New File:** `core/email_service_mock.go`
- Mock implementation for testing
- Track sent emails

### 2.4 2FA Database Schema 📋 **PENDING**
**File:** `core/storage.go`
- Add `TwoFactorCode` struct
- Add `TwoFactorBackupCode` struct
- Add 2FA operations to Storage interface

### 2.5 2FA SQL Tables 📋 **PENDING**
**File:** `core/sql/sqlite_core.sql`
- Add `two_factor_codes` table
- Add `two_factor_backup_codes` table
- Add indexes

**File:** `core/sql/postgres_core.sql`
- Add `two_factor_codes` table
- Add `two_factor_backup_codes` table
- Add indexes

### 2.6 2FA Business Logic 📋 **PENDING**
**New File:** `core/twofactor.go`
- `Enable2FA()` - Send verification code
- `VerifyEnable2FA()` - Verify code and enable 2FA
- `Disable2FA()` - Disable 2FA
- `VerifyLogin2FA()` - Verify 2FA during login
- `SendLogin2FACode()` - Send login 2FA code
- `GetBackupCodes()` - Get backup codes
- `RegenerateBackupCodes()` - Regenerate backup codes

### 2.7 2FA Request/Response Types 📋 **PENDING**
**File:** `core/handlers.go`
- Add 2FA request/response types

### 2.8 2FA Handlers 📋 **PENDING**
**File:** `core/handlers.go`
- `Enable2FAHandler()`
- `VerifyEnable2FAHandler()`
- `Disable2FAHandler()`
- `VerifyLogin2FAHandler()`
- `GetBackupCodesHandler()`
- `RegenerateBackupCodesHandler()`

### 2.9 Integrate 2FA into Login Flow 📋 **PENDING**
**File:** `core/handlers.go`
- Modify `SignInHandler` to check for 2FA
- Send 2FA code if required
- Return `Requires2FA` flag

### 2.10 Update AuthService 📋 **PENDING**
**File:** `core/auth.go`
- Add `EmailService` to Config
- Add to AuthService struct
- Initialize in `NewAuthService()`

---

## Phase 3: Database & Infrastructure (Days 4-5)

### 3.1 Database Migration System 📋 **PENDING**
**New Directory:** `core/migrations/`
- Create migration files (001, 002, etc.)
- `core/migrations/migrator.go` - Migration logic
- `cmd/migrate/main.go` - CLI tool

### 3.2 Compound Indexes 📋 **PENDING**
**File:** `core/sql/sqlite_core.sql`
- Add compound indexes for better query performance

**File:** `core/sql/postgres_core.sql`
- Add compound indexes for better query performance

### 3.3 Make Hardcoded Values Configurable 📋 **PENDING**
**File:** `core/auth.go`
- Add to `SecurityConfig`:
  - `OAuthStateExpiry`
  - `PasswordResetExpiry`
  - `DeviceFingerprintWindow`
  - `TokenLength`
  - `BackupCodeCount`
- Update `DefaultSecurityConfig()`

### 3.4 Redis-based Rate Limiting ❌ **REMOVED**
- User does not need Redis-based rate limiting
- Will continue using in-memory rate limiter

---

## Phase 4: User Experience (Days 6-7)

### 4.1 Refresh Token Mechanism 📋 **PENDING**
**File:** `core/storage.go`
- Add `RefreshToken` struct
- Add refresh token operations to Storage interface

**File:** `core/handlers.go`
- Add `RefreshTokenHandler()`
- Add `RefreshTokenRequest`/`RefreshTokenResponse` types
- Modify `SignInHandler` to create refresh token

**SQL Files:**
- Add `refresh_tokens` table
- Add indexes

### 4.2 Standardize Time Handling 📋 **PENDING**
**File:** `core/storage.go`
- Ensure all nullable datetime fields use `*time.Time`

**File:** `core/storage/sqlite.go`
- Use `sql.NullTime` for scanning

**File:** `core/storage/postgres.go`
- Use `sql.NullTime` for scanning

---

## Phase 5: Code Quality & Polish (Days 8-9)

### 5.1 Custom Error Types 📋 **PENDING**
**New File:** `core/errors.go`
- Define `AuthError` struct
- Define `ErrorType` constants
- Create error constructors

### 5.2 Improved Input Validation 📋 **PENDING**
**File:** `core/common.go`
- Add common password check
- Add input sanitization
- Update `validatePasswordStrength()`

### 5.3 Standardize Documentation 📋 **PENDING**
**Files to update:**
- `README.md` - Fix "Zero Dependencies" claim, update 2FA status
- `core/README.md` - Update with new features
- Create `README_ENV.md` - ENV configuration documentation

### 5.4 Monitoring/Metrics Integration 📋 **PENDING**
**New File:** `core/metrics.go`
- Define `MetricsCollector` interface
- Implement `DefaultMetricsCollector`
- Integrate metrics throughout handlers

---

## Testing Strategy

### Test Coverage Requirements
Write tests for **all exposed service methods**:

### Core Handlers (`handlers.go`)
- ✅ SignUpHandler
- ✅ SignInHandler
- ✅ ValidateHandler
- ✅ LogoutHandler
- ✅ GetSessionsHandler
- ✅ ForgotPasswordHandler
- ✅ ResetPasswordHandler
- ✅ ChangePasswordHandler
- ✅ Enable2FAHandler
- ✅ VerifyEnable2FAHandler
- ✅ Disable2FAHandler
- ✅ VerifyLogin2FAHandler
- ✅ GetBackupCodesHandler
- ✅ RegenerateBackupCodesHandler
- ✅ RefreshTokenHandler

### OAuth Handlers (`oauth_handlers.go`)
- ✅ OAuthInitHandler
- ✅ OAuthCallbackHandler

### Storage Operations (`storage.go`)
All interface methods in both SQLite and PostgreSQL implementations.

### 2FA Logic (`twofactor.go`)
- ✅ Enable2FA
- ✅ VerifyEnable2FA
- ✅ Disable2FA
- ✅ VerifyLogin2FA
- ✅ SendLogin2FACode
- ✅ GetBackupCodes
- ✅ RegenerateBackupCodes

### Common Utilities (`common.go`)
- ✅ Password hashing and verification
- ✅ Token generation
- ✅ Password validation
- ✅ IP extraction
- ✅ Rate limiting

### Migration System
- ✅ Migration up
- ✅ Migration down
- ✅ Migration tracking

### Email Service
- ✅ SMTP email sending
- ✅ Mock email service
- ✅ Template formatting

---

## ENV Configuration Documentation

Create `README_ENV.md` with complete environment variable reference.

---

## Summary

This comprehensive plan addresses all identified issues with:

✅ **High Priority** (Critical security fixes)
1. ✅ Debug logging secured
2. 🔄 Complete 2FA implementation (email-based with ENV config)
3. 📋 Password reset token security
4. 📋 Automated cleanup jobs
5. 📋 Email service interface (SMTP + Mock)
6. 🔄 Configuration validation

✅ **Medium Priority** (Infrastructure improvements)
7. 📋 Database migration system (explicit command)
8. ❌ ~~Redis-based rate limiting~~ (REMOVED per user request)
9. 📋 Compound indexes
10. 📋 Configurable hardcoded values
11. 📋 Refresh token mechanism (multiple concurrent)
12. 📋 Standardized time handling

✅ **Low Priority** (Code quality)
13. 📋 Custom error types
14. 📋 Improved input validation
15. ✅ No health check (skipped per user request)
16. 📋 Standardized documentation
17. 📋 Monitoring/metrics integration

✅ **Testing**
- Comprehensive tests for all exposed service methods
- Test coverage for all new features
- Integration tests for end-to-end flows

---

## Issues Found & Fixed

### ✅ Fixed Issues

#### 1. Inconsistent Metadata Field Types
**Issue:** 
- SQLite: `metadata TEXT`
- PostgreSQL: `metadata JSONB`
- Storage struct: `Metadata string` (TEXT type)

**Fix:** Standardized to `TEXT` in PostgreSQL schema for consistency

#### 2. Missing Description Field (Already Present)
**Status:** ✅ Already correctly implemented
- Both SQLite and PostgreSQL schemas have `description TEXT` field
- Storage struct correctly defines `Description string`

---

## Status: 🚧 In Progress (Phase 1 Complete, Phase 2 In Progress)

## Completed Work Summary:

### ✅ Phase 1: Critical Security Fixes
1. ✅ **Debug logging secured** - Removed sensitive logging from `extractTokenFromRequest()`
2. ✅ **Configuration validation** - Added `validateSecurityConfig()` with comprehensive validation
3. ✅ **Password reset token security** - Only returns token in debug mode
4. ✅ **Automated cleanup jobs** - Background goroutine for cleaning expired data
5. ✅ **Email service interface** - Created `core/email_service.go`
6. ✅ **Storage interface updates** - Added cleanup methods for 2FA/OAuth/refresh tokens

### ✅ Phase 2: Email Service & 2FA (Partially Complete)
1. ✅ **Email service interface** - Created `core/email_service.go`
2. ✅ **SMTP implementation** - Created `core/email_service_smtp.go` with TLS support
3. ✅ **Mock email service** - Created `core/email_service_mock.go` for testing
4. ✅ **2FA database structs** - Added `TwoFactorCode`, `TwoFactorBackupCode`, `RefreshToken` to storage.go
5. ✅ **2FA SQL tables** - Added 2FA and refresh token tables to both schemas
6. ✅ **Storage interface** - Added all 2FA and refresh token methods
7. ✅ **SQLite storage** - Implemented all 2FA, backup code, and refresh token methods
8. ✅ **PostgreSQL storage** - Implemented all 2FA, backup code, and refresh token methods
9. ✅ **Mock storage updates** - Added all missing methods to test mock storage
10. 📋 **2FA business logic** - Need to create `core/twofactor.go`
11. 📋 **2FA handlers** - Need to add to handlers.go
12. 📋 **2FA integration** - Need to modify login flow

### ✅ Phase 3: Database & Infrastructure (Partially Complete)
1. ✅ **Compound indexes** - Added to both SQLite and PostgreSQL schemas
2. ✅ **Configurable values** - Added to SecurityConfig (OAuthStateExpiry, PasswordResetExpiry, etc.)
3. ✅ **Schema updates** - Fixed metadata type inconsistency
4. 📋 **Migration system** - Need to create
5. ✅ **Redis rate limiting** - Not needed per user request

### 📋 Phase 4: User Experience (In Progress)
1. 📋 **Refresh token handler** - Storage complete, handler needed
2. 📋 **Refresh token integration** - Need to modify SignInHandler
3. 📋 **Time handling** - Need to standardize

---

## 🚧 Remaining Work:

### Phase 2 (In Progress)
1. 📋 Create `core/twofactor.go` - Complete 2FA business logic
2. 📋 Add 2FA request/response types to handlers.go
3. 📋 Implement 2FA handlers in handlers.go
4. 📋 Integrate 2FA into login flow (modify SignInHandler)

### Phase 4 (In Progress)
1. 📋 Implement `RefreshTokenHandler` in handlers.go
2. 📋 Modify `SignInHandler` to create and return refresh tokens

### Phase 3 (Pending)
1. 📋 Create migration system (`core/migrations/migrator.go`)
2. 📋 Create migration files
3. 📋 Create CLI tool (`cmd/migrate/main.go`)

### Phase 5 (Pending)
1. 📋 Create `core/errors.go` - Custom error types
2. 📋 Improve input validation in common.go
3. 📋 Update documentation
4. 📋 Create `core/metrics.go` - Monitoring interface

---

**Last Updated:** Schema inconsistency fixed
