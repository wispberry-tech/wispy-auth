# Test Implementation Plan for 70%+ Coverage

## 📊 Current State Analysis

**Current Coverage**: 1.9% (19 statements out of ~1000)
**Target Coverage**: 70%+ (700+ statements)
**Gap**: ~681 statements need test coverage

### Existing Test Files
- ✅ `minimal_test.go` - Basic service creation (3 tests)
- ✅ `storage/storage_test.go` - Comprehensive storage tests (15 tests)

### Missing Test Files (Priority Order)
1. `auth_test.go` - Core authentication service (HIGH)
2. `handlers_test.go` - HTTP handlers (HIGH)
3. `two_factor_test.go` - 2FA functionality (HIGH)
4. `middleware_test.go` - Authentication middleware (MEDIUM)
5. `multitenant_test.go` - Multi-tenant operations (MEDIUM)
6. `referrals_test.go` - Referral system (MEDIUM)
7. `crypto_test.go` - Cryptographic utilities (LOW)
8. `common_test.go` - Common utilities (LOW)

## 🎯 Implementation Strategy

### Phase 1: Core Authentication (Target: +40% coverage)
**Priority**: CRITICAL
**Timeline**: Day 1-2

#### `auth_test.go`
```go
// Test functions to implement:
- TestNewAuthService
- TestNewAuthServiceErrors
- TestSignUp
- TestSignUpValidation
- TestSignUpDuplicateEmail
- TestSignIn
- TestSignInInvalidCredentials
- TestSignInLockedAccount
- TestGetAvailableProviders
- TestOAuthConfiguration
- TestDefaultConfigs
```

**Key Test Scenarios:**
- Service initialization with valid/invalid configs
- User registration flow (success/error cases)
- Login authentication (success/failure/lockout)
- OAuth provider configuration
- Error handling and validation

### Phase 2: HTTP Handlers (Target: +20% coverage)
**Priority**: HIGH
**Timeline**: Day 2-3

#### `handlers_test.go`
```go
// Test functions to implement:
- TestSignUpHandler
- TestSignInHandler
- TestValidateHandler
- TestForgotPasswordHandler
- TestResetPasswordHandler
- TestVerifyEmailHandler
- TestEnable2FAHandler
- TestSend2FACodeHandler
- TestVerify2FACodeHandler
- TestGenerate2FABackupCodesHandler
- TestDisable2FAHandler
- TestGenerateReferralCodeHandler
- TestGetMyReferralCodesHandler
- TestGetMyReferralsHandler
- TestGetReferralStatsHandler
```

**Key Test Scenarios:**
- HTTP request/response handling
- JSON marshaling/unmarshaling
- Status code validation
- Error response formats
- Authentication context

### Phase 3: Security Features (Target: +15% coverage)
**Priority**: HIGH
**Timeline**: Day 3-4

#### `two_factor_test.go`
```go
// Test functions to implement:
- TestEnable2FAForUser
- TestSend2FACode
- TestVerify2FACode
- TestGenerate2FABackupCodes
- TestDisable2FAForUser
- TestValidateBackupCode
- Test2FACodeExpiry
- Test2FARateLimiting
- Test2FALockout
- TestBackupCodeOneTimeUse
```

**Key Test Scenarios:**
- 2FA enablement/disablement
- Code generation and validation
- Backup code generation and usage
- Rate limiting and lockout mechanisms
- Security event logging

### Phase 4: System Integration (Target: +10% coverage)
**Priority**: MEDIUM
**Timeline**: Day 4-5

#### `middleware_test.go`
```go
// Test functions to implement:
- TestRequireAuth
- TestRequirePermission
- TestRequireRole
- TestContextHelpers
- TestMustGetUserFromContext
- TestMustGetTenantFromContext
- TestAuthenticationFailure
- TestUnauthorizedAccess
```

#### `multitenant_test.go`
```go
// Test functions to implement:
- TestCreateTenant
- TestCreateRole
- TestCreatePermission
- TestAssignPermissionToRole
- TestAssignUserToTenant
- TestGetUserTenants
- TestGetUserRoles
- TestGetUserPermissions
- TestTenantIsolation
```

### Phase 5: Feature Completeness (Target: +5% coverage)
**Priority**: LOW
**Timeline**: Day 5-6

#### `referrals_test.go`
#### `crypto_test.go`
#### `common_test.go`

## 🛠 Implementation Details

### Test Infrastructure Setup

#### Test Helper Functions
```go
// auth_test.go helpers
func createTestAuthService(t *testing.T) (*AuthService, storage.Interface)
func createTestConfig() Config
func createTestUser(t *testing.T, service *AuthService) *storage.User

// handlers_test.go helpers
func createTestRequest(method, url string, body interface{}) *http.Request
func executeHandler(handler http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder
func assertStatusCode(t *testing.T, recorder *httptest.ResponseRecorder, expected int)
func assertJSONResponse(t *testing.T, recorder *httptest.ResponseRecorder, expected interface{})

// Generic test helpers
func assertNoError(t *testing.T, err error)
func assertError(t *testing.T, err error, expectedMessage string)
```

#### Mock Email Service Enhancement
```go
type TestEmailService struct {
    SentEmails []EmailRecord
    mu         sync.Mutex
}

type EmailRecord struct {
    Type      string // "verification", "reset", "2fa", etc.
    Email     string
    Token     string
    Timestamp time.Time
}

func (s *TestEmailService) GetSentEmails() []EmailRecord
func (s *TestEmailService) GetLastEmail() *EmailRecord
func (s *TestEmailService) Reset()
```

### Priority Test Cases by Function

#### Critical Path Tests (Must have 100% coverage)
1. **User Authentication**
   - `SignUp()` - All branches
   - `SignIn()` - All branches
   - `ValidateSession()` - All branches

2. **Security Operations**
   - `Enable2FAForUser()` - All branches
   - `Verify2FACode()` - All branches
   - Password validation functions

3. **Authorization**
   - `RequireAuth()` middleware
   - `RequirePermission()` middleware
   - Context extraction functions

#### High Impact Tests (Target 80%+ coverage)
1. **HTTP Handlers** - All public endpoints
2. **Multi-tenant Operations** - Core RBAC functions
3. **Referral System** - Code generation and validation

#### Medium Impact Tests (Target 60%+ coverage)
1. **Utility Functions** - Crypto, validation helpers
2. **Configuration** - Default configs, validation
3. **Error Handling** - Custom error types

## 📋 Implementation Checklist

### Week 1: Foundation
- [ ] Create `auth_test.go` with core service tests
- [ ] Create `handlers_test.go` with HTTP tests
- [ ] Create `two_factor_test.go` with 2FA tests
- [ ] Achieve 50%+ coverage

### Week 2: Integration
- [ ] Create `middleware_test.go`
- [ ] Create `multitenant_test.go`
- [ ] Achieve 65%+ coverage

### Week 3: Completeness
- [ ] Create remaining test files
- [ ] Add edge case tests
- [ ] Achieve 70%+ coverage
- [ ] Performance benchmarks

### Quality Gates
- [ ] All tests pass consistently
- [ ] No race conditions (`go test -race`)
- [ ] Tests run in <5 seconds
- [ ] Coverage report generated
- [ ] Documentation updated

## 🔧 Tools and Commands

### Development Commands
```bash
# Run tests with coverage
go test -cover -coverprofile=coverage.out

# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html

# Run tests with race detection
go test -race -cover

# Run specific test file
go test -cover -run TestAuth

# Verbose test output
go test -v -cover

# Benchmark tests
go test -bench=. -benchmem
```

### Coverage Targets by Command
```bash
# Check overall coverage
go test -cover | grep "coverage:"

# Per-package coverage
go test ./... -cover

# Function-level coverage
go tool cover -func=coverage.out

# Missing coverage lines
go tool cover -func=coverage.out | grep 0.0%
```

## 📊 Success Metrics

### Coverage Goals
- **Day 1**: 25% coverage (auth core)
- **Day 3**: 50% coverage (handlers + 2FA)
- **Day 5**: 65% coverage (middleware + multitenant)
- **Day 7**: 70%+ coverage (complete)

### Quality Metrics
- **Test Execution**: <5 seconds total
- **Test Reliability**: 100% consistent results
- **Code Quality**: No race conditions
- **Documentation**: All public functions tested

### Continuous Monitoring
```bash
# Add to CI/CD pipeline
go test -cover -race -timeout=30s ./...

# Coverage threshold check
go test -cover | awk '/coverage:/ {if ($3 < 70.0) exit 1}'
```

---

This plan provides a systematic approach to achieving 70%+ test coverage while maintaining code quality and ensuring comprehensive testing of critical security features.