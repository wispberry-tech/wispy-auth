# Testing Standards for Wispy Auth

## 🎯 Testing Goals

- **Minimum Coverage**: 70% statement coverage across all packages
- **Quality Over Quantity**: Focus on critical paths and edge cases
- **Clean Architecture**: Test separation between layers
- **Performance**: Ensure tests run quickly and efficiently
- **Security**: Validate all security-critical operations

## 📁 File Naming Convention

### Test File Structure
```
package_file.go → package_file_test.go
```

**Examples:**
- `auth.go` → `auth_test.go`
- `handlers.go` → `handlers_test.go`
- `two_factor.go` → `two_factor_test.go`
- `storage/sqlite.go` → `storage/sqlite_test.go`

### Test Function Naming
```go
// Unit tests
func TestFunctionName(t *testing.T)
func TestStructMethod(t *testing.T)

// Integration tests
func TestIntegrationFeatureName(t *testing.T)

// Error scenarios
func TestFunctionNameError(t *testing.T)
func TestFunctionNameInvalidInput(t *testing.T)

// Edge cases
func TestFunctionNameEdgeCase(t *testing.T)
```

## 🧪 Test Categories

### 1. Unit Tests (70% of tests)
- Individual function testing
- Mocked dependencies
- Fast execution (<1ms per test)
- No external dependencies

### 2. Integration Tests (25% of tests)
- End-to-end feature testing
- Real database operations (in-memory SQLite)
- Handler-to-storage integration
- Authentication flows

### 3. Security Tests (5% of tests)
- Input validation
- SQL injection prevention
- Authentication bypass attempts
- Authorization edge cases

## 🛠 Test Setup Standards

### Required Test Helper Functions
```go
// Storage setup for tests
func createTestStorage(t *testing.T) storage.Interface

// Mock email service for tests
type TestEmailService struct{}

// Test user creation
func createTestUser(t *testing.T, storage storage.Interface) *storage.User

// Test tenant creation
func createTestTenant(t *testing.T, storage storage.Interface) *storage.Tenant
```

### Test Database Setup
- **Use**: In-memory SQLite (`:memory:`)
- **Migrations**: Load from `sql/sqlite_scaffold.sql`
- **Isolation**: Each test gets fresh database
- **Cleanup**: Automatic with in-memory database

## 📊 Coverage Requirements by Package

| Package | Minimum Coverage | Priority Files |
|---------|------------------|----------------|
| **Root Package** | 75% | `auth.go`, `handlers.go` |
| **Storage** | 80% | `sqlite.go`, `postgres.go` |
| **Security** | 85% | `two_factor.go`, `login_security.go` |
| **Multi-tenant** | 70% | `multitenant.go`, `multitenant_setup.go` |
| **Utilities** | 60% | `crypto.go`, `common.go` |

## 🔒 Security Test Requirements

### Authentication Tests
- [ ] Valid login scenarios
- [ ] Invalid credentials
- [ ] Account lockout protection
- [ ] Session management
- [ ] Token validation

### Authorization Tests
- [ ] RBAC permission checking
- [ ] Tenant isolation
- [ ] Role-based access
- [ ] Permission escalation prevention

### Input Validation Tests
- [ ] SQL injection attempts
- [ ] XSS prevention
- [ ] Invalid email formats
- [ ] Password policy enforcement
- [ ] Unicode handling

### 2FA Security Tests
- [ ] Code expiration
- [ ] Brute force protection
- [ ] Backup code usage
- [ ] Rate limiting
- [ ] Replay attack prevention

## 📝 Test Documentation Standards

### Test Structure
```go
func TestFeatureName(t *testing.T) {
    // Arrange - Setup test data
    storage := createTestStorage(t)
    user := createTestUser(t, storage)

    // Act - Execute the function under test
    result, err := functionUnderTest(input)

    // Assert - Verify results
    if err != nil {
        t.Fatal("Unexpected error:", err)
    }

    if result != expectedValue {
        t.Errorf("Expected %v, got %v", expectedValue, result)
    }
}
```

### Error Testing Pattern
```go
func TestFeatureNameError(t *testing.T) {
    tests := []struct {
        name          string
        input         InputType
        expectedError string
    }{
        {"invalid email", InvalidInput{}, "invalid email format"},
        {"missing password", AnotherInput{}, "password required"},
    }

    for _, test := range tests {
        t.Run(test.name, func(t *testing.T) {
            _, err := functionUnderTest(test.input)
            if err == nil {
                t.Error("Expected error but got none")
            }
            if !strings.Contains(err.Error(), test.expectedError) {
                t.Errorf("Expected error containing '%s', got '%s'",
                    test.expectedError, err.Error())
            }
        })
    }
}
```

## 🚀 Performance Standards

### Test Execution Times
- **Unit tests**: <1ms each
- **Integration tests**: <100ms each
- **Full test suite**: <5 seconds
- **Coverage generation**: <10 seconds

### Memory Usage
- **Test process**: <50MB peak
- **Database**: In-memory only
- **No memory leaks**: Use `go test -race`

## 🔧 Test Infrastructure

### Required Mock Implementations
```go
// Email service mock
type TestEmailService struct {
    SentEmails []EmailRecord
}

// Storage interface test helpers
func (s *TestEmailService) SendVerificationEmail(email, token string) error
func (s *TestEmailService) Send2FACode(email, code string) error
// ... other methods

// HTTP test helpers
func createTestRequest(method, url string, body interface{}) *http.Request
func executeHandlerTest(handler http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder
```

### Test Data Management
```go
// Test user templates
var TestUsers = map[string]*storage.User{
    "valid":     {Email: "test@example.com", Username: "testuser"},
    "admin":     {Email: "admin@example.com", Username: "admin"},
    "suspended": {Email: "suspended@example.com", IsSuspended: true},
}

// Test tenant templates
var TestTenants = map[string]*storage.Tenant{
    "default": {Name: "Test Company", Slug: "test"},
    "acme":    {Name: "Acme Corp", Slug: "acme"},
}
```

## 📈 Coverage Tracking

### Command Usage
```bash
go test -cover
```

### Coverage Exclusions
- Example files (`examples/`)
- Generated code
- Third-party integrations
- Development tools

## ✅ Testing Checklist

### Pre-commit Checklist
- [ ] All tests pass
- [ ] Coverage ≥ 70%
- [ ] No race conditions (`go test -race`)
- [ ] Performance benchmarks stable
- [ ] Security tests pass

### New Feature Checklist
- [ ] Unit tests for all public functions
- [ ] Integration test for feature flow
- [ ] Error case testing
- [ ] Security validation tests
- [ ] Performance impact assessment

### Critical Path Testing
- [ ] User registration/login
- [ ] Session management
- [ ] 2FA operations
- [ ] RBAC enforcement
- [ ] Data isolation (multi-tenant)
- [ ] Security event logging

## 🎯 Test Quality Metrics

### Code Quality
- **Cyclomatic Complexity**: <10 per function
- **Test Coverage**: >70% statements
- **Test-to-Code Ratio**: 1:2 (50% test code)
- **Test Execution Time**: <5 seconds total

### Reliability
- **Flaky Tests**: 0% tolerance
- **Test Isolation**: 100% independent
- **Reproducible Results**: Always
- **Cross-platform**: Windows/Linux/macOS

---

## 🔄 Continuous Improvement

### Weekly Reviews
- Coverage trend analysis
- Performance regression detection
- Test failure pattern analysis
- Technical debt identification

### Monthly Updates
- Testing standard refinements
- Tool evaluation and upgrades
- Performance benchmark updates
- Security test enhancement

---

*This document is part of the Wispy Auth development standards and should be updated as the project evolves.*