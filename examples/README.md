# 🌟 Wispy Auth Examples

This directory contains simple, focused examples demonstrating key features of the Wispy Auth library. Each example is self-contained and showcases specific functionality with minimal complexity.

## 📁 Available Examples

### 🔐 [Basic Auth](basic-auth/)
**Core authentication with session management**
- Email/password signup and signin
- Session token management
- Password security requirements
- Account lockout protection
- Protected route middleware

### 🌐 [OAuth Integration](oauth/)
**OAuth2 provider integration**
- Google OAuth2 setup
- GitHub OAuth2 setup
- Custom enterprise provider configuration
- Dynamic provider system
- Mixed authentication (OAuth + traditional)

### 🎯 [Referral System](referrals/)
**Role-based invitation system**
- Referral code generation and validation
- Role-based invitation limits
- Automatic user role assignment
- Referral analytics and tracking
- Complete referral audit trail

### 🏢 [Multi-Tenant RBAC](multitenant/)
**Complete multi-tenant application**
- Multiple tenant organizations
- Role-based access control
- Granular permission system
- Tenant-scoped operations
- Permission-based route protection

## 🚀 Quick Start

Each example is completely self-contained with its own `go.mod` file. To run any example:

```bash
# Choose an example
cd examples/basic-auth

# Install dependencies
go mod tidy

# Run the example
go run main.go
```

## 🧪 Testing the Examples

All examples run on `http://localhost:8080` and include:
- Health check endpoint: `GET /health`
- Detailed curl commands in each README
- Mock email service for testing
- In-memory SQLite for simplicity

## 📚 Learning Path

**New to authentication?** Start here:
1. **Basic Auth** - Learn core concepts
2. **OAuth Integration** - Add social login
3. **Multi-Tenant RBAC** - Scale to organizations
4. **Referral System** - Add growth features

**Building a SaaS?** Focus on:
1. **Multi-Tenant RBAC** - Core architecture
2. **OAuth Integration** - Enterprise SSO
3. **Referral System** - User growth
4. **Basic Auth** - Fallback authentication

## 🔧 Configuration Highlights

### Common Features Across Examples

**Security by Default:**
- Bcrypt password hashing
- Session token management
- Device fingerprinting
- IP address tracking
- Comprehensive audit logging

**Developer Experience:**
- Structured HTTP responses
- Consistent error handling
- Context-based user access
- Interface-based design
- Automatic database migrations

**Production Ready:**
- SQLite for development/testing
- PostgreSQL for production
- Migration-based schema management
- Configurable table/column mapping
- Email service abstraction

## 🎯 Feature Matrix

| Feature | Basic Auth | OAuth | Referrals | Multi-Tenant |
|---------|------------|-------|-----------|--------------|
| Email/Password Auth | ✅ | ✅ | ✅ | ✅ |
| Session Management | ✅ | ✅ | ✅ | ✅ |
| OAuth2 Providers | ❌ | ✅ | ❌ | ❌ |
| Referral Codes | ❌ | ❌ | ✅ | ❌ |
| Multi-Tenant RBAC | ❌ | ❌ | ✅ | ✅ |
| Role-Based Access | ❌ | ❌ | ✅ | ✅ |
| Permissions System | ❌ | ❌ | ❌ | ✅ |
| Tenant Switching | ❌ | ❌ | ❌ | ✅ |

## 🔒 Security Features

All examples demonstrate:
- **Password Security**: Configurable strength requirements
- **Session Security**: Device tracking and IP validation
- **Brute Force Protection**: Account lockout after failed attempts
- **Audit Logging**: Complete security event tracking
- **Input Validation**: Structured request validation
- **CSRF Protection**: State parameter validation for OAuth

## 🏗️ Architecture Patterns

### Structured Response Pattern
```go
result := authService.SignUpHandler(r)
w.WriteHeader(result.StatusCode)
json.NewEncoder(w).Encode(result)
```

### Context-Based Access
```go
user := auth.MustGetUserFromContext(r.Context())
tenant := auth.MustGetTenantFromContext(r.Context())
```

### Middleware Composition
```go
r.Use(authService.RequireAuth())
r.Use(authService.RequirePermission("documents", "read"))
```

## 🔧 Customization

Each example can be customized by modifying the `Config` struct:

```go
config := auth.Config{
    Storage:      sqliteStorage,
    EmailService: &MockEmailService{},
    SecurityConfig: auth.SecurityConfig{
        PasswordMinLength:      12,
        SessionDuration:        48 * time.Hour,
        RequireEmailVerification: true,
        MaxLoginAttempts:       3,
        LockoutDuration:        30 * time.Minute,
    },
    OAuthProviders: map[string]auth.OAuthProviderConfig{
        "google": auth.NewGoogleOAuthProvider(clientID, secret, callback),
    },
    AutoMigrate: true,
}
```

## 📖 Next Steps

After exploring the examples:

1. **Read the [API Reference](../docs/API_REFERENCE.md)** for complete endpoint documentation
2. **Review [Features Overview](../docs/FEATURES.md)** for comprehensive feature details
3. **Check [Project Structure](../docs/PROJECT_STRUCTURE.md)** for architecture insights
4. **Run the [Unit Tests](../*_test.go)** to understand testing patterns

## 🆘 Need Help?

- Check individual example READMEs for specific guidance
- Review the main [README](../README.md) for installation help
- Look at the [CLAUDE.md](../CLAUDE.md) for development commands
- Each example includes detailed curl commands for testing