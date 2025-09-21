# Basic Authentication Example

This example demonstrates basic email/password authentication with session management and security features.

## Features Demonstrated

- ✅ Email/password signup and signin
- ✅ Session management with tokens
- ✅ Password security requirements
- ✅ Account lockout protection
- ✅ Protected routes with middleware
- ✅ In-memory SQLite with automatic migrations
- ✅ Database schema setup from migration files

## Running the Example

```bash
cd examples/basic-auth
go mod tidy
go run main.go
```

## Testing the API

### 1. Sign Up
```bash
curl -X POST http://localhost:8080/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Password123"}'
```

### 2. Sign In
```bash
curl -X POST http://localhost:8080/signin \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Password123"}'
```

### 3. Access Protected Route
```bash
curl -X GET http://localhost:8080/profile \
  -H 'Authorization: Bearer YOUR_TOKEN_HERE'
```

### 4. Sign Out (Demo)
```bash
curl -X POST http://localhost:8080/signout \
  -H 'Authorization: Bearer YOUR_TOKEN_HERE'
```
*Note: This is a demo endpoint - in production you'd implement proper session invalidation.*

## Configuration Highlights

- **Password Requirements**: 8+ chars, uppercase, lowercase, numbers
- **Session Duration**: 24 hours
- **Max Login Attempts**: 5 before lockout
- **Lockout Duration**: 15 minutes
- **Email Verification**: Disabled for simplicity