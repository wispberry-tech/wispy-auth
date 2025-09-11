# Nucleus Auth Example with Chi Router

This example demonstrates how to integrate the Nucleus Auth library with the Chi router for a complete authentication system.

## 🚀 Features

- ✅ **Complete Chi router integration**
- ✅ **All authentication endpoints** (signup, signin, validate, etc.)
- ✅ **Password reset flow** with email notifications
- ✅ **Email verification system**
- ✅ **Session management** (view, revoke sessions)
- ✅ **OAuth2 providers** (Google, GitHub, Discord)
- ✅ **Security middleware** and authentication guards
- ✅ **Database migrations** with comprehensive schema
- ✅ **Production-ready configuration**

## 📋 Prerequisites

- Go 1.21+
- PostgreSQL 12+
- (Optional) OAuth2 credentials for Google/GitHub/Discord

## 🛠 Setup

### 1. Clone and Install Dependencies

```bash
cd example
go mod tidy
```

### 2. Database Setup

Create a PostgreSQL database:
```sql
CREATE DATABASE auth_db;
```

### 3. Environment Configuration

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```bash
# Required
DATABASE_URL=postgresql://username:password@localhost:5432/auth_db
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters-long

# Optional OAuth providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
# ... other OAuth configs
```

### 4. Run Database Migrations

```bash
cd migrations
go run migrate.go
cd ..
```

This will create all necessary tables:
- `users` - Enhanced user table with security features
- `sessions` - Session management with device tracking
- `security_events` - Audit logging for security events
- `tenants`, `roles`, `permissions` - Multi-tenant support (optional)

### 5. Start the Server

```bash
go run main.go handlers.go services.go
```

The server will start on `http://localhost:8080`

## 📚 API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/signup` | User registration |
| POST | `/auth/signin` | User login |
| GET | `/auth/validate` | Validate JWT token |

### Password Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/forgot-password` | Initiate password reset |
| POST | `/auth/reset-password` | Reset password with token |

### Email Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/verify-email` | Verify email with token |
| POST | `/auth/resend-verification` | Resend verification email |

### Session Management (Protected)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/sessions` | Get all user sessions |
| DELETE | `/auth/sessions/{id}` | Revoke specific session |
| POST | `/auth/logout-all` | Revoke all sessions |

### OAuth2

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/oauth?provider=google` | Initiate OAuth flow |
| GET | `/auth/oauth/callback` | Handle OAuth callback |
| GET | `/auth/providers` | List available providers |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |

## 🔧 Example Usage

### User Registration

```bash
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123",
    "name": "John Doe"
  }'
```

Response:
```json
{
  "token": "eyJ...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "name": "John Doe",
    "email_verified": false,
    "created_at": "2024-01-01T00:00:00Z"
  },
  "requires_email_verification": true
}
```

### User Login

```bash
curl -X POST http://localhost:8080/auth/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123"
  }'
```

### Validate Token

```bash
curl -X GET http://localhost:8080/auth/validate \
  -H "Authorization: Bearer eyJ..."
```

### Password Reset Flow

1. **Request reset:**
```bash
curl -X POST http://localhost:8080/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

2. **Reset with token:**
```bash
curl -X POST http://localhost:8080/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "new_password": "NewSecurePass123"
  }'
```

### Session Management

```bash
# Get all sessions
curl -X GET http://localhost:8080/auth/sessions \
  -H "Authorization: Bearer eyJ..."

# Revoke specific session
curl -X DELETE http://localhost:8080/auth/sessions/session-id \
  -H "Authorization: Bearer eyJ..."

# Logout from all devices
curl -X POST http://localhost:8080/auth/logout-all \
  -H "Authorization: Bearer eyJ..."
```

## 🔒 Security Features

### Implemented Security Measures

- ✅ **Password strength validation**
- ✅ **Account lockout** after failed attempts
- ✅ **Email verification** requirement
- ✅ **Password reset** with secure tokens
- ✅ **Session management** with device tracking
- ✅ **IP address logging** and location tracking
- ✅ **Security event auditing**
- ✅ **JWT token validation**
- ✅ **Rate limiting** ready
- ✅ **CORS protection**

### Security Event Logging

All security events are automatically logged:
- Login attempts (successful/failed)
- Password resets
- Email verifications
- Account lockouts
- Session creation/termination

Query security events:
```sql
SELECT * FROM security_events 
WHERE user_id = 1 
ORDER BY created_at DESC;
```

## 🏢 Multi-Tenant Support (Optional)

To enable multi-tenant mode, update the configuration:

```go
cfg.StorageConfig.MultiTenant = auth.MultiTenantConfig{
    Enabled:         true,
    DefaultTenantID: 1,
}
```

The migrations will create tenant-related tables:
- `tenants` - Organizations/tenants
- `roles` - Per-tenant roles
- `permissions` - Global permissions
- `role_permissions` - Role-permission mapping
- `user_tenants` - User-tenant-role relationships

## 📧 Email Integration

The example includes mock email functions that log to console. In production, replace these with your email service:

```go
// In handlers.go
func sendVerificationEmail(email, token string) {
    // Replace with your email service (SendGrid, Mailgun, etc.)
    emailService.Send(EmailTemplate{
        To:       email,
        Subject:  "Verify Your Email",
        Template: "verification",
        Data:     map[string]string{"token": token},
    })
}
```

## 🌐 Frontend Integration

### JavaScript/TypeScript Example

```javascript
class AuthClient {
    constructor(baseURL = 'http://localhost:8080') {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('auth_token');
    }

    async signup(email, password, name) {
        const response = await fetch(`${this.baseURL}/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, name })
        });
        
        const data = await response.json();
        if (data.token) {
            this.setToken(data.token);
        }
        return data;
    }

    async signin(email, password) {
        const response = await fetch(`${this.baseURL}/auth/signin`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        if (data.token) {
            this.setToken(data.token);
        }
        return data;
    }

    async validate() {
        if (!this.token) return null;
        
        const response = await fetch(`${this.baseURL}/auth/validate`, {
            headers: { 'Authorization': `Bearer ${this.token}` }
        });
        
        return response.ok ? response.json() : null;
    }

    setToken(token) {
        this.token = token;
        localStorage.setItem('auth_token', token);
    }

    logout() {
        this.token = null;
        localStorage.removeItem('auth_token');
    }
}

// Usage
const auth = new AuthClient();
const user = await auth.signin('user@example.com', 'password');
```

## 🚀 Production Deployment

### 1. Security Checklist

- [ ] Change JWT secret to a secure random string
- [ ] Use HTTPS in production
- [ ] Configure proper CORS origins
- [ ] Set up rate limiting
- [ ] Configure email service (SendGrid, Mailgun, etc.)
- [ ] Set up monitoring and alerts
- [ ] Configure database connection pooling
- [ ] Set up log aggregation

### 2. Environment Variables

```bash
# Production settings
DATABASE_URL=postgresql://user:pass@prod-db:5432/auth_db
JWT_SECRET=very-long-random-secret-for-production
PORT=8080

# Email service (example with SendGrid)
SENDGRID_API_KEY=your-sendgrid-api-key
FROM_EMAIL=noreply@yourapp.com

# OAuth (production URLs)
GOOGLE_CLIENT_ID=prod-google-client-id
GOOGLE_CLIENT_SECRET=prod-google-secret
```

### 3. Docker Deployment

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o auth-server .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth-server .
EXPOSE 8080
CMD ["./auth-server"]
```

## 🤝 Contributing

This example is part of the Nucleus Auth project. Feel free to submit improvements!

## 📄 License

This example is licensed under the same license as the main Nucleus Auth project.