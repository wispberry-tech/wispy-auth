# Auth Library

A minimal, production-ready Go authentication library supporting email/password and multiple OAuth providers (Google, GitHub, Discord).

## Features

- ✅ Email/Password authentication
- ✅ Google OAuth2
- ✅ GitHub OAuth2  
- ✅ Discord OAuth2
- ✅ JWT token generation & validation
- ✅ PostgreSQL database with flexible schema support
- ✅ Password hashing with bcrypt
- ✅ Multiple provider support per user
- ✅ **Multi-tenant support with roles & permissions**
- ✅ **Flexible database schema configuration**
- ✅ **Role-based access control (RBAC)**
- ✅ **Permission system**

## Installation

```bash
go mod init your-module-name
go mod tidy
```

## Environment Variables

Create a `.env` file:

```bash
# Database (PostgreSQL)
DATABASE_URL=postgresql://username:password@localhost:5432/auth_db

# JWT Secret (change this in production!)
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters-long

# Google OAuth
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret

# Discord OAuth
DISCORD_CLIENT_ID=your-discord-oauth-client-id
DISCORD_CLIENT_SECRET=your-discord-oauth-client-secret
```

## Quick Start

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/your-username/auth-library/auth"
)

func main() {
	// Configuration with flexible table names and schema
	cfg := auth.Config{
		DatabaseDSN: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		StorageConfig: auth.StorageConfig{
			UsersTable:    "users",           // Your table name
			SessionsTable: "user_sessions",   // Your session table name
			UserColumns: auth.UserColumnMapping{
				ID:           "id",
				Email:        "email",
				PasswordHash: "password_hash",
				Name:         "name",
				AvatarURL:    "avatar_url",
				Provider:     "provider",
				ProviderID:   "provider_id",
				CreatedAt:    "created_at",
				UpdatedAt:    "updated_at",
			},
			SessionColumns: auth.SessionColumnMapping{
				ID:        "id",
				UserID:    "user_id",
				Token:     "token",
				ExpiresAt: "expires_at",
				CreatedAt: "created_at",
				UpdatedAt: "updated_at",
			},
		},
		OAuthProviders: map[string]auth.OAuthProviderConfig{
			"google": {
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/auth/oauth/callback?provider=google",
			},
			"github": {
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/auth/oauth/callback?provider=github",
			},
			"discord": {
				ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
				ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
				RedirectURL:  "http://localhost:8080/auth/oauth/callback?provider=discord",
			},
		},
	}

	// Or use default configuration (single-tenant mode):
	// cfg := auth.Config{
	//     DatabaseDSN: os.Getenv("DATABASE_URL"),
	//     JWTSecret:   os.Getenv("JWT_SECRET"),
	//     StorageConfig: auth.DefaultStorageConfig(),
	//     OAuthProviders: map[string]auth.OAuthProviderConfig{...},
	// }

	// For multi-tenant setup:
	// cfg.StorageConfig.MultiTenant.Enabled = true
	// cfg.StorageConfig.MultiTenant.DefaultTenantID = 1

	// Initialize auth service
	authService, err := auth.NewAuthService(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}

	// Set up routes
	http.HandleFunc("/auth/signup", authService.SignUpHandler)
	http.HandleFunc("/auth/signin", authService.SignInHandler)
	http.HandleFunc("/auth/validate", authService.ValidateHandler)
	http.HandleFunc("/auth/oauth", authService.OAuthHandler)
	http.HandleFunc("/auth/oauth/callback", authService.OAuthCallbackHandler)
	http.HandleFunc("/auth/providers", func(w http.ResponseWriter, r *http.Request) {
		providers := []string{"google", "github", "discord"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": providers,
		})
	})

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## API Endpoints

### 1. Email/Password Sign Up
**POST** `/auth/signup`

```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "name": "John Doe"
}
```

Response:
```json
{
  "token": "123|valid-token",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "name": "John Doe",
    "provider": "email",
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z"
  }
}
```

### 2. Email/Password Sign In
**POST** `/auth/signin`

```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

Response: Same as signup response

### 3. Validate Token
**GET** `/auth/validate`

Headers:
```
Authorization: Bearer 123|valid-token
```

Response:
```json
{
  "id": 1,
  "email": "user@example.com",
  "name": "John Doe",
  "provider": "email",
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z"
}
```

### 4. OAuth Initiation
**GET** `/auth/oauth?provider=google`

Redirects to OAuth provider's login page.

### 5. OAuth Callback
**GET** `/auth/oauth/callback?provider=google&code=AUTH_CODE`

Returns same response as signup/signin with user data and JWT token.

### 6. List Providers
**GET** `/auth/providers`

```json
{
  "providers": ["google", "github", "discord"]
}
```

### 7. Health Check
**GET** `/health`

```
OK
```

## OAuth Setup Instructions

### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `http://localhost:8080/auth/oauth/callback?provider=google`

### GitHub OAuth
1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Create New OAuth App
3. Add authorization callback URL: `http://localhost:8080/auth/oauth/callback?provider=github`

### Discord OAuth
1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a New Application
3. Go to OAuth2 → General
4. Add redirect: `http://localhost:8080/auth/oauth/callback?provider=discord`

## Flexible Database Schema

The library now supports flexible database schemas! You can use existing tables with different names and column structures as long as they have the required columns.

### Default Schema
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    password_hash TEXT,
    name VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50),
    provider_id VARCHAR(255),
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX idx_users_provider_id ON users(provider_id);
CREATE INDEX idx_sessions_token ON sessions(token);
```

### Custom Schema Configuration
You can configure the library to work with your existing database schema:

```go
cfg := auth.Config{
    DatabaseDSN: os.Getenv("DATABASE_URL"),
    JWTSecret:   os.Getenv("JWT_SECRET"),
    StorageConfig: auth.StorageConfig{
        UsersTable:    "members",           // Your existing user table
        SessionsTable: "auth_sessions",     // Your session table
        UserColumns: auth.UserColumnMapping{
            ID:           "member_id",      // Your primary key column
            Email:        "email_address",  // Your email column
            PasswordHash: "pwd_hash",       // Your password column
            Name:         "full_name",      // Your name column
            AvatarURL:    "profile_pic",    // Your avatar column
            Provider:     "auth_provider",  // Your provider column
            ProviderID:   "external_id",    // Your provider ID column
            CreatedAt:    "created_on",     // Your created timestamp
            UpdatedAt:    "modified_on",    // Your updated timestamp
        },
        SessionColumns: auth.SessionColumnMapping{
            ID:        "session_id",
            UserID:    "member_id",
            Token:     "access_token",
            ExpiresAt: "expiry_time",
            CreatedAt: "created_on",
            UpdatedAt: "modified_on",
        },
    },
    OAuthProviders: map[string]auth.OAuthProviderConfig{
        // ... your OAuth providers
    },
}
```

### Required Columns
Your database tables must have columns that map to these logical fields:

**Users Table:**
- `ID` (integer, primary key)
- `Email` (string, for email address)
- `PasswordHash` (string, for hashed passwords)
- `Name` (string, for user's display name)
- `AvatarURL` (string, for profile picture URL)
- `Provider` (string, for auth provider: "email", "google", etc.)
- `ProviderID` (string, for external provider user ID)
- `CreatedAt` (timestamp)
- `UpdatedAt` (timestamp)

**Sessions Table:**
- `ID` (string, primary key)
- `UserID` (integer, foreign key to users)
- `Token` (string, unique session token)
- `ExpiresAt` (timestamp)
- `CreatedAt` (timestamp)
- `UpdatedAt` (timestamp)

## Multi-Tenant Support

The library includes comprehensive multi-tenant support with roles and permissions. You can use it in single-tenant mode (default) or enable multi-tenant functionality.

### Single-Tenant Mode (Default)
By default, the library operates in single-tenant mode where all users belong to a single organization.

### Multi-Tenant Mode
Enable multi-tenant support for SaaS applications where multiple organizations share the same system.

### Configuration

```go
cfg := auth.Config{
    DatabaseDSN: os.Getenv("DATABASE_URL"),
    JWTSecret:   os.Getenv("JWT_SECRET"),
    StorageConfig: auth.StorageConfig{
        // ... table and column configurations
        MultiTenant: auth.MultiTenantConfig{
            Enabled:         true,  // Enable multi-tenant mode
            DefaultTenantID: 1,     // Default tenant for new signups
            
            // Customize table names if needed
            TenantsTable:         "organizations",
            RolesTable:          "org_roles", 
            PermissionsTable:    "permissions",
            RolePermissionsTable: "role_permissions",
            UserTenantsTable:    "user_organizations",
            
            // Column mappings (use defaults or customize)
            TenantColumns: auth.DefaultMultiTenantConfig().TenantColumns,
            // ... other column mappings
        },
    },
    OAuthProviders: map[string]auth.OAuthProviderConfig{...},
}

authService, err := auth.NewAuthService(cfg)
if err != nil {
    log.Fatal(err)
}

// Set up default tenant and roles
if err := authService.SetupDefaultTenant(); err != nil {
    log.Fatal(err)
}
```

### Multi-Tenant Database Schema

The multi-tenant functionality adds these tables:

```sql
-- Tenants/Organizations
CREATE TABLE tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Roles (per tenant)
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES tenants(id),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

-- Global permissions
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Role-Permission mapping
CREATE TABLE role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE(role_id, permission_id)
);

-- User-Tenant mapping with roles
CREATE TABLE user_tenants (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, tenant_id)
);
```

### Usage Examples

#### Creating Tenants and Roles

```go
// Create a new tenant
tenant, err := authService.CreateTenant("Acme Corp", "acme", "acme.example.com")
if err != nil {
    log.Fatal(err)
}

// Create custom roles for the tenant
adminRole, err := authService.CreateRole(tenant.ID, "admin", "Administrator", false)
memberRole, err := authService.CreateRole(tenant.ID, "member", "Team Member", false)

// Create permissions
userReadPerm, err := authService.CreatePermission("users.read", "users", "read", "Read user data")
userWritePerm, err := authService.CreatePermission("users.write", "users", "write", "Create/update users")

// Assign permissions to roles
authService.AssignPermissionToRole(adminRole.ID, userReadPerm.ID)
authService.AssignPermissionToRole(adminRole.ID, userWritePerm.ID)
authService.AssignPermissionToRole(memberRole.ID, userReadPerm.ID)
```

#### Managing User-Tenant Relationships

```go
// Assign user to a tenant with a role
err := authService.AssignUserToTenant(userID, tenantID, roleID)

// Get all tenants for a user
userTenants, err := authService.GetUserTenants(userID)

// Check user permissions in a tenant
hasPermission, err := authService.UserHasPermission(userID, tenantID, "users.write")
if hasPermission {
    // User can perform the action
}

// Get all permissions for a user in a tenant
permissions, err := authService.GetUserPermissionsInTenant(userID, tenantID)
```

#### Multi-Tenant Sign Up

```go
// Sign up user to specific tenant
user, err := authService.SignUpWithTenant("user@example.com", "password", "John Doe", tenantID)

// Regular signup assigns to default tenant
user, err := authService.SignUp("user@example.com", "password", "John Doe")
```

### Permission System

The library uses a resource-action based permission system:

- **Resource**: The entity being accessed (e.g., "users", "projects", "billing")
- **Action**: The operation being performed (e.g., "read", "write", "delete")
- **Permission**: Combination of resource and action (e.g., "users.read", "projects.write")

#### Common Permission Patterns

```go
// CRUD permissions for a resource
"users.read"    // View users
"users.write"   // Create/update users  
"users.delete"  // Delete users

// Administrative permissions
"tenants.read"     // View tenant info
"tenants.write"    // Manage tenant settings
"roles.write"      // Manage roles
"permissions.read" // View available permissions
```

### Middleware and Authorization

```go
// Example middleware for HTTP handlers (pseudo-code)
func AuthRequired(permission string) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            // Extract user and tenant from token/headers
            userID := getUserFromToken(r)
            tenantID := getTenantFromHeader(r)
            
            // Check permission
            hasPermission, err := authService.UserHasPermission(userID, tenantID, permission)
            if err != nil || !hasPermission {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            
            next(w, r)
        }
    }
}

// Usage
http.HandleFunc("/users", AuthRequired("users.read")(listUsersHandler))
http.HandleFunc("/users/create", AuthRequired("users.write")(createUserHandler))
```

### Best Practices

1. **Default Tenant**: Always assign new users to a default tenant for backward compatibility
2. **System Roles**: Mark core roles as `is_system: true` to prevent accidental deletion
3. **Permission Naming**: Use consistent naming patterns like `resource.action`
4. **Tenant Isolation**: Always include tenant context in authorization checks
5. **Role Inheritance**: Consider implementing role hierarchies for complex permission models

## Error Handling

The API returns appropriate HTTP status codes:

- `200` - Success
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (invalid credentials/token)
- `409` - Conflict (user already exists)
- `500` - Internal Server Error

## Security Notes

- 🔒 Passwords are hashed using bcrypt
- 🔑 JWT tokens should be properly validated in production
- 🌐 Use HTTPS in production environments
- 🔄 Rotate JWT secrets regularly
- ⚠️ The current token implementation is simplified - replace with proper JWT in production

## Dependencies

```go
require (
    golang.org/x/crypto v0.17.0
    golang.org/x/oauth2 v0.15.0
    gorm.io/driver/postgres v1.5.4
    gorm.io/gorm v1.25.5
)
```

## Running the Server

```bash
# Set environment variables
export DATABASE_URL="postgresql://user:password@localhost:5432/auth_db"
export JWT_SECRET="your-super-secret-key"
export GOOGLE_CLIENT_ID="your-id"
export GOOGLE_CLIENT_SECRET="your-secret"
export GITHUB_CLIENT_ID="your-id" 
export GITHUB_CLIENT_SECRET="your-secret"
export DISCORD_CLIENT_ID="your-id"
export DISCORD_CLIENT_SECRET="your-secret"

# Run the server
go run main.go
```

## Production Recommendations

1. **Use proper JWT implementation** with expiration and refresh tokens
2. **Add rate limiting** to prevent abuse
3. **Implement proper logging** for security auditing
4. **Use environment-specific configurations**
5. **Add database connection pooling**
6. **Implement proper error handling and monitoring**
7. **Add CORS support** for web applications
8. **Use HTTPS** in production environments

This library provides a solid foundation for authentication that can be extended based on your specific requirements!# wispy-auth
