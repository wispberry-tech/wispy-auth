# Multi-Tenant RBAC Example

This example demonstrates a complete multi-tenant application with role-based access control, permissions, and tenant isolation.

## Features Demonstrated

- ✅ Multiple tenant organizations
- ✅ Role-based access control (RBAC)
- ✅ Granular permission system
- ✅ Tenant-scoped user roles
- ✅ Permission-based route protection
- ✅ Tenant context switching
- ✅ Complete data isolation between tenants

## Running the Example

```bash
cd examples/multitenant
go mod tidy
go run main.go
```

## Demo Tenants & Roles

### Acme Corporation (`acme`)
- **admin**: Full access to documents and user management
- **manager**: Read/write documents
- **user**: Read-only document access

### Tech Startup Inc (`techstartup`)
- **owner**: Full access including deployment
- **developer**: Document access + deployment permissions

## Testing Multi-Tenant Flow

### 1. View Available Tenants
```bash
curl http://localhost:8080/tenants
```

### 2. Sign Up Users for Different Tenants

**Acme Corp User:**
```bash
curl -X POST http://localhost:8080/signup/acme \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@acme.com","password":"Password123"}'
```

**Tech Startup User:**
```bash
curl -X POST http://localhost:8080/signup/techstartup \
  -H 'Content-Type: application/json' \
  -d '{"email":"bob@techstartup.io","password":"Password123"}'
```

### 3. Sign In and Get Tokens
```bash
curl -X POST http://localhost:8080/signin \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@acme.com","password":"Password123"}'
```

### 4. Access Tenant-Scoped Resources

**View Profile (Shows Current Tenant):**
```bash
curl -X GET http://localhost:8080/profile \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

**Read Documents (Requires read permission):**
```bash
curl -X GET http://localhost:8080/documents \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

**Create Document (Requires write permission):**
```bash
curl -X POST http://localhost:8080/documents \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"title":"New Document","content":"Document content"}'
```

### 5. Admin-Only Features

**User Management (Admin permission required):**
```bash
curl -X GET http://localhost:8080/admin/users \
  -H 'Authorization: Bearer ADMIN_TOKEN'
```

**Assign Role (Admin permission required):**
```bash
curl -X POST http://localhost:8080/admin/assign-role \
  -H 'Authorization: Bearer ADMIN_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"user_id":2,"role_id":1}'
```

### 6. Tech Startup Specific Features

**Deploy Code (Developer/Owner permission):**
```bash
curl -X POST http://localhost:8080/deploy \
  -H 'Authorization: Bearer TECHSTARTUP_TOKEN'
```

### 7. Tenant Switching

**Switch to Different Tenant:**
```bash
curl -X POST http://localhost:8080/switch-tenant/2 \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

## Permission Matrix

| Role | Read Docs | Write Docs | Manage Users | Deploy |
|------|-----------|------------|--------------|--------|
| **Acme Corp** | | | | |
| admin | ✅ | ✅ | ✅ | ❌ |
| manager | ✅ | ✅ | ❌ | ❌ |
| user | ✅ | ❌ | ❌ | ❌ |
| **Tech Startup** | | | | |
| owner | ✅ | ✅ | ✅ | ✅ |
| developer | ✅ | ❌ | ❌ | ✅ |

## Key Architecture Patterns

### 1. Tenant-Scoped Signup
```go
r.Post("/signup/{tenant}", func(w http.ResponseWriter, r *http.Request) {
    tenantSlug := chi.URLParam(r, "tenant")
    tenantID := getTenantIDBySlug(tenantSlug)
    result := authService.SignUpWithTenantHandler(r, tenantID)
    // ...
})
```

### 2. Permission-Based Route Protection
```go
r.Group(func(r chi.Router) {
    r.Use(authService.RequirePermission("documents", "write"))
    r.Post("/documents", createDocumentHandler)
})
```

### 3. Context-Based Access
```go
func handler(w http.ResponseWriter, r *http.Request) {
    user := auth.MustGetUserFromContext(r.Context())
    tenant := auth.MustGetTenantFromContext(r.Context())
    // User and tenant guaranteed to be available and valid
}
```

## Security Features

- **Data Isolation**: Each tenant's data is completely isolated
- **Role Scoping**: Roles are scoped to specific tenants
- **Permission Validation**: All permissions checked within tenant context
- **Secure Switching**: Tenant switching validates user membership
- **Audit Trail**: All tenant operations logged with security events

## Use Cases Demonstrated

1. **Enterprise SaaS**: Multiple customer organizations
2. **Team Collaboration**: Different teams with different permissions
3. **Hierarchical Access**: Admin → Manager → User hierarchy
4. **Cross-Functional Roles**: Developers with deployment permissions
5. **Tenant Switching**: Users accessing multiple organizations