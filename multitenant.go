package auth

import (
	"time"
)

// Tenant represents a tenant/organization in the system
type Tenant struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`        // URL-friendly identifier
	Domain      string    `json:"domain"`      // Custom domain (optional)
	IsActive    bool      `json:"is_active"`
	Settings    string    `json:"settings"`    // JSON settings specific to tenant
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Role represents a role within a tenant
type Role struct {
	ID          uint      `json:"id"`
	TenantID    uint      `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`   // System roles can't be deleted
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Permission represents a permission that can be assigned to roles
type Permission struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`         // e.g., "users.read", "posts.write"
	Resource    string    `json:"resource"`     // e.g., "users", "posts"
	Action      string    `json:"action"`       // e.g., "read", "write", "delete"
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RolePermission links roles to permissions
type RolePermission struct {
	ID           uint      `json:"id"`
	RoleID       uint      `json:"role_id"`
	PermissionID uint      `json:"permission_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserTenant links users to tenants with roles
type UserTenant struct {
	ID       uint `json:"id"`
	UserID   uint `json:"user_id"`
	TenantID uint `json:"tenant_id"`
	RoleID   uint `json:"role_id"`
	IsActive bool `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	
	// Populated by joins
	Tenant *Tenant `json:"tenant,omitempty"`
	Role   *Role   `json:"role,omitempty"`
}

// UserPermissionCheck represents a user's permission in a specific tenant context
type UserPermissionCheck struct {
	UserID       uint   `json:"user_id"`
	TenantID     uint   `json:"tenant_id"`
	Permission   string `json:"permission"`
	HasPermission bool  `json:"has_permission"`
}

// TenantColumnMapping maps logical tenant fields to actual database column names
type TenantColumnMapping struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Domain    string `json:"domain"`
	IsActive  string `json:"is_active"`
	Settings  string `json:"settings"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// RoleColumnMapping maps logical role fields to actual database column names
type RoleColumnMapping struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsSystem    string `json:"is_system"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// PermissionColumnMapping maps logical permission fields to actual database column names
type PermissionColumnMapping struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// RolePermissionColumnMapping maps logical role_permission fields to actual database column names
type RolePermissionColumnMapping struct {
	ID           string `json:"id"`
	RoleID       string `json:"role_id"`
	PermissionID string `json:"permission_id"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// UserTenantColumnMapping maps logical user_tenant fields to actual database column names
type UserTenantColumnMapping struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	TenantID  string `json:"tenant_id"`
	RoleID    string `json:"role_id"`
	IsActive  string `json:"is_active"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// MultiTenantConfig holds configuration for multi-tenant functionality
type MultiTenantConfig struct {
	Enabled         bool   `json:"enabled"`
	DefaultTenantID uint   `json:"default_tenant_id"`
	
	// Table names
	TenantsTable         string `json:"tenants_table"`
	RolesTable          string `json:"roles_table"`
	PermissionsTable    string `json:"permissions_table"`
	RolePermissionsTable string `json:"role_permissions_table"`
	UserTenantsTable    string `json:"user_tenants_table"`
	
	// Column mappings
	TenantColumns         TenantColumnMapping         `json:"tenant_columns"`
	RoleColumns          RoleColumnMapping          `json:"role_columns"`
	PermissionColumns    PermissionColumnMapping    `json:"permission_columns"`
	RolePermissionColumns RolePermissionColumnMapping `json:"role_permission_columns"`
	UserTenantColumns    UserTenantColumnMapping    `json:"user_tenant_columns"`
}

// DefaultMultiTenantConfig returns a default multi-tenant configuration
func DefaultMultiTenantConfig() MultiTenantConfig {
	return MultiTenantConfig{
		Enabled:         false, // Disabled by default for backward compatibility
		DefaultTenantID: 1,
		
		TenantsTable:         "tenants",
		RolesTable:          "roles",
		PermissionsTable:    "permissions",
		RolePermissionsTable: "role_permissions",
		UserTenantsTable:    "user_tenants",
		
		TenantColumns: TenantColumnMapping{
			ID:        "id",
			Name:      "name",
			Slug:      "slug",
			Domain:    "domain",
			IsActive:  "is_active",
			Settings:  "settings",
			CreatedAt: "created_at",
			UpdatedAt: "updated_at",
		},
		RoleColumns: RoleColumnMapping{
			ID:          "id",
			TenantID:    "tenant_id",
			Name:        "name",
			Description: "description",
			IsSystem:    "is_system",
			CreatedAt:   "created_at",
			UpdatedAt:   "updated_at",
		},
		PermissionColumns: PermissionColumnMapping{
			ID:          "id",
			Name:        "name",
			Resource:    "resource",
			Action:      "action",
			Description: "description",
			CreatedAt:   "created_at",
			UpdatedAt:   "updated_at",
		},
		RolePermissionColumns: RolePermissionColumnMapping{
			ID:           "id",
			RoleID:       "role_id",
			PermissionID: "permission_id",
			CreatedAt:    "created_at",
			UpdatedAt:    "updated_at",
		},
		UserTenantColumns: UserTenantColumnMapping{
			ID:        "id",
			UserID:    "user_id",
			TenantID:  "tenant_id",
			RoleID:    "role_id",
			IsActive:  "is_active",
			CreatedAt: "created_at",
			UpdatedAt: "updated_at",
		},
	}
}