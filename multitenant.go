package auth

import (
	"time"
)

// RolePermission links roles to permissions
type RolePermission struct {
	ID           uint      `json:"id"`
	RoleID       uint      `json:"role_id"`
	PermissionID uint      `json:"permission_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
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

