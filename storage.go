package auth

import (
	"errors"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrInvalidSession  = errors.New("invalid session")
)


// Session represents a user session
type Session struct {
	ID        string    `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StorageInterface defines the contract for data storage operations
type StorageInterface interface {
	// User operations
	CreateUser(user *User) error
	GetUserByEmail(email, provider string) (*User, error)
	GetUserByEmailAnyProvider(email string) (*User, error)
	GetUserByProviderID(provider, providerID string) (*User, error)
	GetUserByID(id uint) (*User, error)
	UpdateUser(user *User) error
	
	// Session operations
	CreateSession(session *Session) error
	GetSession(token string) (*Session, error)
	DeleteSession(token string) error
	DeleteUserSessions(userID uint) error
	CleanupExpiredSessions() error
	
	// Multi-tenant operations
	CreateTenant(tenant *Tenant) error
	GetTenantByID(id uint) (*Tenant, error)
	GetTenantBySlug(slug string) (*Tenant, error)
	UpdateTenant(tenant *Tenant) error
	ListTenants() ([]*Tenant, error)
	
	// Role operations
	CreateRole(role *Role) error
	GetRoleByID(id uint) (*Role, error)
	GetRolesByTenant(tenantID uint) ([]*Role, error)
	UpdateRole(role *Role) error
	DeleteRole(id uint) error
	
	// Permission operations
	CreatePermission(permission *Permission) error
	GetPermissionByID(id uint) (*Permission, error)
	GetPermissionByName(name string) (*Permission, error)
	ListPermissions() ([]*Permission, error)
	UpdatePermission(permission *Permission) error
	DeletePermission(id uint) error
	
	// Role-Permission operations
	AssignPermissionToRole(roleID, permissionID uint) error
	RemovePermissionFromRole(roleID, permissionID uint) error
	GetRolePermissions(roleID uint) ([]*Permission, error)
	
	// User-Tenant operations
	AssignUserToTenant(userID, tenantID, roleID uint) error
	RemoveUserFromTenant(userID, tenantID uint) error
	GetUserTenants(userID uint) ([]*UserTenant, error)
	GetTenantUsers(tenantID uint) ([]*UserTenant, error)
	UpdateUserTenantRole(userID, tenantID, roleID uint) error
	
	// Permission checking
	UserHasPermission(userID, tenantID uint, permission string) (bool, error)
	GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error)
	
	// Utility operations
	Close() error
}

// StorageConfig holds configuration for table names and database settings
type StorageConfig struct {
	// Table names
	UsersTable    string `json:"users_table"`
	SessionsTable string `json:"sessions_table"`
	
	// Required user columns mapping
	UserColumns UserColumnMapping `json:"user_columns"`
	
	// Required session columns mapping  
	SessionColumns SessionColumnMapping `json:"session_columns"`
	
	// Multi-tenant configuration
	MultiTenant MultiTenantConfig `json:"multi_tenant"`
}

// UserColumnMapping maps logical user fields to actual database column names
type UserColumnMapping struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Name         string `json:"name"`
	AvatarURL    string `json:"avatar_url"`
	Provider     string `json:"provider"`
	ProviderID   string `json:"provider_id"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// SessionColumnMapping maps logical session fields to actual database column names
type SessionColumnMapping struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// DefaultStorageConfig returns a default configuration with standard table and column names
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		UsersTable:    "users",
		SessionsTable: "sessions",
		UserColumns: UserColumnMapping{
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
		SessionColumns: SessionColumnMapping{
			ID:        "id",
			UserID:    "user_id",
			Token:     "token",
			ExpiresAt: "expires_at",
			CreatedAt: "created_at",
			UpdatedAt: "updated_at",
		},
		MultiTenant: DefaultMultiTenantConfig(),
	}
}