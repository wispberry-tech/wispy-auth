package auth

import (
	"fmt"
	"log/slog"
)

// SetupDefaultTenant creates a default tenant and basic roles if they don't exist
func (a *AuthService) SetupDefaultTenant() error {
	if !a.storageConfig.MultiTenant.Enabled {
		return nil // Skip if multi-tenant is disabled
	}

	// Check if default tenant exists
	_, err := a.storage.GetTenantByID(a.storageConfig.MultiTenant.DefaultTenantID)
	if err == nil {
		return nil // Default tenant already exists
	}

	// Create default tenant
	tenant := &Tenant{
		Name:     "Default",
		Slug:     "default",
		Domain:   "",
		IsActive: true,
		Settings: "{}",
	}
	
	if err := a.storage.CreateTenant(tenant); err != nil {
		slog.Error("Failed to create default tenant", "error", err, "tenant_name", tenant.Name)
		return fmt.Errorf("failed to create default tenant: %w", err)
	}
	
	// Update the tenant ID to match the expected default ID
	if tenant.ID != a.storageConfig.MultiTenant.DefaultTenantID {
		// This is a simplification; in practice, you might want to handle this differently
		slog.Warn("Default tenant created with different ID than expected",
			"created_id", tenant.ID, "expected_id", a.storageConfig.MultiTenant.DefaultTenantID)
	}

	// Create default roles
	if err := a.createDefaultRoles(tenant.ID); err != nil {
		slog.Error("Failed to create default roles", "error", err, "tenant_id", tenant.ID)
		return fmt.Errorf("failed to create default roles: %w", err)
	}

	// Create default permissions
	if err := a.createDefaultPermissions(); err != nil {
		slog.Error("Failed to create default permissions", "error", err)
		return fmt.Errorf("failed to create default permissions: %w", err)
	}

	return nil
}

// createDefaultRoles creates standard roles for a tenant
func (a *AuthService) createDefaultRoles(tenantID uint) error {
	defaultRoles := []Role{
		{
			TenantID:    tenantID,
			Name:        "admin",
			Description: "Administrator with full access",
			IsSystem:    true,
		},
		{
			TenantID:    tenantID,
			Name:        "user",
			Description: "Standard user with basic access",
			IsSystem:    true,
		},
		{
			TenantID:    tenantID,
			Name:        "readonly",
			Description: "Read-only access",
			IsSystem:    true,
		},
	}

	for _, role := range defaultRoles {
		if err := a.storage.CreateRole(&role); err != nil {
			slog.Error("Failed to create role", "error", err, "role_name", role.Name, "tenant_id", tenantID)
			return fmt.Errorf("failed to create role %s: %w", role.Name, err)
		}
	}

	return nil
}

// createDefaultPermissions creates standard permissions
func (a *AuthService) createDefaultPermissions() error {
	defaultPermissions := []Permission{
		{Name: "users.read", Resource: "users", Action: "read", Description: "Read user information"},
		{Name: "users.write", Resource: "users", Action: "write", Description: "Create and update users"},
		{Name: "users.delete", Resource: "users", Action: "delete", Description: "Delete users"},
		{Name: "roles.read", Resource: "roles", Action: "read", Description: "Read role information"},
		{Name: "roles.write", Resource: "roles", Action: "write", Description: "Create and update roles"},
		{Name: "roles.delete", Resource: "roles", Action: "delete", Description: "Delete roles"},
		{Name: "permissions.read", Resource: "permissions", Action: "read", Description: "Read permission information"},
		{Name: "permissions.write", Resource: "permissions", Action: "write", Description: "Create and update permissions"},
		{Name: "tenants.read", Resource: "tenants", Action: "read", Description: "Read tenant information"},
		{Name: "tenants.write", Resource: "tenants", Action: "write", Description: "Create and update tenants"},
	}

	for _, permission := range defaultPermissions {
		if err := a.storage.CreatePermission(&permission); err != nil {
			slog.Error("Failed to create permission", "error", err, "permission_name", permission.Name)
			return fmt.Errorf("failed to create permission %s: %w", permission.Name, err)
		}
	}

	return nil
}

// AssignDefaultPermissions assigns default permissions to standard roles
func (a *AuthService) AssignDefaultPermissions(tenantID uint) error {
	// Get roles
	roles, err := a.storage.GetRolesByTenant(tenantID)
	if err != nil {
		slog.Error("Failed to get roles", "error", err, "tenant_id", tenantID)
		return fmt.Errorf("failed to get roles: %w", err)
	}

	// Get permissions
	permissions, err := a.storage.ListPermissions()
	if err != nil {
		slog.Error("Failed to get permissions", "error", err)
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	// Create permission maps for easy lookup
	roleMap := make(map[string]*Role)
	for _, role := range roles {
		roleMap[role.Name] = role
	}

	permissionMap := make(map[string]*Permission)
	for _, permission := range permissions {
		permissionMap[permission.Name] = permission
	}

	// Assign permissions to admin role (all permissions)
	if adminRole, exists := roleMap["admin"]; exists {
		for _, permission := range permissions {
			if err := a.storage.AssignPermissionToRole(adminRole.ID, permission.ID); err != nil {
				slog.Error("Failed to assign permission to admin", "error", err, "permission_name", permission.Name, "role_id", adminRole.ID)
				return fmt.Errorf("failed to assign permission %s to admin: %w", permission.Name, err)
			}
		}
	}

	// Assign permissions to user role (basic permissions)
	if userRole, exists := roleMap["user"]; exists {
		userPermissions := []string{"users.read", "roles.read", "permissions.read"}
		for _, permName := range userPermissions {
			if permission, exists := permissionMap[permName]; exists {
				if err := a.storage.AssignPermissionToRole(userRole.ID, permission.ID); err != nil {
					slog.Error("Failed to assign permission to user", "error", err, "permission_name", permName, "role_id", userRole.ID)
					return fmt.Errorf("failed to assign permission %s to user: %w", permName, err)
				}
			}
		}
	}

	// Assign permissions to readonly role (read-only permissions)
	if readonlyRole, exists := roleMap["readonly"]; exists {
		readonlyPermissions := []string{"users.read", "roles.read", "permissions.read", "tenants.read"}
		for _, permName := range readonlyPermissions {
			if permission, exists := permissionMap[permName]; exists {
				if err := a.storage.AssignPermissionToRole(readonlyRole.ID, permission.ID); err != nil {
					slog.Error("Failed to assign permission to readonly", "error", err, "permission_name", permName, "role_id", readonlyRole.ID)
					return fmt.Errorf("failed to assign permission %s to readonly: %w", permName, err)
				}
			}
		}
	}

	return nil
}

