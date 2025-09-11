package auth

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Multi-tenant operations for PostgreSQL storage

// CreateTenant creates a new tenant
func (p *PostgresStorage) CreateTenant(tenant *Tenant) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s, %s) 
		VALUES (?, ?, ?, ?, ?, ?, ?) 
		RETURNING %s`,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantColumns.ID,
	)

	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now

	return p.db.Raw(query,
		tenant.Name,
		tenant.Slug,
		tenant.Domain,
		tenant.IsActive,
		tenant.Settings,
		tenant.CreatedAt,
		tenant.UpdatedAt,
	).Scan(&tenant.ID).Error
}

// GetTenantByID retrieves a tenant by ID
func (p *PostgresStorage) GetTenantByID(id uint) (*Tenant, error) {
	var tenant Tenant
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?`,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.ID,
	)

	err := p.db.Raw(query, id).Scan(&tenant).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound // Reusing existing error for consistency
		}
		return nil, err
	}
	return &tenant, nil
}

// GetTenantBySlug retrieves a tenant by slug
func (p *PostgresStorage) GetTenantBySlug(slug string) (*Tenant, error) {
	var tenant Tenant
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?`,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.Slug,
	)

	err := p.db.Raw(query, slug).Scan(&tenant).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &tenant, nil
}

// UpdateTenant updates an existing tenant
func (p *PostgresStorage) UpdateTenant(tenant *Tenant) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = ?, %s = ?, %s = ?, %s = ?, %s = ?, %s = ?
		WHERE %s = ?`,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantColumns.ID,
	)

	tenant.UpdatedAt = time.Now()

	return p.db.Exec(query,
		tenant.Name,
		tenant.Slug,
		tenant.Domain,
		tenant.IsActive,
		tenant.Settings,
		tenant.UpdatedAt,
		tenant.ID,
	).Error
}

// ListTenants retrieves all tenants
func (p *PostgresStorage) ListTenants() ([]*Tenant, error) {
	var tenants []*Tenant
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		ORDER BY %s`,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.CreatedAt,
	)

	return tenants, p.db.Raw(query).Scan(&tenants).Error
}

// CreateRole creates a new role
func (p *PostgresStorage) CreateRole(role *Role) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES (?, ?, ?, ?, ?, ?) 
		RETURNING %s`,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RoleColumns.ID,
	)

	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now

	return p.db.Raw(query,
		role.TenantID,
		role.Name,
		role.Description,
		role.IsSystem,
		role.CreatedAt,
		role.UpdatedAt,
	).Scan(&role.ID).Error
}

// GetRoleByID retrieves a role by ID
func (p *PostgresStorage) GetRoleByID(id uint) (*Role, error) {
	var role Role
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?`,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.ID,
	)

	err := p.db.Raw(query, id).Scan(&role).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &role, nil
}

// GetRolesByTenant retrieves all roles for a tenant
func (p *PostgresStorage) GetRolesByTenant(tenantID uint) ([]*Role, error) {
	var roles []*Role
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?
		ORDER BY %s`,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
	)

	return roles, p.db.Raw(query, tenantID).Scan(&roles).Error
}

// UpdateRole updates an existing role
func (p *PostgresStorage) UpdateRole(role *Role) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = ?, %s = ?, %s = ?, %s = ?, %s = ?
		WHERE %s = ?`,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RoleColumns.ID,
	)

	role.UpdatedAt = time.Now()

	return p.db.Exec(query,
		role.TenantID,
		role.Name,
		role.Description,
		role.IsSystem,
		role.UpdatedAt,
		role.ID,
	).Error
}

// DeleteRole deletes a role (only if not system role)
func (p *PostgresStorage) DeleteRole(id uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = ? AND %s = false`,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.IsSystem,
	)
	return p.db.Exec(query, id).Error
}

// CreatePermission creates a new permission
func (p *PostgresStorage) CreatePermission(permission *Permission) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES (?, ?, ?, ?, ?, ?) 
		RETURNING %s`,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionColumns.ID,
	)

	now := time.Now()
	permission.CreatedAt = now
	permission.UpdatedAt = now

	return p.db.Raw(query,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.CreatedAt,
		permission.UpdatedAt,
	).Scan(&permission.ID).Error
}

// GetPermissionByID retrieves a permission by ID
func (p *PostgresStorage) GetPermissionByID(id uint) (*Permission, error) {
	var permission Permission
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.ID,
	)

	err := p.db.Raw(query, id).Scan(&permission).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &permission, nil
}

// GetPermissionByName retrieves a permission by name
func (p *PostgresStorage) GetPermissionByName(name string) (*Permission, error) {
	var permission Permission
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	err := p.db.Raw(query, name).Scan(&permission).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &permission, nil
}

// ListPermissions retrieves all permissions
func (p *PostgresStorage) ListPermissions() ([]*Permission, error) {
	var permissions []*Permission
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		ORDER BY %s`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	return permissions, p.db.Raw(query).Scan(&permissions).Error
}

// UpdatePermission updates an existing permission
func (p *PostgresStorage) UpdatePermission(permission *Permission) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = ?, %s = ?, %s = ?, %s = ?, %s = ?
		WHERE %s = ?`,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionColumns.ID,
	)

	permission.UpdatedAt = time.Now()

	return p.db.Exec(query,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.UpdatedAt,
		permission.ID,
	).Error
}

// DeletePermission deletes a permission
func (p *PostgresStorage) DeletePermission(id uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.ID,
	)
	return p.db.Exec(query, id).Error
}

// AssignPermissionToRole assigns a permission to a role
func (p *PostgresStorage) AssignPermissionToRole(roleID, permissionID uint) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s) 
		VALUES (?, ?)
		ON CONFLICT DO NOTHING`,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
	)

	return p.db.Exec(query, roleID, permissionID).Error
}

// RemovePermissionFromRole removes a permission from a role
func (p *PostgresStorage) RemovePermissionFromRole(roleID, permissionID uint) error {
	query := fmt.Sprintf(`
		DELETE FROM %s 
		WHERE %s = ? AND %s = ?`,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
	)

	return p.db.Exec(query, roleID, permissionID).Error
}

// GetRolePermissions retrieves all permissions for a role
func (p *PostgresStorage) GetRolePermissions(roleID uint) ([]*Permission, error) {
	var permissions []*Permission
	query := fmt.Sprintf(`
		SELECT p.%s, p.%s, p.%s, p.%s, p.%s, p.%s, p.%s 
		FROM %s p
		INNER JOIN %s rp ON p.%s = rp.%s
		WHERE rp.%s = ?
		ORDER BY p.%s`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	return permissions, p.db.Raw(query, roleID).Scan(&permissions).Error
}

// AssignUserToTenant assigns a user to a tenant with a role
func (p *PostgresStorage) AssignUserToTenant(userID, tenantID, roleID uint) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (%s, %s) DO UPDATE SET %s = ?, %s = ?, %s = ?`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
	)

	now := time.Now()
	return p.db.Exec(query, userID, tenantID, roleID, true, now, now, roleID, true, now).Error
}

// RemoveUserFromTenant removes a user from a tenant
func (p *PostgresStorage) RemoveUserFromTenant(userID, tenantID uint) error {
	query := fmt.Sprintf(`
		DELETE FROM %s 
		WHERE %s = ? AND %s = ?`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
	)

	return p.db.Exec(query, userID, tenantID).Error
}

// GetUserTenants retrieves all tenants for a user
func (p *PostgresStorage) GetUserTenants(userID uint) ([]*UserTenant, error) {
	var userTenants []*UserTenant
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ? AND %s = true
		ORDER BY %s`,
		p.config.MultiTenant.UserTenantColumns.ID,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
	)

	return userTenants, p.db.Raw(query, userID).Scan(&userTenants).Error
}

// GetTenantUsers retrieves all users for a tenant
func (p *PostgresStorage) GetTenantUsers(tenantID uint) ([]*UserTenant, error) {
	var userTenants []*UserTenant
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ? AND %s = true
		ORDER BY %s`,
		p.config.MultiTenant.UserTenantColumns.ID,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
	)

	return userTenants, p.db.Raw(query, tenantID).Scan(&userTenants).Error
}

// UpdateUserTenantRole updates a user's role in a tenant
func (p *PostgresStorage) UpdateUserTenantRole(userID, tenantID, roleID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = ?, %s = ?
		WHERE %s = ? AND %s = ?`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
	)

	return p.db.Exec(query, roleID, time.Now(), userID, tenantID).Error
}

// UserHasPermission checks if a user has a specific permission in a tenant
func (p *PostgresStorage) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*) > 0
		FROM %s ut
		INNER JOIN %s r ON ut.%s = r.%s
		INNER JOIN %s rp ON r.%s = rp.%s
		INNER JOIN %s p ON rp.%s = p.%s
		WHERE ut.%s = ? AND ut.%s = ? AND ut.%s = true AND p.%s = ?`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	var hasPermission bool
	err := p.db.Raw(query, userID, tenantID, permission).Scan(&hasPermission).Error
	return hasPermission, err
}

// GetUserPermissionsInTenant retrieves all permissions for a user in a specific tenant
func (p *PostgresStorage) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	var permissions []*Permission
	query := fmt.Sprintf(`
		SELECT DISTINCT p.%s, p.%s, p.%s, p.%s, p.%s, p.%s, p.%s
		FROM %s ut
		INNER JOIN %s r ON ut.%s = r.%s
		INNER JOIN %s rp ON r.%s = rp.%s
		INNER JOIN %s p ON rp.%s = p.%s
		WHERE ut.%s = ? AND ut.%s = ? AND ut.%s = true
		ORDER BY p.%s`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.IsActive,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	return permissions, p.db.Raw(query, userID, tenantID).Scan(&permissions).Error
}