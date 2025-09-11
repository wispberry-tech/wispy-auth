package auth

import (
	"database/sql"
	"fmt"
	"time"
)

// Multi-tenant operations for PostgreSQL storage using pure SQL

// CreateTenant creates a new tenant
func (p *PostgresStorage) CreateTenant(tenant *Tenant) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5, $6, $7) 
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

	err := p.db.QueryRow(query,
		tenant.Name,
		tenant.Slug,
		tenant.Domain,
		tenant.IsActive,
		tenant.Settings,
		tenant.CreatedAt,
		tenant.UpdatedAt,
	).Scan(&tenant.ID)

	return err
}

// GetTenantByID retrieves a tenant by ID
func (p *PostgresStorage) GetTenantByID(id uint) (*Tenant, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = $1`,
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

	var tenant Tenant
	err := p.db.QueryRow(query, id).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.Domain,
		&tenant.IsActive,
		&tenant.Settings,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrTenantNotFound
		}
		return nil, err
	}

	return &tenant, nil
}

// GetTenantBySlug retrieves a tenant by slug
func (p *PostgresStorage) GetTenantBySlug(slug string) (*Tenant, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = $1`,
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

	var tenant Tenant
	err := p.db.QueryRow(query, slug).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.Domain,
		&tenant.IsActive,
		&tenant.Settings,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrTenantNotFound
		}
		return nil, err
	}

	return &tenant, nil
}

// UpdateTenant updates an existing tenant
func (p *PostgresStorage) UpdateTenant(tenant *Tenant) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2, %s = $3, %s = $4, %s = $5, %s = $6
		WHERE %s = $7`,
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

	_, err := p.db.Exec(query,
		tenant.Name,
		tenant.Slug,
		tenant.Domain,
		tenant.IsActive,
		tenant.Settings,
		tenant.UpdatedAt,
		tenant.ID,
	)

	return err
}

// ListTenants retrieves all tenants
func (p *PostgresStorage) ListTenants() ([]*Tenant, error) {
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
		p.config.MultiTenant.TenantColumns.Name,
	)

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		var tenant Tenant
		err := rows.Scan(
			&tenant.ID,
			&tenant.Name,
			&tenant.Slug,
			&tenant.Domain,
			&tenant.IsActive,
			&tenant.Settings,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, &tenant)
	}

	return tenants, rows.Err()
}

// CreateRole creates a new role
func (p *PostgresStorage) CreateRole(role *Role) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5, $6) 
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

	err := p.db.QueryRow(query,
		role.TenantID,
		role.Name,
		role.Description,
		role.IsSystem,
		role.CreatedAt,
		role.UpdatedAt,
	).Scan(&role.ID)

	return err
}

// GetRoleByID retrieves a role by ID
func (p *PostgresStorage) GetRoleByID(id uint) (*Role, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1`,
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

	var role Role
	err := p.db.QueryRow(query, id).Scan(
		&role.ID,
		&role.TenantID,
		&role.Name,
		&role.Description,
		&role.IsSystem,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrRoleNotFound
		}
		return nil, err
	}

	return &role, nil
}

// GetRolesByTenant retrieves all roles for a tenant
func (p *PostgresStorage) GetRolesByTenant(tenantID uint) ([]*Role, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1
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

	rows, err := p.db.Query(query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		var role Role
		err := rows.Scan(
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}

	return roles, rows.Err()
}

// UpdateRole updates an existing role
func (p *PostgresStorage) UpdateRole(role *Role) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2, %s = $3, %s = $4, %s = $5
		WHERE %s = $6`,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RoleColumns.ID,
	)

	role.UpdatedAt = time.Now()

	_, err := p.db.Exec(query,
		role.TenantID,
		role.Name,
		role.Description,
		role.IsSystem,
		role.UpdatedAt,
		role.ID,
	)

	return err
}

// DeleteRole deletes a role
func (p *PostgresStorage) DeleteRole(id uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`, 
		p.config.MultiTenant.RolesTable, 
		p.config.MultiTenant.RoleColumns.ID)
		
	_, err := p.db.Exec(query, id)
	return err
}

// CreatePermission creates a new permission
func (p *PostgresStorage) CreatePermission(permission *Permission) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5, $6) 
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

	err := p.db.QueryRow(query,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.CreatedAt,
		permission.UpdatedAt,
	).Scan(&permission.ID)

	return err
}

// GetPermissionByID retrieves a permission by ID
func (p *PostgresStorage) GetPermissionByID(id uint) (*Permission, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1`,
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

	var permission Permission
	err := p.db.QueryRow(query, id).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrPermissionNotFound
		}
		return nil, err
	}

	return &permission, nil
}

// GetPermissionByName retrieves a permission by name
func (p *PostgresStorage) GetPermissionByName(name string) (*Permission, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1`,
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

	var permission Permission
	err := p.db.QueryRow(query, name).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrPermissionNotFound
		}
		return nil, err
	}

	return &permission, nil
}

// ListPermissions retrieves all permissions
func (p *PostgresStorage) ListPermissions() ([]*Permission, error) {
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

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		var permission Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	return permissions, rows.Err()
}

// UpdatePermission updates an existing permission
func (p *PostgresStorage) UpdatePermission(permission *Permission) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2, %s = $3, %s = $4, %s = $5
		WHERE %s = $6`,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionColumns.ID,
	)

	permission.UpdatedAt = time.Now()

	_, err := p.db.Exec(query,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.UpdatedAt,
		permission.ID,
	)

	return err
}

// DeletePermission deletes a permission
func (p *PostgresStorage) DeletePermission(id uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`, 
		p.config.MultiTenant.PermissionsTable, 
		p.config.MultiTenant.PermissionColumns.ID)
		
	_, err := p.db.Exec(query, id)
	return err
}

// AssignPermissionToRole assigns a permission to a role
func (p *PostgresStorage) AssignPermissionToRole(roleID, permissionID uint) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4)`,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.RolePermissionColumns.CreatedAt,
		p.config.MultiTenant.RolePermissionColumns.UpdatedAt,
	)

	now := time.Now()
	_, err := p.db.Exec(query, roleID, permissionID, now, now)
	return err
}

// RemovePermissionFromRole removes a permission from a role
func (p *PostgresStorage) RemovePermissionFromRole(roleID, permissionID uint) error {
	query := fmt.Sprintf(`
		DELETE FROM %s 
		WHERE %s = $1 AND %s = $2`,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
	)

	_, err := p.db.Exec(query, roleID, permissionID)
	return err
}

// GetRolePermissions retrieves all permissions for a role
func (p *PostgresStorage) GetRolePermissions(roleID uint) ([]*Permission, error) {
	query := fmt.Sprintf(`
		SELECT p.%s, p.%s, p.%s, p.%s, p.%s, p.%s, p.%s
		FROM %s p
		JOIN %s rp ON p.%s = rp.%s
		WHERE rp.%s = $1
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

	rows, err := p.db.Query(query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		var permission Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	return permissions, rows.Err()
}

// AssignUserToTenant assigns a user to a tenant with a role
func (p *PostgresStorage) AssignUserToTenant(userID, tenantID, roleID uint) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (%s, %s) 
		DO UPDATE SET %s = $3, %s = $5`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		// ON CONFLICT columns
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		// DO UPDATE SET
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
	)

	now := time.Now()
	_, err := p.db.Exec(query, userID, tenantID, roleID, now, now)
	return err
}

// RemoveUserFromTenant removes a user from a tenant
func (p *PostgresStorage) RemoveUserFromTenant(userID, tenantID uint) error {
	query := fmt.Sprintf(`
		DELETE FROM %s 
		WHERE %s = $1 AND %s = $2`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
	)

	_, err := p.db.Exec(query, userID, tenantID)
	return err
}

// GetUserTenants retrieves all tenants for a user
func (p *PostgresStorage) GetUserTenants(userID uint) ([]*UserTenant, error) {
	query := fmt.Sprintf(`
		SELECT ut.%s, ut.%s, ut.%s, ut.%s,
			   t.%s, t.%s, t.%s, t.%s, t.%s,
			   r.%s, r.%s, r.%s, r.%s, r.%s, r.%s, r.%s
		FROM %s ut
		JOIN %s t ON ut.%s = t.%s
		JOIN %s r ON ut.%s = r.%s
		WHERE ut.%s = $1
		ORDER BY t.%s`,
		// UserTenant fields
		p.config.MultiTenant.UserTenantColumns.ID,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		// Tenant fields
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		// Role fields
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.RolesTable,
		// Joins
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		// Where
		p.config.MultiTenant.UserTenantColumns.UserID,
		// Order by
		p.config.MultiTenant.TenantColumns.Name,
	)

	rows, err := p.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userTenants []*UserTenant
	for rows.Next() {
		var userTenant UserTenant
		var tenant Tenant
		var role Role

		err := rows.Scan(
			// UserTenant fields
			&userTenant.UserID,
			&userTenant.TenantID,
			&userTenant.RoleID,
			&userTenant.CreatedAt,
			&userTenant.UpdatedAt,
			// Tenant fields
			&tenant.ID,
			&tenant.Name,
			&tenant.Slug,
			&tenant.Domain,
			&tenant.IsActive,
			&tenant.Settings,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
			// Role fields
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		userTenant.Tenant = &tenant
		userTenant.Role = &role
		userTenants = append(userTenants, &userTenant)
	}

	return userTenants, rows.Err()
}

// GetTenantUsers retrieves all users for a tenant
func (p *PostgresStorage) GetTenantUsers(tenantID uint) ([]*UserTenant, error) {
	query := fmt.Sprintf(`
		SELECT ut.%s, ut.%s, ut.%s, ut.%s, ut.%s,
			   r.%s, r.%s, r.%s, r.%s, r.%s, r.%s, r.%s
		FROM %s ut
		JOIN %s r ON ut.%s = r.%s
		WHERE ut.%s = $1
		ORDER BY ut.%s`,
		// UserTenant fields
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		// Role fields
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		// Join
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		// Where
		p.config.MultiTenant.UserTenantColumns.TenantID,
		// Order by
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
	)

	rows, err := p.db.Query(query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userTenants []*UserTenant
	for rows.Next() {
		var userTenant UserTenant
		var role Role

		err := rows.Scan(
			// UserTenant fields
			&userTenant.UserID,
			&userTenant.TenantID,
			&userTenant.RoleID,
			&userTenant.CreatedAt,
			&userTenant.UpdatedAt,
			// Role fields
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		userTenant.Role = &role
		userTenants = append(userTenants, &userTenant)
	}

	return userTenants, rows.Err()
}

// UpdateUserTenantRole updates a user's role in a tenant
func (p *PostgresStorage) UpdateUserTenantRole(userID, tenantID, roleID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2
		WHERE %s = $3 AND %s = $4`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
	)

	_, err := p.db.Exec(query, roleID, time.Now(), userID, tenantID)
	return err
}

// UserHasPermission checks if a user has a specific permission in a tenant
func (p *PostgresStorage) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM %s ut
		JOIN %s r ON ut.%s = r.%s
		JOIN %s rp ON r.%s = rp.%s
		JOIN %s p ON rp.%s = p.%s
		WHERE ut.%s = $1 AND ut.%s = $2 AND p.%s = $3`,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.PermissionsTable,
		// Joins
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.PermissionColumns.ID,
		// Where conditions
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	var count int
	err := p.db.QueryRow(query, userID, tenantID, permission).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetUserPermissionsInTenant gets all permissions for a user in a specific tenant
func (p *PostgresStorage) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	query := fmt.Sprintf(`
		SELECT DISTINCT p.%s, p.%s, p.%s, p.%s, p.%s, p.%s, p.%s
		FROM %s ut
		JOIN %s r ON ut.%s = r.%s
		JOIN %s rp ON r.%s = rp.%s
		JOIN %s p ON rp.%s = p.%s
		WHERE ut.%s = $1 AND ut.%s = $2
		ORDER BY p.%s`,
		// Permission fields
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.PermissionsTable,
		// Joins
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.PermissionColumns.ID,
		// Where conditions
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		// Order by
		p.config.MultiTenant.PermissionColumns.Name,
	)

	rows, err := p.db.Query(query, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		var permission Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	return permissions, rows.Err()
}