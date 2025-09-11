-- Multi-tenant support tables (optional - only run if multi-tenant is enabled)

-- Tenants/Organizations table
CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Roles table (per tenant)
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false, -- System roles cannot be deleted
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

-- Global permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL, -- e.g., 'users.read', 'projects.write'
    resource VARCHAR(100) NOT NULL,    -- e.g., 'users', 'projects'
    action VARCHAR(100) NOT NULL,      -- e.g., 'read', 'write', 'delete'
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Role-Permission mapping table
CREATE TABLE IF NOT EXISTS role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(role_id, permission_id)
);

-- User-Tenant mapping with roles
CREATE TABLE IF NOT EXISTS user_tenants (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, tenant_id)
);

-- Indexes for multi-tenant tables
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
CREATE INDEX IF NOT EXISTS idx_tenants_is_active ON tenants(is_active);

CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_is_system ON roles(is_system);

CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

CREATE INDEX IF NOT EXISTS idx_user_tenants_user_id ON user_tenants(user_id);
CREATE INDEX IF NOT EXISTS idx_user_tenants_tenant_id ON user_tenants(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_tenants_role_id ON user_tenants(role_id);
CREATE INDEX IF NOT EXISTS idx_user_tenants_is_active ON user_tenants(is_active);

-- Insert default tenant and roles (optional)
INSERT INTO tenants (id, name, slug, domain, is_active) 
VALUES (1, 'Default', 'default', '', true) 
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (tenant_id, name, description, is_system) 
VALUES 
    (1, 'admin', 'Administrator with full access', true),
    (1, 'member', 'Regular member with basic access', true)
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Insert common permissions
INSERT INTO permissions (name, resource, action, description) VALUES
    ('users.read', 'users', 'read', 'View user information'),
    ('users.write', 'users', 'write', 'Create and modify users'),
    ('users.delete', 'users', 'delete', 'Delete users'),
    ('tenants.read', 'tenants', 'read', 'View tenant information'),
    ('tenants.write', 'tenants', 'write', 'Modify tenant settings'),
    ('roles.read', 'roles', 'read', 'View roles and permissions'),
    ('roles.write', 'roles', 'write', 'Manage roles and permissions')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to default admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r 
CROSS JOIN permissions p
WHERE r.tenant_id = 1 AND r.name = 'admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign basic permissions to member role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r 
CROSS JOIN permissions p
WHERE r.tenant_id = 1 AND r.name = 'member' AND p.name IN ('users.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;