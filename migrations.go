package auth

import (
	"fmt"
	"log/slog"
	"time"
)

// Migration represents a database migration
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// getMigrations returns all available migrations
func getMigrations() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "Create users table",
			SQL: `
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    password_hash VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50) DEFAULT 'email',
    provider_id VARCHAR(255),
    
    -- Email Security
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    verification_token VARCHAR(255),
    
    -- Password Security
    password_reset_token VARCHAR(255),
    password_reset_expires_at TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE,
    
    -- Login Security
    login_attempts INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP WITH TIME ZONE,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    
    -- Location & Device Tracking
    last_known_ip VARCHAR(45),
    last_login_location VARCHAR(255),
    
    -- Two-Factor Authentication
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    backup_codes TEXT,
    
    -- Account Security
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    suspended_at TIMESTAMP WITH TIME ZONE,
    suspend_reason TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider_id ON users(provider, provider_id);
CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token);
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token);
`,
		},
		{
			Version:     2,
			Description: "Create sessions table",
			SQL: `
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Device & Location Tracking
    device_fingerprint VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    location VARCHAR(255),
    
    -- Security Features
    is_active BOOLEAN DEFAULT TRUE,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    requires_two_factor BOOLEAN DEFAULT FALSE,
    two_factor_verified BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`,
		},
		{
			Version:     3,
			Description: "Create security events table",
			SQL: `
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    tenant_id INTEGER,
    event_type VARCHAR(100) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
`,
		},
		{
			Version:     4,
			Description: "Create OAuth states table",
			SQL: `
CREATE TABLE IF NOT EXISTS oauth_states (
    state_id VARCHAR(255) PRIMARY KEY,
    csrf_token VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create index for cleanup
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);
`,
		},
		{
			Version:     5,
			Description: "Create tenants table",
			SQL: `
CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
`,
		},
		{
			Version:     6,
			Description: "Create roles table",
			SQL: `
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(tenant_id, name)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id);
`,
		},
		{
			Version:     7,
			Description: "Create permissions table",
			SQL: `
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action);
`,
		},
		{
			Version:     8,
			Description: "Create role_permissions table",
			SQL: `
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (role_id, permission_id)
);
`,
		},
		{
			Version:     9,
			Description: "Create user_tenants table",
			SQL: `
CREATE TABLE IF NOT EXISTS user_tenants (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (user_id, tenant_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_tenants_user_id ON user_tenants(user_id);
CREATE INDEX IF NOT EXISTS idx_user_tenants_tenant_id ON user_tenants(tenant_id);
`,
		},
		{
			Version:     10,
			Description: "Create migrations tracking table",
			SQL: `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
`,
		},
	}
}

// RunMigrations executes all pending migrations
func (p *PostgresStorage) RunMigrations() error {
	slog.Info("Starting database migrations")
	
	migrations := getMigrations()
	
	// Create migrations tracking table first
	migrationTrackingSQL := `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`
	
	if _, err := p.db.Exec(migrationTrackingSQL); err != nil {
		slog.Error("Failed to create migrations tracking table", "error", err)
		return fmt.Errorf("failed to create migrations tracking table: %w", err)
	}
	
	// Get current migration version
	appliedMigrations, err := p.getAppliedMigrations()
	if err != nil {
		slog.Error("Failed to get applied migrations", "error", err)
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}
	
	// Apply pending migrations
	for _, migration := range migrations {
		if _, applied := appliedMigrations[migration.Version]; applied {
			slog.Debug("Migration already applied", "version", migration.Version, "description", migration.Description)
			continue
		}
		
		slog.Info("Applying migration", "version", migration.Version, "description", migration.Description)
		
		// Begin transaction
		tx, err := p.db.Begin()
		if err != nil {
			slog.Error("Failed to begin migration transaction", "error", err, "version", migration.Version)
			return fmt.Errorf("failed to begin migration transaction for version %d: %w", migration.Version, err)
		}
		
		// Execute migration SQL
		if _, err := tx.Exec(migration.SQL); err != nil {
			tx.Rollback()
			slog.Error("Failed to execute migration", "error", err, "version", migration.Version, "description", migration.Description)
			return fmt.Errorf("failed to execute migration %d (%s): %w", migration.Version, migration.Description, err)
		}
		
		// Record migration as applied
		if _, err := tx.Exec("INSERT INTO schema_migrations (version, description) VALUES ($1, $2)", migration.Version, migration.Description); err != nil {
			tx.Rollback()
			slog.Error("Failed to record migration", "error", err, "version", migration.Version)
			return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
		}
		
		// Commit transaction
		if err := tx.Commit(); err != nil {
			slog.Error("Failed to commit migration", "error", err, "version", migration.Version)
			return fmt.Errorf("failed to commit migration %d: %w", migration.Version, err)
		}
		
		slog.Info("Migration applied successfully", "version", migration.Version, "description", migration.Description)
	}
	
	slog.Info("Database migrations completed successfully")
	return nil
}

// getAppliedMigrations returns a map of applied migration versions
func (p *PostgresStorage) getAppliedMigrations() (map[int]bool, error) {
	applied := make(map[int]bool)
	
	rows, err := p.db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		// If table doesn't exist, return empty map
		if err.Error() == `pq: relation "schema_migrations" does not exist` {
			return applied, nil
		}
		return nil, err
	}
	defer rows.Close()
	
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	
	return applied, rows.Err()
}

// GetMigrationStatus returns the current migration status
func (p *PostgresStorage) GetMigrationStatus() ([]MigrationStatus, error) {
	migrations := getMigrations()
	appliedMigrations, err := p.getAppliedMigrations()
	if err != nil {
		return nil, err
	}
	
	var status []MigrationStatus
	for _, migration := range migrations {
		applied := appliedMigrations[migration.Version]
		var appliedAt *time.Time
		
		if applied {
			// Get the applied timestamp
			var timestamp time.Time
			err := p.db.QueryRow("SELECT applied_at FROM schema_migrations WHERE version = $1", migration.Version).Scan(&timestamp)
			if err == nil {
				appliedAt = &timestamp
			}
		}
		
		status = append(status, MigrationStatus{
			Version:     migration.Version,
			Description: migration.Description,
			Applied:     applied,
			AppliedAt:   appliedAt,
		})
	}
	
	return status, nil
}

// MigrationStatus represents the status of a migration
type MigrationStatus struct {
	Version     int        `json:"version"`
	Description string     `json:"description"`
	Applied     bool       `json:"applied"`
	AppliedAt   *time.Time `json:"applied_at,omitempty"`
}