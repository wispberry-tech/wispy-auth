-- Wispy Auth SQLite Schema
-- Complete database schema for the wispy-auth authentication system
-- This file contains all tables needed for a complete authentication system with multi-tenancy, RBAC, and security features

-- Users table - Core user identity and basic authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL DEFAULT (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6)))),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    password_hash VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50) DEFAULT 'email',
    provider_id VARCHAR(255),

    -- Core Security (frequently accessed)
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User Security table - Detailed security tracking and sensitive data
CREATE TABLE IF NOT EXISTS user_security (
    user_id INTEGER PRIMARY KEY,

    -- Email Security Details
    email_verified_at DATETIME,
    verification_token VARCHAR(255),

    -- Password Security
    password_reset_token VARCHAR(255),
    password_reset_expires_at DATETIME,
    password_changed_at DATETIME,

    -- Login Security Tracking
    login_attempts INTEGER DEFAULT 0,
    last_failed_login_at DATETIME,
    locked_until DATETIME,
    last_login_at DATETIME,

    -- Location & Device Tracking
    last_known_ip VARCHAR(45),
    last_login_location VARCHAR(255),

    -- Two-Factor Authentication
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    backup_codes TEXT,

    -- Account Management
    suspended_at DATETIME,
    suspend_reason TEXT,

    -- Referral System
    referred_by_code VARCHAR(50),

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for users table
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider_id ON users(provider, provider_id);

-- Create indexes for user_security table
CREATE INDEX IF NOT EXISTS idx_user_security_verification_token ON user_security(verification_token);
CREATE INDEX IF NOT EXISTS idx_user_security_password_reset_token ON user_security(password_reset_token);
CREATE INDEX IF NOT EXISTS idx_user_security_referred_by_code ON user_security(referred_by_code);
CREATE INDEX IF NOT EXISTS idx_user_security_last_login_at ON user_security(last_login_at);
CREATE INDEX IF NOT EXISTS idx_user_security_locked_until ON user_security(locked_until);

-- Sessions table - User session management with device tracking
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR(512) UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    csrf_token VARCHAR(255),

    -- Device & Location Tracking
    device_fingerprint VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    location VARCHAR(255),

    -- Security Features
    is_active BOOLEAN DEFAULT TRUE,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    requires_two_factor BOOLEAN DEFAULT FALSE,
    two_factor_verified BOOLEAN DEFAULT FALSE,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for sessions table
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Security Events table - Comprehensive audit logging
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    tenant_id INTEGER,
    event_type VARCHAR(100) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    metadata TEXT, -- JSON stored as TEXT in SQLite
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for security_events table
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);

-- OAuth States table - OAuth flow state management
CREATE TABLE IF NOT EXISTS oauth_states (
    state VARCHAR(255) PRIMARY KEY,
    csrf_token VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL
);

-- Create index for oauth_states table
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);

-- Tenants table - Multi-tenant organization management
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL DEFAULT (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6)))),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    settings TEXT DEFAULT '{}', -- JSON stored as TEXT in SQLite
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for tenants table
CREATE INDEX IF NOT EXISTS idx_tenants_uuid ON tenants(uuid);
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);

-- Roles table - Role-based access control within tenants
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(tenant_id, name),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create indexes for roles table
CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id);

-- Permissions table - System-wide permissions for granular access control
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for permissions table
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action);

-- Role Permissions table - Many-to-many relationship between roles and permissions
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- User Tenants table - Many-to-many relationship between users and tenants with roles
CREATE TABLE IF NOT EXISTS user_tenants (
    user_id INTEGER NOT NULL,
    tenant_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, tenant_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Create indexes for user_tenants table
CREATE INDEX IF NOT EXISTS idx_user_tenants_user_id ON user_tenants(user_id);
CREATE INDEX IF NOT EXISTS idx_user_tenants_tenant_id ON user_tenants(tenant_id);

-- Referral Codes table - Store referral codes with role-based generation tracking
CREATE TABLE IF NOT EXISTS referral_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(50) UNIQUE NOT NULL,
    generated_by_user_id INTEGER NOT NULL,
    generated_by_role_id INTEGER NOT NULL,
    tenant_id INTEGER NOT NULL,
    max_uses INTEGER DEFAULT 1,
    current_uses INTEGER DEFAULT 0,
    expires_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (generated_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (generated_by_role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create indexes for referral_codes table
CREATE INDEX IF NOT EXISTS idx_referral_codes_code ON referral_codes(code);
CREATE INDEX IF NOT EXISTS idx_referral_codes_generated_by_user_id ON referral_codes(generated_by_user_id);
CREATE INDEX IF NOT EXISTS idx_referral_codes_tenant_id ON referral_codes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_referral_codes_is_active ON referral_codes(is_active);

-- User Referrals table - Track referral relationships with role context
CREATE TABLE IF NOT EXISTS user_referrals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_user_id INTEGER NOT NULL,
    referred_user_id INTEGER NOT NULL,
    referral_code_id INTEGER NOT NULL,
    referrer_role_id INTEGER NOT NULL,
    tenant_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(referred_user_id), -- Each user can only be referred once
    FOREIGN KEY (referrer_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (referred_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (referral_code_id) REFERENCES referral_codes(id) ON DELETE CASCADE,
    FOREIGN KEY (referrer_role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create indexes for user_referrals table
CREATE INDEX IF NOT EXISTS idx_user_referrals_referrer_user_id ON user_referrals(referrer_user_id);
CREATE INDEX IF NOT EXISTS idx_user_referrals_referred_user_id ON user_referrals(referred_user_id);
CREATE INDEX IF NOT EXISTS idx_user_referrals_tenant_id ON user_referrals(tenant_id);

-- Two Factor Codes table - For storing temporary 2FA verification codes
CREATE TABLE IF NOT EXISTS two_factor_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code VARCHAR(10) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    attempt_count INTEGER DEFAULT 0,
    locked_until DATETIME,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for two_factor_codes table
CREATE INDEX IF NOT EXISTS idx_two_factor_codes_user_id ON two_factor_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_two_factor_codes_expires_at ON two_factor_codes(expires_at);
