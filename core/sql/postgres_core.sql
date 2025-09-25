-- Wispy Auth Core PostgreSQL Schema
-- Simplified database schema for core authentication only
-- Removed multi-tenant, RBAC, referral, and email service functionality

-- Users table - Core user identity and basic authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
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

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User Security table - Detailed security tracking and sensitive data
CREATE TABLE IF NOT EXISTS user_security (
    user_id INTEGER PRIMARY KEY,

    -- Login Security
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    last_failed_login_at TIMESTAMP WITH TIME ZONE,
    last_failed_login_ip INET,

    -- Password Security
    password_changed_at TIMESTAMP WITH TIME ZONE,
    force_password_change BOOLEAN DEFAULT FALSE,

    -- 2FA Settings
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    two_factor_backup_codes TEXT,
    two_factor_verified_at TIMESTAMP WITH TIME ZONE,

    -- Session Security
    concurrent_sessions INTEGER DEFAULT 0,
    last_session_token VARCHAR(255),

    -- Device Tracking
    device_fingerprint VARCHAR(255),
    known_devices TEXT,

    -- Security Metadata
    security_version INTEGER DEFAULT 1,
    risk_score INTEGER DEFAULT 0,
    suspicious_activity_count INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sessions table - Session management with device tracking
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,

    -- Session Data
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Device Information
    user_agent TEXT,
    ip_address INET,
    device_fingerprint VARCHAR(255),

    -- Session Metadata
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Security Events table - Comprehensive security audit log
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,

    -- Event Details
    event_type VARCHAR(50) NOT NULL,
    description TEXT,

    -- Request Context
    ip_address INET,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),

    -- Event Metadata
    severity VARCHAR(20) DEFAULT 'info',
    success BOOLEAN DEFAULT TRUE,
    metadata JSONB,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- OAuth States table - OAuth CSRF protection
CREATE TABLE IF NOT EXISTS oauth_states (
    id SERIAL PRIMARY KEY,
    state VARCHAR(255) UNIQUE NOT NULL,
    csrf VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    redirect_url TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);

CREATE INDEX IF NOT EXISTS idx_oauth_states_state ON oauth_states(state);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);