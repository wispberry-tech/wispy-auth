-- Create security_events table for audit logging
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    tenant_id INTEGER, -- For multi-tenant setups (references tenants.id if multi-tenant is enabled)
    event_type VARCHAR(50) NOT NULL, -- login_success, login_failed, password_reset, etc.
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    metadata JSONB, -- Additional context data
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for performance and querying
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_id ON security_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_address ON security_events(ip_address);

-- Create partial indexes for common queries
CREATE INDEX IF NOT EXISTS idx_security_events_failed_logins 
    ON security_events(user_id, created_at) 
    WHERE event_type = 'login_failed';

CREATE INDEX IF NOT EXISTS idx_security_events_successful_logins 
    ON security_events(user_id, created_at) 
    WHERE event_type = 'login_success';

-- Add constraint for event_type values
ALTER TABLE security_events ADD CONSTRAINT security_events_event_type_check 
    CHECK (event_type IN (
        'login_success',
        'login_failed', 
        'password_reset',
        'password_changed',
        'email_verified',
        'account_locked',
        'session_created',
        'session_terminated',
        'two_factor_enabled',
        'two_factor_disabled'
    ));

-- Function to clean old security events (optional - keep last 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_security_events()
RETURNS void AS $$
BEGIN
    DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;