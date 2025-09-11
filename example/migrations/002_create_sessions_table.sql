-- Create sessions table with enhanced security tracking
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    
    -- Device & Location Tracking
    device_fingerprint VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    location VARCHAR(255),
    
    -- Security Features
    is_active BOOLEAN DEFAULT true,
    last_activity TIMESTAMP DEFAULT NOW(),
    requires_two_factor BOOLEAN DEFAULT false,
    two_factor_verified BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_device_fingerprint ON sessions(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_sessions_ip_address ON sessions(ip_address);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- Add constraint for session cleanup
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;