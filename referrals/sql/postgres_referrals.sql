-- Referrals Extension PostgreSQL Schema
-- Extends the core authentication schema with referral functionality
-- This should be run after the core schema is created

-- Referral Codes table - Stores generated referral codes
CREATE TABLE IF NOT EXISTS referral_codes (
    id SERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    generated_by INTEGER NOT NULL,
    max_uses INTEGER DEFAULT 0,  -- 0 means unlimited
    current_uses INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE CASCADE
);

-- Referral Relationships table - Tracks who referred whom
CREATE TABLE IF NOT EXISTS referral_relationships (
    id SERIAL PRIMARY KEY,
    referrer_user_id INTEGER NOT NULL,
    referred_user_id INTEGER NOT NULL,
    referral_code_id INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Prevent duplicate referral relationships
    UNIQUE(referred_user_id),

    FOREIGN KEY (referrer_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (referred_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (referral_code_id) REFERENCES referral_codes(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_referral_codes_code ON referral_codes(code);
CREATE INDEX IF NOT EXISTS idx_referral_codes_generated_by ON referral_codes(generated_by);
CREATE INDEX IF NOT EXISTS idx_referral_codes_active ON referral_codes(is_active);
CREATE INDEX IF NOT EXISTS idx_referral_codes_expires_at ON referral_codes(expires_at);

CREATE INDEX IF NOT EXISTS idx_referral_relationships_referrer ON referral_relationships(referrer_user_id);
CREATE INDEX IF NOT EXISTS idx_referral_relationships_referred ON referral_relationships(referred_user_id);
CREATE INDEX IF NOT EXISTS idx_referral_relationships_code ON referral_relationships(referral_code_id);

-- View for referral statistics (computed dynamically)
CREATE OR REPLACE VIEW referral_stats AS
SELECT
    u.id as user_id,
    COALESCE(total_referred.count, 0) as total_referred,
    COALESCE(active_codes.count, 0) as active_codes,
    COALESCE(total_uses.count, 0) as total_codes_used,
    COALESCE(total_referred.count, 0) as successful_signups
FROM users u
LEFT JOIN (
    SELECT
        rr.referrer_user_id,
        COUNT(*) as count
    FROM referral_relationships rr
    GROUP BY rr.referrer_user_id
) total_referred ON u.id = total_referred.referrer_user_id
LEFT JOIN (
    SELECT
        rc.generated_by,
        COUNT(*) as count
    FROM referral_codes rc
    WHERE rc.is_active = TRUE
    AND (rc.expires_at IS NULL OR rc.expires_at > NOW())
    GROUP BY rc.generated_by
) active_codes ON u.id = active_codes.generated_by
LEFT JOIN (
    SELECT
        rc.generated_by,
        SUM(rc.current_uses) as count
    FROM referral_codes rc
    GROUP BY rc.generated_by
) total_uses ON u.id = total_uses.generated_by;