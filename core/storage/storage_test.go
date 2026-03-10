package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/ncruces/go-sqlite3"
)

// TestDB provides test database setup and teardown
type TestDB struct {
	DB   *sql.DB
	Path string
	Type string // "sqlite" or "postgres"
}

// SetupTestDB creates a test database for testing
func SetupTestDB(t *testing.T, dbType string) *TestDB {
	t.Helper()

	var testDB *TestDB

	switch dbType {
	case "sqlite":
		testDB = setupSQLiteTestDB(t)
	case "postgres":
		testDB = setupPostgresTestDB(t)
	default:
		t.Fatalf("Unsupported database type: %s", dbType)
	}

	// Run migrations
	if err := runMigrations(testDB, t); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return testDB
}

// TeardownTestDB cleans up test database
func TeardownTestDB(t *testing.T, testDB *TestDB) {
	t.Helper()

	if testDB.DB != nil {
		if err := testDB.DB.Close(); err != nil {
			t.Errorf("Failed to close database: %v", err)
		}
	}

	if testDB.Type == "sqlite" && testDB.Path != "" {
		if err := os.Remove(testDB.Path); err != nil {
			t.Logf("Warning: Failed to remove test database: %v", err)
		}
	}
}

// setupSQLiteTestDB creates an in-memory SQLite database
func setupSQLiteTestDB(t *testing.T) *TestDB {
	t.Helper()

	dbPath := filepath.Join(os.TempDir(), fmt.Sprintf("wispy_test_%d.db", time.Now().UnixNano()))
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping SQLite database: %v", err)
	}

	return &TestDB{
		DB:   db,
		Path: dbPath,
		Type: "sqlite",
	}
}

// setupPostgresTestDB creates a PostgreSQL test database
func setupPostgresTestDB(t *testing.T) *TestDB {
	t.Helper()

	// Read PostgreSQL connection from environment or use defaults
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/wispy_test?sslmode=disable"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("Skipping PostgreSQL tests: Failed to connect to database: %v (set TEST_POSTGRES_DSN)", err)
		return nil
	}

	if err := db.Ping(); err != nil {
		t.Skipf("Skipping PostgreSQL tests: Failed to ping database: %v", err)
		return nil
	}

	// Clean up any existing test data
	_, _ = db.Exec("DROP SCHEMA public CASCADE")
	_, _ = db.Exec("CREATE SCHEMA public")

	return &TestDB{
		DB:   db,
		Type: "postgres",
	}
}

// runMigrations runs database schema migrations
func runMigrations(testDB *TestDB, t *testing.T) error {
	t.Helper()

	var schemaSQL string
	switch testDB.Type {
	case "sqlite":
		schemaSQL = getSQLiteSchema()
	case "postgres":
		schemaSQL = getPostgresSchema()
	default:
		return fmt.Errorf("unsupported database type: %s", testDB.Type)
	}

	if _, err := testDB.DB.Exec(schemaSQL); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// getSQLiteSchema returns the SQLite schema
func getSQLiteSchema() string {
	return `-- Wispy Auth SQLite Test Schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL DEFAULT (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6)))),
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    password_hash VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50) DEFAULT 'email',
    provider_id VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email, provider)
);

-- User Security table
CREATE TABLE IF NOT EXISTS user_security (
    user_id INTEGER PRIMARY KEY,

    -- Login Security
    login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    last_login_at DATETIME,
    last_login_ip VARCHAR(45),
    last_failed_login_at DATETIME,
    last_failed_login_ip VARCHAR(45),

    -- Password Security
    password_changed_at DATETIME,
    force_password_change BOOLEAN DEFAULT FALSE,

    -- 2FA Settings
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    two_factor_backup_codes TEXT,
    two_factor_verified_at DATETIME,

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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    last_accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    ip_address VARCHAR(45),
    device_fingerprint VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_expires ON sessions(user_id, expires_at);

-- OAuth States table
CREATE TABLE IF NOT EXISTS oauth_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state VARCHAR(255) UNIQUE NOT NULL,
    csrf VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    redirect_url TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_state ON oauth_states(state);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at);

-- Security Events table
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,

    -- Event Details
    event_type VARCHAR(50) NOT NULL,
    description TEXT,

    -- Request Context
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(255),

    -- Event Metadata
    severity VARCHAR(20) DEFAULT 'info',
    success BOOLEAN DEFAULT TRUE,
    metadata TEXT,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_security_events_user_type ON security_events(user_id, event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC);

-- Password Reset Tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_expires ON password_reset_tokens(user_id, expires_at);

-- 2FA Codes table
CREATE TABLE IF NOT EXISTS two_factor_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code VARCHAR(10) NOT NULL,
    code_type VARCHAR(20) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_two_factor_codes_user_code ON two_factor_codes(user_id, code);
CREATE INDEX IF NOT EXISTS idx_two_factor_codes_expires ON two_factor_codes(expires_at);

-- 2FA Backup Codes table
CREATE TABLE IF NOT EXISTS two_factor_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code VARCHAR(10) NOT NULL,
    used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_two_factor_backup_codes_user_code ON two_factor_backup_codes(user_id, code);

-- Refresh Tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    session_id INTEGER,
    expires_at DATETIME NOT NULL,
    last_used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at);`
}

// getPostgresSchema returns the PostgreSQL schema
func getPostgresSchema() string {
	return `-- Wispy Auth PostgreSQL Test Schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    uuid TEXT UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    password_hash VARCHAR(255),
    avatar_url TEXT,
    provider VARCHAR(50) DEFAULT 'email',
    provider_id VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_suspended BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider_id ON users(provider, provider_id);

-- User Security table
CREATE TABLE IF NOT EXISTS user_security (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    last_failed_login_at TIMESTAMP,
    last_failed_login_ip VARCHAR(45),
    password_changed_at TIMESTAMP,
    force_password_change BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    two_factor_backup_codes TEXT,
    two_factor_verified_at TIMESTAMP,
    concurrent_sessions INTEGER DEFAULT 0,
    security_version INTEGER DEFAULT 1,
    risk_score INTEGER DEFAULT 0,
    suspicious_activity_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    device_fingerprint VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    is_active BOOLEAN DEFAULT TRUE,
    last_accessed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_expires ON sessions(user_id, expires_at);

-- OAuth States table
CREATE TABLE IF NOT EXISTS oauth_states (
    id SERIAL PRIMARY KEY,
    state VARCHAR(255) UNIQUE NOT NULL,
    csrf VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    redirect_url TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_state ON oauth_states(state);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at);

-- Security Events table
CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    description TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    severity VARCHAR(20) DEFAULT 'info',
    success BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_security_events_user_type ON security_events(user_id, event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC);

-- Password Reset Tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_expires ON password_reset_tokens(user_id, expires_at);

-- 2FA Codes table
CREATE TABLE IF NOT EXISTS two_factor_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    code_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_two_factor_codes_user_code ON two_factor_codes(user_id, code);
CREATE INDEX IF NOT EXISTS idx_two_factor_codes_expires ON two_factor_codes(expires_at);

-- 2FA Backup Codes table
CREATE TABLE IF NOT EXISTS two_factor_backup_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_two_factor_backup_codes_user_code ON two_factor_backup_codes(user_id, code);

-- Refresh Tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at);

-- UUID generation function
CREATE OR REPLACE FUNCTION gen_random_uuid() RETURNS TEXT AS $$
    SELECT lower(hex(random_blob(4))) || '-' || 
           lower(hex(random_blob(2))) || '-4' || 
           substr(lower(hex(random_blob(2))), 2) || '-' || 
           substr('89ab', abs(random()) % 4 + 1, 1) || 
           substr(lower(hex(random_blob(2))), 2) || '-' || 
           lower(hex(random_blob(6)))
$$ LANGUAGE SQL;`
}

// AssertTimeWithin checks if two timestamps are within a given duration
func AssertTimeWithin(t *testing.T, expected, actual time.Time, duration time.Duration) {
	t.Helper()
	diff := expected.Sub(actual)
	if diff < 0 {
		diff = -diff
	}
	if diff > duration {
		t.Errorf("Time difference exceeds %v: got %v", duration, diff)
	}
}

// AssertTimeAfter checks if actual time is after expected time
func AssertTimeAfter(t *testing.T, expected, actual time.Time) {
	t.Helper()
	if !actual.After(expected) {
		t.Errorf("Expected time %v to be after %v", actual, expected)
	}
}

// AssertTimeBefore checks if actual time is before expected time
func AssertTimeBefore(t *testing.T, expected, actual time.Time) {
	t.Helper()
	if !actual.Before(expected) {
		t.Errorf("Expected time %v to be before %v", actual, expected)
	}
}
