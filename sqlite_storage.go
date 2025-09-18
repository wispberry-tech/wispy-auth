package auth

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStorage implements StorageInterface for SQLite databases using pure SQL
type SQLiteStorage struct {
	db     *sql.DB
	config StorageConfig
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(dbPath string, config StorageConfig) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Enable foreign keys and WAL mode for better performance and consistency
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}

	storage := &SQLiteStorage{
		db:     db,
		config: config,
	}

	return storage, nil
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// RecreateDatabase drops all tables and recreates them - useful for testing
func (s *SQLiteStorage) RecreateDatabase() error {
	// Drop tables in reverse dependency order
	tables := []string{
		"security_events",
		"user_tenants", 
		"role_permissions",
		"sessions",
		"oauth_states",
		"users",
		"permissions",
		"roles", 
		"tenants",
	}

	for _, table := range tables {
		if _, err := s.db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)); err != nil {
			return fmt.Errorf("failed to drop table %s: %w", table, err)
		}
	}

	// Recreate all tables
	return s.CreateTables()
}

// CreateTables creates all necessary tables for the auth system
func (s *SQLiteStorage) CreateTables() error {
	queries := []string{
		// Tenants table
		`CREATE TABLE IF NOT EXISTS tenants (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			slug TEXT UNIQUE NOT NULL,
			settings TEXT DEFAULT '{}',
			is_active BOOLEAN DEFAULT TRUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Roles table
		`CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tenant_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (tenant_id) REFERENCES tenants(id),
			UNIQUE(tenant_id, name)
		)`,

		// Permissions table
		`CREATE TABLE IF NOT EXISTS permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Role permissions junction table
		`CREATE TABLE IF NOT EXISTS role_permissions (
			role_id INTEGER NOT NULL,
			permission_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (role_id, permission_id),
			FOREIGN KEY (role_id) REFERENCES roles(id),
			FOREIGN KEY (permission_id) REFERENCES permissions(id)
		)`,

		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			username TEXT,
			first_name TEXT,
			last_name TEXT,
			password_hash TEXT,
			provider TEXT DEFAULT 'email',
			provider_id TEXT,
			email_verified BOOLEAN DEFAULT FALSE,
			email_verification_token TEXT,
			email_verification_expires DATETIME,
			password_reset_token TEXT,
			password_reset_expires DATETIME,
			password_changed_at DATETIME,
			two_factor_enabled BOOLEAN DEFAULT FALSE,
			two_factor_secret TEXT,
			two_factor_backup_codes TEXT,
			failed_login_attempts INTEGER DEFAULT 0,
			locked_until DATETIME,
			last_login_at DATETIME,
			last_login_ip TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			is_suspended BOOLEAN DEFAULT FALSE,
			suspension_reason TEXT,
			suspension_expires DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// User tenants junction table
		`CREATE TABLE IF NOT EXISTS user_tenants (
			user_id INTEGER NOT NULL,
			tenant_id INTEGER NOT NULL,
			role_id INTEGER,
			is_active BOOLEAN DEFAULT TRUE,
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, tenant_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (tenant_id) REFERENCES tenants(id),
			FOREIGN KEY (role_id) REFERENCES roles(id)
		)`,

		// Sessions table
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			token TEXT UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			device_fingerprint TEXT,
			user_agent TEXT,
			ip_address TEXT,
			location TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
			requires_two_factor BOOLEAN DEFAULT FALSE,
			two_factor_verified BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,

		// OAuth states table
		`CREATE TABLE IF NOT EXISTS oauth_states (
			state_id TEXT PRIMARY KEY,
			csrf_token TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)`,

		// Security events table
		`CREATE TABLE IF NOT EXISTS security_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			tenant_id INTEGER,
			event_type TEXT NOT NULL,
			description TEXT,
			ip_address TEXT,
			user_agent TEXT,
			location TEXT,
			additional_data TEXT DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (tenant_id) REFERENCES tenants(id)
		)`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	// Create indexes for better performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
		"CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id)",
		"CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(email_verification_token)",
		"CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(password_reset_token)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at)",
	}

	for _, index := range indexes {
		if _, err := s.db.Exec(index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// OAuth State storage methods
func (s *SQLiteStorage) StoreOAuthState(state *OAuthState) error {
	query := `INSERT INTO oauth_states (state_id, csrf_token, created_at, expires_at) 
			  VALUES (?, ?, ?, ?)`

	_, err := s.db.Exec(query, state.State, state.CSRF, state.CreatedAt, state.ExpiresAt)
	if err != nil {
		slog.Error("Failed to store OAuth state", "error", err, "state_id", state.State)
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetOAuthState(stateID string) (*OAuthState, error) {
	query := `SELECT state_id, csrf_token, created_at, expires_at 
			  FROM oauth_states WHERE state_id = ?`

	var state OAuthState
	err := s.db.QueryRow(query, stateID).Scan(
		&state.State,
		&state.CSRF,
		&state.CreatedAt,
		&state.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		slog.Warn("OAuth state not found", "state_id", stateID)
		return nil, fmt.Errorf("OAuth state not found")
	}
	if err != nil {
		slog.Error("Failed to get OAuth state", "error", err, "state_id", stateID)
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	return &state, nil
}

func (s *SQLiteStorage) DeleteOAuthState(stateID string) error {
	query := `DELETE FROM oauth_states WHERE state_id = ?`
	_, err := s.db.Exec(query, stateID)
	if err != nil {
		slog.Error("Failed to delete OAuth state", "error", err, "state_id", stateID)
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) CleanupExpiredOAuthStates() error {
	query := `DELETE FROM oauth_states WHERE expires_at < ?`
	_, err := s.db.Exec(query, time.Now())
	if err != nil {
		slog.Error("Failed to cleanup expired OAuth states", "error", err)
		return fmt.Errorf("failed to cleanup expired OAuth states: %w", err)
	}
	return nil
}

// User storage methods
func (s *SQLiteStorage) CreateUser(user *User) error {
	query := `INSERT INTO users (email, username, first_name, last_name, password_hash, 
			  provider, provider_id, email_verification_token, 
			  password_changed_at, created_at, updated_at) 
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.VerificationToken,
		user.PasswordChangedAt, user.CreatedAt, user.UpdatedAt)

	if err != nil {
		slog.Error("Failed to create user", "error", err, "email", user.Email)
		return fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get user ID: %w", err)
	}

	user.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetUserByID(id uint) (*User, error) {
	query := `SELECT id, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, email_verification_token,
			  password_reset_token, password_changed_at, two_factor_enabled, 
			  two_factor_secret, failed_login_attempts, locked_until,
			  last_login_at, last_login_ip, is_active, is_suspended,
			  suspension_reason, created_at, updated_at
			  FROM users WHERE id = ?`

	user := &User{}
	var lockedUntil, lastLoginAt, passwordChangedAt sql.NullTime
	var loginAttempts sql.NullInt64
	var lastKnownIP, suspendReason sql.NullString

	err := s.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.VerificationToken, &user.PasswordResetToken,
		&passwordChangedAt, &user.TwoFactorEnabled,
		&user.TwoFactorSecret, &loginAttempts,
		&lockedUntil, &lastLoginAt, &lastKnownIP, &user.IsActive,
		&user.IsSuspended, &suspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		slog.Error("Failed to get user by ID", "error", err, "user_id", id)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Handle nullable fields
	if passwordChangedAt.Valid {
		user.PasswordChangedAt = &passwordChangedAt.Time
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	if lastKnownIP.Valid {
		user.LastKnownIP = lastKnownIP.String
	}
	if suspendReason.Valid {
		user.SuspendReason = suspendReason.String
	}
	if loginAttempts.Valid {
		user.LoginAttempts = int(loginAttempts.Int64)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	query := `SELECT id, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, 
			  COALESCE(email_verification_token, '') as email_verification_token,
			  COALESCE(password_reset_token, '') as password_reset_token, 
			  password_changed_at, two_factor_enabled, 
			  COALESCE(two_factor_secret, '') as two_factor_secret, 
			  COALESCE(failed_login_attempts, 0) as failed_login_attempts, 
			  locked_until, last_login_at, 
			  COALESCE(last_login_ip, '') as last_login_ip, 
			  is_active, is_suspended,
			  COALESCE(suspension_reason, '') as suspension_reason, 
			  created_at, updated_at
			  FROM users WHERE email = ?`

	user := &User{}
	var passwordChangedAt, lockedUntil, lastLoginAt sql.NullTime

	err := s.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.VerificationToken, &user.PasswordResetToken,
		&passwordChangedAt, &user.TwoFactorEnabled,
		&user.TwoFactorSecret, &user.LoginAttempts,
		&lockedUntil, &lastLoginAt, &user.LastKnownIP, &user.IsActive,
		&user.IsSuspended, &user.SuspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		slog.Error("Failed to get user by email", "error", err, "email", email)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Handle nullable fields
	if passwordChangedAt.Valid {
		user.PasswordChangedAt = &passwordChangedAt.Time
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}

	return user, nil
}

func (s *SQLiteStorage) UpdateUser(user *User) error {
	query := `UPDATE users SET username = ?, first_name = ?, last_name = ?,
			  password_hash = ?, email_verified = ?, email_verification_token = ?,
			  password_reset_token = ?, password_changed_at = ?, two_factor_enabled = ?,
			  two_factor_secret = ?, failed_login_attempts = ?,
			  locked_until = ?, last_login_at = ?, last_login_ip = ?, is_active = ?,
			  is_suspended = ?, suspension_reason = ?,
			  updated_at = ? WHERE id = ?`

	_, err := s.db.Exec(query,
		user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.EmailVerified, user.VerificationToken,
		user.PasswordResetToken, user.PasswordChangedAt,
		user.TwoFactorEnabled, user.TwoFactorSecret, user.LoginAttempts,
		user.LockedUntil, user.LastLoginAt,
		user.LastKnownIP, user.IsActive, user.IsSuspended, user.SuspendReason,
		user.UpdatedAt, user.ID)

	if err != nil {
		slog.Error("Failed to update user", "error", err, "user_id", user.ID)
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// Session storage methods
func (s *SQLiteStorage) CreateSession(session *Session) error {
	query := `INSERT INTO sessions (id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, location, is_active, last_activity,
			  requires_two_factor, two_factor_verified, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		session.ID, session.UserID, session.Token, session.ExpiresAt,
		session.DeviceFingerprint, session.UserAgent, session.IPAddress,
		session.Location, session.IsActive, session.LastActivity,
		session.RequiresTwoFactor, session.TwoFactorVerified,
		session.CreatedAt, session.UpdatedAt)

	if err != nil {
		slog.Error("Failed to create session", "error", err, "session_id", session.ID)
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetSession(token string) (*Session, error) {
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, location, is_active, last_activity,
			  requires_two_factor, two_factor_verified, created_at, updated_at
			  FROM sessions WHERE token = ? AND is_active = TRUE`

	session := &Session{}
	err := s.db.QueryRow(query, token).Scan(
		&session.ID, &session.UserID, &session.Token, &session.ExpiresAt,
		&session.DeviceFingerprint, &session.UserAgent, &session.IPAddress,
		&session.Location, &session.IsActive, &session.LastActivity,
		&session.RequiresTwoFactor, &session.TwoFactorVerified,
		&session.CreatedAt, &session.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		slog.Error("Failed to get session", "error", err, "token", token)
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

func (s *SQLiteStorage) UpdateSession(session *Session) error {
	query := `UPDATE sessions SET last_activity = ?, requires_two_factor = ?,
			  two_factor_verified = ?, updated_at = ? WHERE id = ?`

	_, err := s.db.Exec(query,
		session.LastActivity, session.RequiresTwoFactor,
		session.TwoFactorVerified, session.UpdatedAt, session.ID)

	if err != nil {
		slog.Error("Failed to update session", "error", err, "session_id", session.ID)
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetUserSessions(userID uint) ([]*Session, error) {
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, location, is_active, last_activity,
			  requires_two_factor, two_factor_verified, created_at, updated_at
			  FROM sessions WHERE user_id = ? AND is_active = TRUE
			  ORDER BY last_activity DESC`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		slog.Error("Failed to get user sessions", "error", err, "user_id", userID)
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		session := &Session{}
		err := rows.Scan(
			&session.ID, &session.UserID, &session.Token, &session.ExpiresAt,
			&session.DeviceFingerprint, &session.UserAgent, &session.IPAddress,
			&session.Location, &session.IsActive, &session.LastActivity,
			&session.RequiresTwoFactor, &session.TwoFactorVerified,
			&session.CreatedAt, &session.UpdatedAt,
		)
		if err != nil {
			slog.Error("Failed to scan session", "error", err, "user_id", userID)
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (s *SQLiteStorage) CountActiveSessions(userID uint) (int, error) {
	query := `SELECT COUNT(*) FROM sessions WHERE user_id = ? AND is_active = TRUE`

	var count int
	err := s.db.QueryRow(query, userID).Scan(&count)
	if err != nil {
		slog.Error("Failed to count active sessions", "error", err, "user_id", userID)
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}

	return count, nil
}

func (s *SQLiteStorage) RevokeSession(sessionID string) error {
	query := `UPDATE sessions SET is_active = FALSE, updated_at = ? WHERE id = ?`

	_, err := s.db.Exec(query, time.Now(), sessionID)
	if err != nil {
		slog.Error("Failed to revoke session", "error", err, "session_id", sessionID)
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) RevokeAllUserSessions(userID uint) error {
	query := `UPDATE sessions SET is_active = FALSE, updated_at = ? WHERE user_id = ?`

	_, err := s.db.Exec(query, time.Now(), userID)
	if err != nil {
		slog.Error("Failed to revoke all user sessions", "error", err, "user_id", userID)
		return fmt.Errorf("failed to revoke all user sessions: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) CleanupExpiredSessions() error {
	query := `DELETE FROM sessions WHERE expires_at < ?`

	_, err := s.db.Exec(query, time.Now())
	if err != nil {
		slog.Error("Failed to cleanup expired sessions", "error", err)
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	return nil
}

// Security event storage methods
func (s *SQLiteStorage) LogSecurityEvent(event *SecurityEvent) error {
	query := `INSERT INTO security_events (user_id, tenant_id, event_type, description,
			  ip_address, user_agent, location, additional_data, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		event.UserID, event.TenantID, event.EventType, event.Description,
		event.IPAddress, event.UserAgent, event.Location,
		event.Metadata, event.CreatedAt)

	if err != nil {
		slog.Error("Failed to log security event", "error", err, "event_type", event.EventType)
		return fmt.Errorf("failed to log security event: %w", err)
	}

	return nil
}

// Multi-tenant storage methods (basic implementations for now)
func (s *SQLiteStorage) CreateTenant(tenant *Tenant) error {
	query := `INSERT INTO tenants (name, slug, settings, is_active, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query, tenant.Name, tenant.Slug, tenant.Settings,
		tenant.IsActive, tenant.CreatedAt, tenant.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get tenant ID: %w", err)
	}

	tenant.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetTenantByID(id uint) (*Tenant, error) {
	query := `SELECT id, name, slug, settings, is_active, created_at, updated_at
			  FROM tenants WHERE id = ?`

	tenant := &Tenant{}
	err := s.db.QueryRow(query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Settings,
		&tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tenant not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	return tenant, nil
}

func (s *SQLiteStorage) GetUserTenants(userID uint) ([]*UserTenant, error) {
	query := `SELECT ut.user_id, ut.tenant_id, ut.role_id, ut.is_active, ut.created_at, ut.updated_at,
			  t.id, t.name, t.slug, t.settings, t.is_active, t.created_at, t.updated_at,
			  r.id, r.tenant_id, r.name, r.description, r.created_at, r.updated_at
			  FROM user_tenants ut
			  JOIN tenants t ON ut.tenant_id = t.id
			  LEFT JOIN roles r ON ut.role_id = r.id
			  WHERE ut.user_id = ? AND ut.is_active = TRUE`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user tenants: %w", err)
	}
	defer rows.Close()

	var userTenants []*UserTenant
	for rows.Next() {
		ut := &UserTenant{}
		t := &Tenant{}
		var r *Role
		var roleID sql.NullInt64
		var roleTenantID sql.NullInt64
		var roleName, roleDescription sql.NullString
		var roleCreatedAt, roleUpdatedAt sql.NullTime

		err := rows.Scan(
			&ut.UserID, &ut.TenantID, &ut.RoleID, &ut.IsActive, &ut.CreatedAt, &ut.UpdatedAt,
			&t.ID, &t.Name, &t.Slug, &t.Settings, &t.IsActive, &t.CreatedAt, &t.UpdatedAt,
			&roleID, &roleTenantID, &roleName, &roleDescription, &roleCreatedAt, &roleUpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user tenant: %w", err)
		}

		ut.Tenant = t

		// Handle role if it exists
		if roleID.Valid {
			r = &Role{
				ID:          uint(roleID.Int64),
				TenantID:    uint(roleTenantID.Int64),
				Name:        roleName.String,
				Description: roleDescription.String,
				CreatedAt:   roleCreatedAt.Time,
				UpdatedAt:   roleUpdatedAt.Time,
			}
			ut.Role = r
		}

		userTenants = append(userTenants, ut)
	}

	return userTenants, nil
}

func (s *SQLiteStorage) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	// This is a simplified implementation - in a full system you'd check through roles
	return false, nil
}

// Missing methods - implementing as stubs for now
func (s *SQLiteStorage) GetUserByEmail(email, provider string) (*User, error) {
	return s.GetUserByEmailAnyProvider(email)
}

func (s *SQLiteStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	query := `SELECT id, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, email_verification_token,
			  password_reset_token, password_changed_at, two_factor_enabled, 
			  two_factor_secret, failed_login_attempts, locked_until,
			  last_login_at, last_login_ip, is_active, is_suspended,
			  suspension_reason, created_at, updated_at
			  FROM users WHERE provider = ? AND provider_id = ?`

	user := &User{}
	var passwordChangedAt, lockedUntil, lastLoginAt sql.NullTime
	var loginAttempts sql.NullInt64
	var lastKnownIP, suspendReason sql.NullString

	err := s.db.QueryRow(query, provider, providerID).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.VerificationToken, &user.PasswordResetToken,
		&passwordChangedAt, &user.TwoFactorEnabled,
		&user.TwoFactorSecret, &loginAttempts,
		&lockedUntil, &lastLoginAt, &lastKnownIP, &user.IsActive,
		&user.IsSuspended, &suspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Handle nullable fields
	if passwordChangedAt.Valid {
		user.PasswordChangedAt = &passwordChangedAt.Time
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	if lastKnownIP.Valid {
		user.LastKnownIP = lastKnownIP.String
	}
	if suspendReason.Valid {
		user.SuspendReason = suspendReason.String
	}
	if loginAttempts.Valid {
		user.LoginAttempts = int(loginAttempts.Int64)
	}

	return user, nil
}

func (s *SQLiteStorage) DeleteSession(token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := s.db.Exec(query, token)
	return err
}

func (s *SQLiteStorage) DeleteUserSessions(userID uint) error {
	query := `DELETE FROM sessions WHERE user_id = ?`
	_, err := s.db.Exec(query, userID)
	return err
}

// Tenant operations stubs
func (s *SQLiteStorage) GetTenantBySlug(slug string) (*Tenant, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) UpdateTenant(tenant *Tenant) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) ListTenants() ([]*Tenant, error) {
	return nil, fmt.Errorf("not implemented")
}

// Role operations stubs
func (s *SQLiteStorage) CreateRole(role *Role) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetRoleByID(id uint) (*Role, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetRolesByTenant(tenantID uint) ([]*Role, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) UpdateRole(role *Role) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) DeleteRole(id uint) error {
	return fmt.Errorf("not implemented")
}

// Permission operations stubs
func (s *SQLiteStorage) CreatePermission(permission *Permission) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetPermissionByID(id uint) (*Permission, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetPermissionByName(name string) (*Permission, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) ListPermissions() ([]*Permission, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) UpdatePermission(permission *Permission) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) DeletePermission(id uint) error {
	return fmt.Errorf("not implemented")
}

// Role-Permission operations stubs
func (s *SQLiteStorage) AssignPermissionToRole(roleID, permissionID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) RemovePermissionFromRole(roleID, permissionID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetRolePermissions(roleID uint) ([]*Permission, error) {
	return nil, fmt.Errorf("not implemented")
}

// User-Tenant operations stubs
func (s *SQLiteStorage) AssignUserToTenant(userID, tenantID, roleID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) RemoveUserFromTenant(userID, tenantID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetTenantUsers(tenantID uint) ([]*UserTenant, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) UpdateUserTenantRole(userID, tenantID, roleID uint) error {
	return fmt.Errorf("not implemented")
}

// Additional required methods
func (s *SQLiteStorage) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) CreateSecurityEvent(event *SecurityEvent) error {
	return s.LogSecurityEvent(event)
}

func (s *SQLiteStorage) GetSecurityEvents(userID *uint, tenantID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) CreatePasswordResetToken(userID uint, token string, expiresAt time.Time) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetUserByPasswordResetToken(token string) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) ClearPasswordResetToken(userID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) SetEmailVerificationToken(userID uint, token string) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetUserByVerificationToken(token string) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) MarkEmailAsVerified(userID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) IncrementLoginAttempts(userID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) ResetLoginAttempts(userID uint) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) LockUser(userID uint, until time.Time) error {
	return fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) UnlockUser(userID uint) error {
	return fmt.Errorf("not implemented")
}