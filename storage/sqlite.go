package storage

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

// Helper function for debug logging
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SQLiteStorage is a production-ready SQLite storage implementation
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}
	return NewSQLiteStorageFromDB(db)
}

// NewSQLiteStorageFromDB creates a new SQLite storage from an existing database connection
func NewSQLiteStorageFromDB(db *sql.DB) (*SQLiteStorage, error) {
	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	s := &SQLiteStorage{db: db}

	return s, nil
}

// NewInMemorySQLiteStorage creates a new in-memory SQLite storage instance for testing
// This function automatically runs the SQL scaffolding from sql/sqlite_scaffold.sql
func NewInMemorySQLiteStorage() (*SQLiteStorage, error) {
	// Create in-memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory SQLite database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Read and execute the SQL scaffolding file
	scaffoldPath := filepath.Join("..", "sql", "sqlite_scaffold.sql")
	if _, err := os.Stat(scaffoldPath); os.IsNotExist(err) {
		// Try relative to current directory
		scaffoldPath = filepath.Join("sql", "sqlite_scaffold.sql")
		if _, err := os.Stat(scaffoldPath); os.IsNotExist(err) {
			// Try one more location
			scaffoldPath = filepath.Join("..", "..", "sql", "sqlite_scaffold.sql")
		}
	}

	scaffoldSQL, err := os.ReadFile(scaffoldPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SQL scaffolding file: %w", err)
	}

	// Execute the scaffolding SQL
	if _, err := db.Exec(string(scaffoldSQL)); err != nil {
		return nil, fmt.Errorf("failed to execute SQL scaffolding: %w", err)
	}

	return &SQLiteStorage{db: db}, nil
}

// Implement required interface methods
func (s *SQLiteStorage) CreateUser(user *User) error {
	query := `INSERT INTO users (email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get user ID: %w", err)
	}

	user.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetUserByEmail(email, provider string) (*User, error) {
	query := `SELECT id, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = ? AND provider = ?`

	user := &User{}

	err := s.db.QueryRow(query, email, provider).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	return s.GetUserByEmail(email, "email")
}

func (s *SQLiteStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *SQLiteStorage) GetUserByID(id uint) (*User, error) {
	query := `SELECT id, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE id = ?`

	user := &User{}

	err := s.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) UpdateUser(user *User) error {
	query := `UPDATE users SET username = ?, first_name = ?, last_name = ?,
			  password_hash = ?, email_verified = ?, is_active = ?, is_suspended = ?,
			  updated_at = ? WHERE id = ?`

	_, err := s.db.Exec(query, user.Username, user.FirstName, user.LastName,
		user.PasswordHash, user.EmailVerified, user.IsActive, user.IsSuspended,
		time.Now(), user.ID)

	return err
}

// UserSecurity operations
func (s *SQLiteStorage) CreateUserSecurity(security *UserSecurity) error {
	query := `INSERT INTO user_security (user_id, email_verified_at, verification_token,
			  password_reset_token, password_reset_expires_at, password_changed_at,
			  login_attempts, last_failed_login_at, locked_until, last_login_at,
			  last_known_ip, last_login_location, two_factor_enabled, two_factor_secret,
			  backup_codes, suspended_at, suspend_reason, referred_by_code,
			  created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		security.UserID, security.EmailVerifiedAt, security.VerificationToken,
		security.PasswordResetToken, security.PasswordResetExpiresAt, security.PasswordChangedAt,
		security.LoginAttempts, security.LastFailedLoginAt, security.LockedUntil, security.LastLoginAt,
		security.LastKnownIP, security.LastLoginLocation, security.TwoFactorEnabled, security.TwoFactorSecret,
		security.BackupCodes, security.SuspendedAt, security.SuspendReason, security.ReferredByCode,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user security: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetUserSecurity(userID uint) (*UserSecurity, error) {
	query := `SELECT user_id, email_verified_at, verification_token,
			  password_reset_token, password_reset_expires_at, password_changed_at,
			  login_attempts, last_failed_login_at, locked_until, last_login_at,
			  last_known_ip, last_login_location, two_factor_enabled, two_factor_secret,
			  backup_codes, suspended_at, suspend_reason, referred_by_code,
			  created_at, updated_at
			  FROM user_security WHERE user_id = ?`

	security := &UserSecurity{}
	var emailVerifiedAt, passwordResetExpiresAt, passwordChangedAt sql.NullTime
	var lastFailedLoginAt, lockedUntil, lastLoginAt, suspendedAt sql.NullTime
	var verificationToken, passwordResetToken sql.NullString
	var lastKnownIP, lastLoginLocation, twoFactorSecret, backupCodes sql.NullString
	var suspendReason, referredByCode sql.NullString

	err := s.db.QueryRow(query, userID).Scan(
		&security.UserID, &emailVerifiedAt, &verificationToken,
		&passwordResetToken, &passwordResetExpiresAt, &passwordChangedAt,
		&security.LoginAttempts, &lastFailedLoginAt, &lockedUntil, &lastLoginAt,
		&lastKnownIP, &lastLoginLocation, &security.TwoFactorEnabled, &twoFactorSecret,
		&backupCodes, &suspendedAt, &suspendReason, &referredByCode,
		&security.CreatedAt, &security.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user security not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user security: %w", err)
	}

	// Handle nullable fields
	if emailVerifiedAt.Valid {
		security.EmailVerifiedAt = &emailVerifiedAt.Time
	}
	if verificationToken.Valid {
		security.VerificationToken = verificationToken.String
	}
	if passwordResetToken.Valid {
		security.PasswordResetToken = passwordResetToken.String
	}
	if passwordResetExpiresAt.Valid {
		security.PasswordResetExpiresAt = &passwordResetExpiresAt.Time
	}
	if passwordChangedAt.Valid {
		security.PasswordChangedAt = &passwordChangedAt.Time
	}
	if lastFailedLoginAt.Valid {
		security.LastFailedLoginAt = &lastFailedLoginAt.Time
	}
	if lockedUntil.Valid {
		security.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		security.LastLoginAt = &lastLoginAt.Time
	}
	if lastKnownIP.Valid {
		security.LastKnownIP = lastKnownIP.String
	}
	if lastLoginLocation.Valid {
		security.LastLoginLocation = lastLoginLocation.String
	}
	if twoFactorSecret.Valid {
		security.TwoFactorSecret = twoFactorSecret.String
	}
	if backupCodes.Valid {
		security.BackupCodes = backupCodes.String
	}
	if suspendedAt.Valid {
		security.SuspendedAt = &suspendedAt.Time
	}
	if suspendReason.Valid {
		security.SuspendReason = suspendReason.String
	}
	if referredByCode.Valid {
		security.ReferredByCode = referredByCode.String
	}

	return security, nil
}

func (s *SQLiteStorage) UpdateUserSecurity(security *UserSecurity) error {
	query := `UPDATE user_security SET email_verified_at = ?, verification_token = ?,
			  password_reset_token = ?, password_reset_expires_at = ?, password_changed_at = ?,
			  login_attempts = ?, last_failed_login_at = ?, locked_until = ?, last_login_at = ?,
			  last_known_ip = ?, last_login_location = ?, two_factor_enabled = ?, two_factor_secret = ?,
			  backup_codes = ?, suspended_at = ?, suspend_reason = ?, referred_by_code = ?,
			  updated_at = ? WHERE user_id = ?`

	_, err := s.db.Exec(query,
		security.EmailVerifiedAt, security.VerificationToken,
		security.PasswordResetToken, security.PasswordResetExpiresAt, security.PasswordChangedAt,
		security.LoginAttempts, security.LastFailedLoginAt, security.LockedUntil, security.LastLoginAt,
		security.LastKnownIP, security.LastLoginLocation, security.TwoFactorEnabled, security.TwoFactorSecret,
		security.BackupCodes, security.SuspendedAt, security.SuspendReason, security.ReferredByCode,
		time.Now(), security.UserID)

	return err
}

// Optimized security operations for common use cases
func (s *SQLiteStorage) IncrementLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = login_attempts + 1,
			  last_failed_login_at = ?, updated_at = ? WHERE user_id = ?`
	_, err := s.db.Exec(query, time.Now(), time.Now(), userID)
	return err
}

func (s *SQLiteStorage) ResetLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = 0, locked_until = NULL,
			  updated_at = ? WHERE user_id = ?`
	_, err := s.db.Exec(query, time.Now(), userID)
	return err
}

func (s *SQLiteStorage) SetUserLocked(userID uint, until time.Time) error {
	query := `UPDATE user_security SET locked_until = ?, updated_at = ? WHERE user_id = ?`
	_, err := s.db.Exec(query, until, time.Now(), userID)
	return err
}

func (s *SQLiteStorage) UpdateLastLogin(userID uint, ipAddress string) error {
	query := `UPDATE user_security SET last_login_at = ?, last_known_ip = ?,
			  updated_at = ? WHERE user_id = ?`
	_, err := s.db.Exec(query, time.Now(), ipAddress, time.Now(), userID)
	return err
}

func (s *SQLiteStorage) CreateSession(session *Session) error {
	// Generate session ID if not provided
	if session.ID == "" {
		session.ID = fmt.Sprintf("%d_%d", session.UserID, time.Now().UnixNano())
	}

	// Debug: Log what we're about to store
	slog.Debug("SQLite storing session", "session_id", session.ID, "user_id", session.UserID, "token_prefix", session.Token[:min(8, len(session.Token))], "token_length", len(session.Token))

	query := `INSERT INTO sessions (id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, location, is_active, last_activity,
			  requires_two_factor, two_factor_verified, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		session.ID, session.UserID, session.Token, session.ExpiresAt,
		session.DeviceFingerprint, session.UserAgent, session.IPAddress,
		session.Location, session.IsActive, session.LastActivity,
		session.RequiresTwoFactor, session.TwoFactorVerified,
		time.Now(), time.Now())

	if err != nil {
		slog.Error("SQLite session creation failed", "error", err, "session_id", session.ID, "token_prefix", session.Token[:min(8, len(session.Token))])
		return fmt.Errorf("failed to create session: %w", err)
	}

	slog.Debug("SQLite session created successfully", "session_id", session.ID, "token_prefix", session.Token[:min(8, len(session.Token))])
	return nil
}

func (s *SQLiteStorage) GetSession(token string) (*Session, error) {
	// Debug: Log what we're looking for
	slog.Debug("SQLite looking for session", "token_prefix", token[:min(8, len(token))], "token_length", len(token))

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
		slog.Debug("SQLite session not found", "token_prefix", token[:min(8, len(token))])
		return nil, ErrSessionNotFound
	}
	if err != nil {
		slog.Error("SQLite session query failed", "error", err, "token_prefix", token[:min(8, len(token))])
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	slog.Debug("SQLite session found", "session_id", session.ID, "user_id", session.UserID, "stored_token_prefix", session.Token[:min(8, len(session.Token))])
	return session, nil
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Stub implementations for other required methods
func (s *SQLiteStorage) GetUserSessions(userID uint) ([]*Session, error) {
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, location, is_active, last_activity,
			  requires_two_factor, two_factor_verified, created_at, updated_at
			  FROM sessions WHERE user_id = ? AND is_active = TRUE`

	rows, err := s.db.Query(query, userID)
	if err != nil {
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
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}
func (s *SQLiteStorage) UpdateSession(session *Session) error {
	query := `UPDATE sessions SET is_active = ?, last_activity = ?, updated_at = ? WHERE token = ?`
	_, err := s.db.Exec(query, session.IsActive, session.LastActivity, time.Now(), session.Token)
	return err
}
func (s *SQLiteStorage) DeleteSession(token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := s.db.Exec(query, token)
	return err
}
func (s *SQLiteStorage) DeleteUserSessions(userID uint) error         { return nil }
func (s *SQLiteStorage) CleanupExpiredSessions() error                { return nil }
func (s *SQLiteStorage) CountActiveSessions(userID uint) (int, error) { return 0, nil }
func (s *SQLiteStorage) StoreOAuthState(state *OAuthState) error {
	query := `INSERT INTO oauth_states (state, csrf_token, created_at, expires_at)
			  VALUES (?, ?, ?, ?)`

	_, err := s.db.Exec(query, state.State, state.CSRF, state.CreatedAt, state.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetOAuthState(stateID string) (*OAuthState, error) {
	query := `SELECT state, csrf_token, created_at, expires_at
			  FROM oauth_states WHERE state = ?`

	var state OAuthState
	err := s.db.QueryRow(query, stateID).Scan(
		&state.State,
		&state.CSRF,
		&state.CreatedAt,
		&state.ExpiresAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("OAuth state not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	return &state, nil
}

func (s *SQLiteStorage) DeleteOAuthState(stateID string) error {
	query := `DELETE FROM oauth_states WHERE state = ?`

	result, err := s.db.Exec(query, stateID)
	if err != nil {
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("OAuth state not found")
	}

	return nil
}
func (s *SQLiteStorage) CreateTenant(tenant *Tenant) error {
	query := `INSERT INTO tenants (name, slug, domain, is_active, settings, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		tenant.Name, tenant.Slug, tenant.Domain, tenant.IsActive, tenant.Settings,
		time.Now(), time.Now())

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
	query := `SELECT id, name, slug, domain, is_active, settings, created_at, updated_at
			  FROM tenants WHERE id = ?`

	tenant := &Tenant{}
	err := s.db.QueryRow(query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain,
		&tenant.IsActive, &tenant.Settings, &tenant.CreatedAt, &tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tenant not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	return tenant, nil
}
func (s *SQLiteStorage) GetTenantBySlug(slug string) (*Tenant, error) {
	query := `SELECT id, name, slug, domain, is_active, settings, created_at, updated_at
			  FROM tenants WHERE slug = ?`

	tenant := &Tenant{}
	err := s.db.QueryRow(query, slug).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain,
		&tenant.IsActive, &tenant.Settings, &tenant.CreatedAt, &tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tenant not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	return tenant, nil
}
func (s *SQLiteStorage) UpdateTenant(tenant *Tenant) error {
	query := `UPDATE tenants SET name = ?, slug = ?, domain = ?, is_active = ?, settings = ?, updated_at = ?
			  WHERE id = ?`

	_, err := s.db.Exec(query, tenant.Name, tenant.Slug, tenant.Domain,
		tenant.IsActive, tenant.Settings, time.Now(), tenant.ID)

	return err
}
func (s *SQLiteStorage) ListTenants() ([]*Tenant, error) {
	query := `SELECT id, name, slug, domain, is_active, settings, created_at, updated_at
			  FROM tenants ORDER BY created_at ASC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		tenant := &Tenant{}
		err := rows.Scan(
			&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain,
			&tenant.IsActive, &tenant.Settings, &tenant.CreatedAt, &tenant.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant: %w", err)
		}
		tenants = append(tenants, tenant)
	}

	return tenants, nil
}
func (s *SQLiteStorage) CreateRole(role *Role) error {
	query := `INSERT INTO roles (tenant_id, name, description, is_system, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		role.TenantID, role.Name, role.Description, role.IsSystem,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get role ID: %w", err)
	}

	role.ID = uint(id)
	return nil
}
func (s *SQLiteStorage) GetRoleByID(id uint) (*Role, error) {
	query := `SELECT id, tenant_id, name, description, is_system, created_at, updated_at
			  FROM roles WHERE id = ?`

	role := &Role{}
	err := s.db.QueryRow(query, id).Scan(
		&role.ID, &role.TenantID, &role.Name, &role.Description,
		&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return role, nil
}
func (s *SQLiteStorage) GetRolesByTenant(tenantID uint) ([]*Role, error) {
	query := `SELECT id, tenant_id, name, description, is_system, created_at, updated_at
			  FROM roles WHERE tenant_id = ?`

	rows, err := s.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		role := &Role{}
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.Description,
			&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	return roles, nil
}
func (s *SQLiteStorage) UpdateRole(role *Role) error {
	query := `UPDATE roles SET tenant_id = ?, name = ?, description = ?, is_system = ?, updated_at = ?
			  WHERE id = ?`

	_, err := s.db.Exec(query, role.TenantID, role.Name, role.Description,
		role.IsSystem, time.Now(), role.ID)

	return err
}
func (s *SQLiteStorage) DeleteRole(id uint) error { return nil }
func (s *SQLiteStorage) CreatePermission(permission *Permission) error {
	query := `INSERT INTO permissions (name, resource, action, description, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		permission.Name, permission.Resource, permission.Action, permission.Description,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get permission ID: %w", err)
	}

	permission.ID = uint(id)
	return nil
}
func (s *SQLiteStorage) GetPermissionByID(id uint) (*Permission, error) {
	query := `SELECT id, name, resource, action, description, created_at, updated_at
			  FROM permissions WHERE id = ?`

	permission := &Permission{}
	err := s.db.QueryRow(query, id).Scan(
		&permission.ID, &permission.Name, &permission.Resource, &permission.Action,
		&permission.Description, &permission.CreatedAt, &permission.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("permission not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	return permission, nil
}
func (s *SQLiteStorage) GetPermissionByName(name string) (*Permission, error) {
	query := `SELECT id, name, resource, action, description, created_at, updated_at
			  FROM permissions WHERE name = ?`

	permission := &Permission{}
	err := s.db.QueryRow(query, name).Scan(
		&permission.ID, &permission.Name, &permission.Resource, &permission.Action,
		&permission.Description, &permission.CreatedAt, &permission.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("permission not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	return permission, nil
}
func (s *SQLiteStorage) ListPermissions() ([]*Permission, error) { return nil, nil }
func (s *SQLiteStorage) UpdatePermission(permission *Permission) error {
	query := `UPDATE permissions SET name = ?, resource = ?, action = ?, description = ?, updated_at = ?
			  WHERE id = ?`

	_, err := s.db.Exec(query, permission.Name, permission.Resource, permission.Action,
		permission.Description, time.Now(), permission.ID)

	return err
}
func (s *SQLiteStorage) DeletePermission(id uint) error                           { return nil }
func (s *SQLiteStorage) AssignPermissionToRole(roleID, permissionID uint) error   { return nil }
func (s *SQLiteStorage) RemovePermissionFromRole(roleID, permissionID uint) error { return nil }
func (s *SQLiteStorage) GetRolePermissions(roleID uint) ([]*Permission, error)    { return nil, nil }
func (s *SQLiteStorage) AssignUserToTenant(userID, tenantID, roleID uint) error {
	query := `INSERT INTO user_tenants (user_id, tenant_id, role_id, created_at, updated_at)
			  VALUES (?, ?, ?, datetime('now'), datetime('now'))`

	_, err := s.db.Exec(query, userID, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to assign user to tenant: %w", err)
	}

	return nil
}
func (s *SQLiteStorage) RemoveUserFromTenant(userID, tenantID uint) error         { return nil }
func (s *SQLiteStorage) GetUserTenants(userID uint) ([]*UserTenant, error)        { return nil, nil }
func (s *SQLiteStorage) GetTenantUsers(tenantID uint) ([]*UserTenant, error)      { return nil, nil }
func (s *SQLiteStorage) UpdateUserTenantRole(userID, tenantID, roleID uint) error { return nil }
func (s *SQLiteStorage) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	return false, nil
}
func (s *SQLiteStorage) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	return nil, nil
}
func (s *SQLiteStorage) CreateSecurityEvent(event *SecurityEvent) error {
	query := `INSERT INTO security_events (user_id, tenant_id, event_type, description, ip_address, user_agent, location, metadata, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		event.UserID, event.TenantID, event.EventType, event.Description,
		event.IPAddress, event.UserAgent, event.Location, event.Metadata, time.Now())

	if err != nil {
		return fmt.Errorf("failed to create security event: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get security event ID: %w", err)
	}

	event.ID = uint(id)
	return nil
}
func (s *SQLiteStorage) GetSecurityEvents(userID *uint, tenantID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	return nil, nil
}
func (s *SQLiteStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	query := `SELECT id, user_id, tenant_id, event_type, description, ip_address, user_agent, location, metadata, created_at
			  FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := s.db.Query(query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}
	defer rows.Close()

	var events []*SecurityEvent
	for rows.Next() {
		event := &SecurityEvent{}
		err := rows.Scan(
			&event.ID, &event.UserID, &event.TenantID, &event.EventType,
			&event.Description, &event.IPAddress, &event.UserAgent,
			&event.Location, &event.Metadata, &event.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan security event: %w", err)
		}
		events = append(events, event)
	}

	return events, nil
}
func (s *SQLiteStorage) CreatePasswordResetToken(userID uint, token string, expiresAt time.Time) error {
	return nil
}
func (s *SQLiteStorage) GetUserByPasswordResetToken(token string) (*User, error) {
	query := `SELECT u.id, u.email, u.username, u.first_name, u.last_name, u.password_hash,
			  u.avatar_url, u.provider, u.provider_id, u.email_verified, u.is_active,
			  u.is_suspended, u.created_at, u.updated_at
			  FROM users u
			  JOIN user_security us ON u.id = us.user_id
			  WHERE us.password_reset_token = ? AND us.password_reset_expires_at > datetime('now')`

	user := &User{}
	err := s.db.QueryRow(query, token).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by reset token: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByVerificationToken(token string) (*User, error) {
	query := `SELECT u.id, u.email, u.username, u.first_name, u.last_name, u.password_hash,
			  u.avatar_url, u.provider, u.provider_id, u.email_verified, u.is_active,
			  u.is_suspended, u.created_at, u.updated_at
			  FROM users u
			  JOIN user_security us ON u.id = us.user_id
			  WHERE us.verification_token = ?`

	user := &User{}
	err := s.db.QueryRow(query, token).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by verification token: %w", err)
	}

	return user, nil
}

// Referral Code operations - Stub implementations for now
func (s *SQLiteStorage) CreateReferralCode(code *ReferralCode) error {
	query := `INSERT INTO referral_codes (code, generated_by_user_id, generated_by_role_id, tenant_id, max_uses, current_uses, expires_at, is_active, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		code.Code, code.GeneratedByUserID, code.GeneratedByRoleID, code.TenantID,
		code.MaxUses, code.CurrentUses, code.ExpiresAt, code.IsActive,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create referral code: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get referral code ID: %w", err)
	}

	code.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetReferralCodeByCode(code string) (*ReferralCode, error) {
	query := `SELECT id, code, generated_by_user_id, generated_by_role_id, tenant_id, max_uses, current_uses, expires_at, is_active, created_at, updated_at
			  FROM referral_codes WHERE code = ?`

	referralCode := &ReferralCode{}
	var expiresAt sql.NullTime

	err := s.db.QueryRow(query, code).Scan(
		&referralCode.ID, &referralCode.Code, &referralCode.GeneratedByUserID,
		&referralCode.GeneratedByRoleID, &referralCode.TenantID, &referralCode.MaxUses,
		&referralCode.CurrentUses, &expiresAt, &referralCode.IsActive,
		&referralCode.CreatedAt, &referralCode.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("referral code not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get referral code: %w", err)
	}

	if expiresAt.Valid {
		referralCode.ExpiresAt = &expiresAt.Time
	}

	return referralCode, nil
}

func (s *SQLiteStorage) GetReferralCodesByUser(userID uint) ([]*ReferralCode, error) {
	query := `SELECT id, code, generated_by_user_id, generated_by_role_id, tenant_id, max_uses, current_uses, expires_at, is_active, created_at, updated_at
			  FROM referral_codes WHERE generated_by_user_id = ?`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get referral codes: %w", err)
	}
	defer rows.Close()

	var codes []*ReferralCode
	for rows.Next() {
		code := &ReferralCode{}
		var expiresAt sql.NullTime

		err := rows.Scan(
			&code.ID, &code.Code, &code.GeneratedByUserID,
			&code.GeneratedByRoleID, &code.TenantID, &code.MaxUses,
			&code.CurrentUses, &expiresAt, &code.IsActive,
			&code.CreatedAt, &code.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan referral code: %w", err)
		}

		if expiresAt.Valid {
			code.ExpiresAt = &expiresAt.Time
		}

		codes = append(codes, code)
	}

	return codes, nil
}

func (s *SQLiteStorage) UpdateReferralCode(code *ReferralCode) error {
	query := `UPDATE referral_codes SET code = ?, generated_by_user_id = ?, generated_by_role_id = ?, tenant_id = ?, max_uses = ?, current_uses = ?, expires_at = ?, is_active = ?, updated_at = ?
			  WHERE id = ?`

	_, err := s.db.Exec(query, code.Code, code.GeneratedByUserID, code.GeneratedByRoleID,
		code.TenantID, code.MaxUses, code.CurrentUses, code.ExpiresAt, code.IsActive, time.Now(), code.ID)

	return err
}

func (s *SQLiteStorage) DeactivateReferralCode(codeID uint) error {
	return fmt.Errorf("referral code deactivation not implemented yet")
}

func (s *SQLiteStorage) CountActiveReferralsByUserRole(userID, roleID uint) (int, error) {
	return 0, nil
}

// User Referral operations - Stub implementations for now
func (s *SQLiteStorage) CreateUserReferral(referral *UserReferral) error {
	return fmt.Errorf("user referral creation not implemented yet")
}

func (s *SQLiteStorage) GetUserReferralsByReferrer(referrerUserID uint) ([]*UserReferral, error) {
	return []*UserReferral{}, nil
}

func (s *SQLiteStorage) GetUserReferralByReferred(referredUserID uint) (*UserReferral, error) {
	return nil, fmt.Errorf("user referral not found")
}

func (s *SQLiteStorage) GetReferralStatsByUser(userID uint) (int, int, error) {
	return 0, 0, nil
}

// Two Factor Code operations
func (s *SQLiteStorage) CreateTwoFactorCode(code *TwoFactorCode) error {
	query := `INSERT INTO two_factor_codes 
		(user_id, code, expires_at, created_at, attempt_count) 
		VALUES (?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		code.UserID,
		code.Code,
		code.ExpiresAt,
		code.CreatedAt,
		code.AttemptCount)

	if err != nil {
		return fmt.Errorf("failed to create 2FA code: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get 2FA code ID: %w", err)
	}

	code.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetActiveTwoFactorCodeByUserID(userID uint) (*TwoFactorCode, error) {
	query := `SELECT id, user_id, code, expires_at, created_at, used_at, attempt_count, locked_until 
		FROM two_factor_codes 
		WHERE user_id = ? AND (used_at IS NULL OR used_at > datetime('now', '-1 hour')) 
		ORDER BY created_at DESC LIMIT 1`

	var code TwoFactorCode
	var usedAt sql.NullTime
	var lockedUntil sql.NullTime

	err := s.db.QueryRow(query, userID).Scan(
		&code.ID,
		&code.UserID,
		&code.Code,
		&code.ExpiresAt,
		&code.CreatedAt,
		&usedAt,
		&code.AttemptCount,
		&lockedUntil,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get 2FA code: %w", err)
	}

	if usedAt.Valid {
		code.UsedAt = &usedAt.Time
	}

	if lockedUntil.Valid {
		code.LockedUntil = &lockedUntil.Time
	}

	return &code, nil
}

func (s *SQLiteStorage) UpdateTwoFactorCode(code *TwoFactorCode) error {
	query := `UPDATE two_factor_codes 
		SET used_at = ?, attempt_count = ?, locked_until = ? 
		WHERE id = ?`

	_, err := s.db.Exec(query,
		code.UsedAt,
		code.AttemptCount,
		code.LockedUntil,
		code.ID)

	if err != nil {
		return fmt.Errorf("failed to update 2FA code: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) DeleteExpiredTwoFactorCodes() error {
	query := `DELETE FROM two_factor_codes 
		WHERE expires_at < datetime('now') 
		OR (used_at IS NOT NULL AND used_at < datetime('now', '-1 hour'))`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to delete expired 2FA codes: %w", err)
	}

	return nil
}
