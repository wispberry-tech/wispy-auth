package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/wispberry-tech/wispy-auth/core"
	. "github.com/wispberry-tech/wispy-auth/core"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

// SQLiteStorage is a production-ready SQLite storage implementation for core auth
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

	// Auto-create missing tables
	schemaManager := core.NewSchemaManager(db, "sqlite")
	if err := schemaManager.EnsureCoreSchema(); err != nil {
		return nil, fmt.Errorf("failed to ensure core schema: %w", err)
	}

	return s, nil
}

// NewInMemorySQLiteStorage creates a new in-memory SQLite storage instance for testing
func NewInMemorySQLiteStorage() (*SQLiteStorage, error) {
	// Create in-memory database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory SQLite database: %w", err)
	}

	// Use the common initialization which includes auto-schema creation
	return NewSQLiteStorageFromDB(db)
}

// User operations
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
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = ? AND provider = ?`

	err := s.db.QueryRow(query, email, provider).Scan(
		&user.ID, &user.UUID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = ?`

	err := s.db.QueryRow(query, email).Scan(
		&user.ID, &user.UUID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE provider = ? AND provider_id = ?`

	err := s.db.QueryRow(query, provider, providerID).Scan(
		&user.ID, &user.UUID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by provider ID: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByID(id uint) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE id = ?`

	err := s.db.QueryRow(query, id).Scan(
		&user.ID, &user.UUID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByUUID(uuid string) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE uuid = ?`

	err := s.db.QueryRow(query, uuid).Scan(
		&user.ID, &user.UUID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by UUID: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) UpdateUser(user *User) error {
	query := `UPDATE users SET email = ?, username = ?, first_name = ?, last_name = ?,
			  password_hash = ?, provider = ?, provider_id = ?, email_verified = ?,
			  is_active = ?, is_suspended = ?, updated_at = ?
			  WHERE id = ?`

	_, err := s.db.Exec(query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended, time.Now(), user.ID)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// User Security operations
func (s *SQLiteStorage) CreateUserSecurity(security *UserSecurity) error {
	query := `INSERT INTO user_security (user_id, login_attempts, last_login_ip,
			  password_changed_at, force_password_change, two_factor_enabled,
			  concurrent_sessions, security_version, risk_score, suspicious_activity_count,
			  created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		security.UserID, security.LoginAttempts, security.LastLoginIP,
		security.PasswordChangedAt, security.ForcePasswordChange, security.TwoFactorEnabled,
		security.ConcurrentSessions, security.SecurityVersion, security.RiskScore,
		security.SuspiciousActivityCount, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user security: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetUserSecurity(userID uint) (*UserSecurity, error) {
	security := &UserSecurity{}
	query := `SELECT user_id, login_attempts, locked_until, last_login_at, last_login_ip,
			  last_failed_login_at, last_failed_login_ip, password_changed_at,
			  force_password_change, two_factor_enabled, two_factor_secret,
			  two_factor_backup_codes, two_factor_verified_at, concurrent_sessions,
			  last_session_token, device_fingerprint, known_devices,
			  security_version, risk_score, suspicious_activity_count,
			  created_at, updated_at
			  FROM user_security WHERE user_id = ?`

	err := s.db.QueryRow(query, userID).Scan(
		&security.UserID, &security.LoginAttempts, &security.LockedUntil,
		&security.LastLoginAt, &security.LastLoginIP, &security.LastFailedLoginAt,
		&security.LastFailedLoginIP, &security.PasswordChangedAt, &security.ForcePasswordChange,
		&security.TwoFactorEnabled, &security.TwoFactorSecret, &security.TwoFactorBackupCodes,
		&security.TwoFactorVerifiedAt, &security.ConcurrentSessions, &security.LastSessionToken,
		&security.DeviceFingerprint, &security.KnownDevices, &security.SecurityVersion,
		&security.RiskScore, &security.SuspiciousActivityCount, &security.CreatedAt, &security.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user security: %w", err)
	}

	return security, nil
}

func (s *SQLiteStorage) UpdateUserSecurity(security *UserSecurity) error {
	query := `UPDATE user_security SET login_attempts = ?, locked_until = ?,
			  last_login_at = ?, last_login_ip = ?, last_failed_login_at = ?,
			  last_failed_login_ip = ?, password_changed_at = ?, force_password_change = ?,
			  two_factor_enabled = ?, two_factor_secret = ?, two_factor_backup_codes = ?,
			  two_factor_verified_at = ?, concurrent_sessions = ?, last_session_token = ?,
			  device_fingerprint = ?, known_devices = ?, security_version = ?,
			  risk_score = ?, suspicious_activity_count = ?, updated_at = ?
			  WHERE user_id = ?`

	_, err := s.db.Exec(query,
		security.LoginAttempts, security.LockedUntil, security.LastLoginAt,
		security.LastLoginIP, security.LastFailedLoginAt, security.LastFailedLoginIP,
		security.PasswordChangedAt, security.ForcePasswordChange, security.TwoFactorEnabled,
		security.TwoFactorSecret, security.TwoFactorBackupCodes, security.TwoFactorVerifiedAt,
		security.ConcurrentSessions, security.LastSessionToken, security.DeviceFingerprint,
		security.KnownDevices, security.SecurityVersion, security.RiskScore,
		security.SuspiciousActivityCount, time.Now(), security.UserID)

	if err != nil {
		return fmt.Errorf("failed to update user security: %w", err)
	}

	return nil
}

// Optimized security operations
func (s *SQLiteStorage) IncrementLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = login_attempts + 1, updated_at = ?
			  WHERE user_id = ?`
	_, err := s.db.Exec(query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to increment login attempts: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) ResetLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = 0, locked_until = NULL, updated_at = ?
			  WHERE user_id = ?`
	_, err := s.db.Exec(query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) SetUserLocked(userID uint, until time.Time) error {
	query := `UPDATE user_security SET locked_until = ?, updated_at = ?
			  WHERE user_id = ?`
	_, err := s.db.Exec(query, until, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to set user locked: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) UpdateLastLogin(userID uint, ipAddress string) error {
	query := `UPDATE user_security SET last_login_at = ?, last_login_ip = ?, updated_at = ?
			  WHERE user_id = ?`
	_, err := s.db.Exec(query, time.Now(), ipAddress, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// Session operations
func (s *SQLiteStorage) CreateSession(session *Session) error {
	query := `INSERT INTO sessions (token, user_id, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		session.Token, session.UserID, session.ExpiresAt, session.DeviceFingerprint,
		session.UserAgent, session.IPAddress, session.IsActive, session.LastAccessedAt,
		time.Now())

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get session ID: %w", err)
	}

	session.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetSession(token string) (*Session, error) {
	session := &Session{}
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at
			  FROM sessions WHERE token = ? AND is_active = 1`

	err := s.db.QueryRow(query, token).Scan(
		&session.ID, &session.UserID, &session.Token, &session.ExpiresAt,
		&session.DeviceFingerprint, &session.UserAgent, &session.IPAddress,
		&session.IsActive, &session.LastAccessedAt, &session.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

func (s *SQLiteStorage) GetUserSessions(userID uint) ([]*Session, error) {
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at
			  FROM sessions WHERE user_id = ? ORDER BY last_accessed_at DESC`

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
			&session.IsActive, &session.LastAccessedAt, &session.CreatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (s *SQLiteStorage) UpdateSession(session *Session) error {
	query := `UPDATE sessions SET expires_at = ?, device_fingerprint = ?,
			  user_agent = ?, ip_address = ?, is_active = ?, last_accessed_at = ?
			  WHERE id = ?`

	_, err := s.db.Exec(query,
		session.ExpiresAt, session.DeviceFingerprint, session.UserAgent,
		session.IPAddress, session.IsActive, session.LastAccessedAt, session.ID)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) DeleteSession(token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := s.db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) DeleteUserSessions(userID uint) error {
	query := `DELETE FROM sessions WHERE user_id = ?`
	_, err := s.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) CleanupExpiredSessions() error {
	query := `DELETE FROM sessions WHERE expires_at < ? OR is_active = 0`
	_, err := s.db.Exec(query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) CountActiveSessions(userID uint) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM sessions WHERE user_id = ? AND is_active = 1 AND expires_at > ?`
	err := s.db.QueryRow(query, userID, time.Now()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}
	return count, nil
}

// OAuth state operations
func (s *SQLiteStorage) StoreOAuthState(state *OAuthState) error {
	query := `INSERT INTO oauth_states (state, csrf, provider, redirect_url, expires_at, created_at)
			  VALUES (?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		state.State, state.CSRF, state.Provider, state.RedirectURL,
		state.ExpiresAt, time.Now())

	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get OAuth state ID: %w", err)
	}

	state.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetOAuthState(state string) (*OAuthState, error) {
	oauthState := &OAuthState{}
	query := `SELECT id, state, csrf, provider, redirect_url, expires_at, created_at
			  FROM oauth_states WHERE state = ?`

	err := s.db.QueryRow(query, state).Scan(
		&oauthState.ID, &oauthState.State, &oauthState.CSRF, &oauthState.Provider,
		&oauthState.RedirectURL, &oauthState.ExpiresAt, &oauthState.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	return oauthState, nil
}

func (s *SQLiteStorage) DeleteOAuthState(state string) error {
	query := `DELETE FROM oauth_states WHERE state = ?`
	_, err := s.db.Exec(query, state)
	if err != nil {
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}
	return nil
}

// Security Event operations
func (s *SQLiteStorage) CreateSecurityEvent(event *SecurityEvent) error {
	query := `INSERT INTO security_events (user_id, event_type, description,
			  ip_address, user_agent, device_fingerprint, severity,
			  success, metadata, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		event.UserID, event.EventType, event.Description, event.IPAddress,
		event.UserAgent, event.DeviceFingerprint, event.Severity,
		event.Success, event.Metadata, time.Now())

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

func (s *SQLiteStorage) GetSecurityEvents(userID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	query := `SELECT id, user_id, event_type, description, ip_address,
			  user_agent, device_fingerprint, severity, success, metadata, created_at
			  FROM security_events WHERE 1=1`
	args := []interface{}{}

	if userID != nil {
		query += ` AND user_id = ?`
		args = append(args, *userID)
	}

	if eventType != "" {
		query += ` AND event_type = ?`
		args = append(args, eventType)
	}

	query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}
	defer rows.Close()

	var events []*SecurityEvent
	for rows.Next() {
		event := &SecurityEvent{}
		err := rows.Scan(
			&event.ID, &event.UserID, &event.EventType, &event.Description,
			&event.IPAddress, &event.UserAgent, &event.DeviceFingerprint,
			&event.Severity, &event.Success, &event.Metadata, &event.CreatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan security event: %w", err)
		}
		events = append(events, event)
	}

	return events, nil
}

func (s *SQLiteStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return s.GetSecurityEvents(&userID, "", limit, offset)
}

// Health check
func (s *SQLiteStorage) Ping() error {
	return s.db.Ping()
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}