package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
	. "github.com/wispberry-tech/wispy-auth/core"
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

// GetDB returns the underlying database connection for sharing with extensions
func (s *SQLiteStorage) GetDB() (*sql.DB, error) {
	return s.db, nil
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

	if id <= 0 || id > 1<<31-1 { // Check for valid positive ID within uint range
		return fmt.Errorf("invalid user ID: %d", id)
	}
	user.ID = uint(id)

	// Retrieve the generated UUID
	err = s.db.QueryRow("SELECT uuid FROM users WHERE id = ?", user.ID).Scan(&user.UUID)
	if err != nil {
		return fmt.Errorf("failed to get user UUID: %w", err)
	}

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

// CreateUserWithSecurity creates a user and their security record in a transaction
func (s *SQLiteStorage) CreateUserWithSecurity(user *User, security *UserSecurity) error {
	// Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Rollback transaction if we exit with an error
	defer func() {
		if err != nil {
			tx.Rollback() // #nosec G104 - Rollback error can be ignored in defer cleanup
		}
	}()

	// Create user first
	userQuery := `INSERT INTO users (email, username, first_name, last_name, password_hash,
				  provider, provider_id, email_verified, is_active, is_suspended,
				  created_at, updated_at)
				  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := tx.Exec(userQuery,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user in transaction: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get user ID: %w", err)
	}

	if id <= 0 || id > 1<<31-1 { // Check for valid positive ID within uint range
		return fmt.Errorf("invalid user ID: %d", id)
	}
	user.ID = uint(id)
	security.UserID = user.ID

	// Retrieve the generated UUID
	err = tx.QueryRow("SELECT uuid FROM users WHERE id = ?", user.ID).Scan(&user.UUID)
	if err != nil {
		return fmt.Errorf("failed to get user UUID: %w", err)
	}

	// Create user security record
	securityQuery := `INSERT INTO user_security (user_id, login_attempts, last_login_ip,
					  password_changed_at, force_password_change, two_factor_enabled,
					  concurrent_sessions, security_version, risk_score, suspicious_activity_count,
					  created_at, updated_at)
					  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.Exec(securityQuery,
		security.UserID, security.LoginAttempts, security.LastLoginIP,
		security.PasswordChangedAt, security.ForcePasswordChange, security.TwoFactorEnabled,
		security.ConcurrentSessions, security.SecurityVersion, security.RiskScore,
		security.SuspiciousActivityCount, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user security in transaction: %w", err)
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
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

	// Convert string IP pointer to sql.NullString to handle NULL properly
	var lastLoginIP sql.NullString
	if security.LastLoginIP != nil {
		lastLoginIP.String = *security.LastLoginIP
		lastLoginIP.Valid = true
	}

	_, err := s.db.Exec(query,
		security.UserID, security.LoginAttempts, lastLoginIP,
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

	// Use sql.NullString for nullable string fields
	var lastLoginIP, lastFailedLoginIP, twoFactorSecret, twoFactorBackupCodes sql.NullString
	var lastSessionToken, deviceFingerprint, knownDevices sql.NullString

	err := s.db.QueryRow(query, userID).Scan(
		&security.UserID, &security.LoginAttempts, &security.LockedUntil,
		&security.LastLoginAt, &lastLoginIP, &security.LastFailedLoginAt,
		&lastFailedLoginIP, &security.PasswordChangedAt, &security.ForcePasswordChange,
		&security.TwoFactorEnabled, &twoFactorSecret, &twoFactorBackupCodes,
		&security.TwoFactorVerifiedAt, &security.ConcurrentSessions, &lastSessionToken,
		&deviceFingerprint, &knownDevices, &security.SecurityVersion,
		&security.RiskScore, &security.SuspiciousActivityCount, &security.CreatedAt, &security.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user security: %w", err)
	}

	// Convert sql.NullString back to *string or string
	if lastLoginIP.Valid {
		security.LastLoginIP = &lastLoginIP.String
	}
	if lastFailedLoginIP.Valid {
		security.LastFailedLoginIP = &lastFailedLoginIP.String
	}
	if twoFactorSecret.Valid {
		security.TwoFactorSecret = twoFactorSecret.String
	}
	if twoFactorBackupCodes.Valid {
		security.TwoFactorBackupCodes = twoFactorBackupCodes.String
	}
	if lastSessionToken.Valid {
		security.LastSessionToken = lastSessionToken.String
	}
	if deviceFingerprint.Valid {
		security.DeviceFingerprint = deviceFingerprint.String
	}
	if knownDevices.Valid {
		security.KnownDevices = knownDevices.String
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

	// Convert string IP pointers to sql.NullString to handle NULL properly
	var lastLoginIP, lastFailedLoginIP sql.NullString
	if security.LastLoginIP != nil {
		lastLoginIP.String = *security.LastLoginIP
		lastLoginIP.Valid = true
	}
	if security.LastFailedLoginIP != nil {
		lastFailedLoginIP.String = *security.LastFailedLoginIP
		lastFailedLoginIP.Valid = true
	}

	_, err := s.db.Exec(query,
		security.LoginAttempts, security.LockedUntil, security.LastLoginAt,
		lastLoginIP, security.LastFailedLoginAt, lastFailedLoginIP,
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

func (s *SQLiteStorage) UpdateLastLogin(userID uint, ipAddress *string) error {
	query := `UPDATE user_security SET last_login_at = ?, last_login_ip = ?, updated_at = ?
			  WHERE user_id = ?`

	// Convert string IP pointer to sql.NullString to handle NULL properly
	var ip sql.NullString
	if ipAddress != nil {
		ip.String = *ipAddress
		ip.Valid = true
	}

	_, err := s.db.Exec(query, time.Now(), ip, time.Now(), userID)
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

	// Convert strings to sql.NullString to handle NULL properly
	var ipAddress, userAgent, deviceFingerprint sql.NullString
	if session.IPAddress != "" {
		ipAddress.String = session.IPAddress
		ipAddress.Valid = true
	}
	if session.UserAgent != "" {
		userAgent.String = session.UserAgent
		userAgent.Valid = true
	}
	if session.DeviceFingerprint != "" {
		deviceFingerprint.String = session.DeviceFingerprint
		deviceFingerprint.Valid = true
	}

	result, err := s.db.Exec(query,
		session.Token, session.UserID, session.ExpiresAt, deviceFingerprint,
		userAgent, ipAddress, session.IsActive, session.LastAccessedAt,
		time.Now())

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get session ID: %w", err)
	}

	if id <= 0 || id > 1<<31-1 { // Check for valid positive ID within uint range
		return fmt.Errorf("invalid session ID: %d", id)
	}
	session.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetSession(token string) (*Session, error) {
	session := &Session{}
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at
			  FROM sessions WHERE token = ? AND is_active = 1`

	// Use sql.NullString for nullable fields to handle NULL values
	var ipAddress, userAgent, deviceFingerprint sql.NullString

	err := s.db.QueryRow(query, token).Scan(
		&session.ID, &session.UserID, &session.Token, &session.ExpiresAt,
		&deviceFingerprint, &userAgent, &ipAddress,
		&session.IsActive, &session.LastAccessedAt, &session.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Convert sql.NullString back to string
	if ipAddress.Valid {
		session.IPAddress = ipAddress.String
	}
	if userAgent.Valid {
		session.UserAgent = userAgent.String
	}
	if deviceFingerprint.Valid {
		session.DeviceFingerprint = deviceFingerprint.String
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
		// Use sql.NullString for nullable fields to handle NULL values
		var ipAddress, userAgent, deviceFingerprint sql.NullString

		err := rows.Scan(
			&session.ID, &session.UserID, &session.Token, &session.ExpiresAt,
			&deviceFingerprint, &userAgent, &ipAddress,
			&session.IsActive, &session.LastAccessedAt, &session.CreatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		// Convert sql.NullString back to string
		if ipAddress.Valid {
			session.IPAddress = ipAddress.String
		}
		if userAgent.Valid {
			session.UserAgent = userAgent.String
		}
		if deviceFingerprint.Valid {
			session.DeviceFingerprint = deviceFingerprint.String
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (s *SQLiteStorage) UpdateSession(session *Session) error {
	query := `UPDATE sessions SET expires_at = ?, device_fingerprint = ?,
			  user_agent = ?, ip_address = ?, is_active = ?, last_accessed_at = ?
			  WHERE id = ?`

	// Convert strings to sql.NullString to handle NULL properly
	var ipAddress, userAgent, deviceFingerprint sql.NullString
	if session.IPAddress != "" {
		ipAddress.String = session.IPAddress
		ipAddress.Valid = true
	}
	if session.UserAgent != "" {
		userAgent.String = session.UserAgent
		userAgent.Valid = true
	}
	if session.DeviceFingerprint != "" {
		deviceFingerprint.String = session.DeviceFingerprint
		deviceFingerprint.Valid = true
	}

	_, err := s.db.Exec(query,
		session.ExpiresAt, deviceFingerprint, userAgent,
		ipAddress, session.IsActive, session.LastAccessedAt, session.ID)

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

	// Convert string to sql.NullString to handle NULL properly
	var redirectURL sql.NullString
	if state.RedirectURL != "" {
		redirectURL.String = state.RedirectURL
		redirectURL.Valid = true
	}

	result, err := s.db.Exec(query,
		state.State, state.CSRF, state.Provider, redirectURL,
		state.ExpiresAt, time.Now())

	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get OAuth state ID: %w", err)
	}

	if id <= 0 || id > 1<<31-1 { // Check for valid positive ID within uint range
		return fmt.Errorf("invalid OAuth state ID: %d", id)
	}
	state.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetOAuthState(state string) (*OAuthState, error) {
	oauthState := &OAuthState{}
	query := `SELECT id, state, csrf, provider, redirect_url, expires_at, created_at
			  FROM oauth_states WHERE state = ?`

	// Use sql.NullString for redirect_url to handle NULL values
	var redirectURL sql.NullString

	err := s.db.QueryRow(query, state).Scan(
		&oauthState.ID, &oauthState.State, &oauthState.CSRF, &oauthState.Provider,
		&redirectURL, &oauthState.ExpiresAt, &oauthState.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	// Convert sql.NullString back to string
	if redirectURL.Valid {
		oauthState.RedirectURL = redirectURL.String
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

	// Convert strings to sql.NullString to handle NULL properly
	var ipAddress, description, userAgent, deviceFingerprint, metadata sql.NullString
	if event.IPAddress != "" {
		ipAddress.String = event.IPAddress
		ipAddress.Valid = true
	}
	if event.Description != "" {
		description.String = event.Description
		description.Valid = true
	}
	if event.UserAgent != "" {
		userAgent.String = event.UserAgent
		userAgent.Valid = true
	}
	if event.DeviceFingerprint != "" {
		deviceFingerprint.String = event.DeviceFingerprint
		deviceFingerprint.Valid = true
	}
	if event.Metadata != "" {
		metadata.String = event.Metadata
		metadata.Valid = true
	}

	result, err := s.db.Exec(query,
		event.UserID, event.EventType, description, ipAddress,
		userAgent, deviceFingerprint, event.Severity,
		event.Success, metadata, time.Now())

	if err != nil {
		return fmt.Errorf("failed to create security event: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get security event ID: %w", err)
	}

	if id <= 0 || id > 1<<31-1 { // Check for valid positive ID within uint range
		return fmt.Errorf("invalid security event ID: %d", id)
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
		// Use sql.NullString for nullable fields to handle NULL values
		var ipAddress, description, userAgent, deviceFingerprint, metadata sql.NullString

		err := rows.Scan(
			&event.ID, &event.UserID, &event.EventType, &description,
			&ipAddress, &userAgent, &deviceFingerprint,
			&event.Severity, &event.Success, &metadata, &event.CreatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan security event: %w", err)
		}

		// Convert sql.NullString back to string
		if ipAddress.Valid {
			event.IPAddress = ipAddress.String
		}
		if description.Valid {
			event.Description = description.String
		}
		if userAgent.Valid {
			event.UserAgent = userAgent.String
		}
		if deviceFingerprint.Valid {
			event.DeviceFingerprint = deviceFingerprint.String
		}
		if metadata.Valid {
			event.Metadata = metadata.String
		}

		events = append(events, event)
	}

	return events, nil
}

func (s *SQLiteStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return s.GetSecurityEvents(&userID, "", limit, offset)
}

// HandleFailedLogin atomically increments login attempts and locks account if needed
func (s *SQLiteStorage) HandleFailedLogin(userID uint, maxAttempts int, lockoutDuration time.Duration) (bool, error) {
	// Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Rollback transaction if we exit with an error
	defer func() {
		if err != nil {
			tx.Rollback() // #nosec G104 - Rollback error can be ignored in defer cleanup
		}
	}()

	// Increment login attempts and get current count
	var currentAttempts int
	incrementQuery := `UPDATE user_security SET login_attempts = login_attempts + 1, updated_at = ?
					   WHERE user_id = ? RETURNING login_attempts`

	err = tx.QueryRow(incrementQuery, time.Now(), userID).Scan(&currentAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to increment login attempts: %w", err)
	}

	// Check if we need to lock the account
	wasLocked := false
	if currentAttempts >= maxAttempts {
		lockUntil := time.Now().Add(lockoutDuration)
		lockQuery := `UPDATE user_security SET locked_until = ?, updated_at = ? WHERE user_id = ?`

		_, err = tx.Exec(lockQuery, lockUntil, time.Now(), userID)
		if err != nil {
			return false, fmt.Errorf("failed to lock user account: %w", err)
		}
		wasLocked = true
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return false, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return wasLocked, nil
}

// Password Reset Token operations
func (s *SQLiteStorage) CreatePasswordResetToken(token *PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at)
		VALUES (?, ?, ?, ?)`

	_, err := s.db.Exec(query, token.UserID, token.Token, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetPasswordResetToken(token string) (*PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token = ? AND used_at IS NULL AND expires_at > ?`

	var resetToken PasswordResetToken
	var usedAt sql.NullTime

	err := s.db.QueryRow(query, token, time.Now()).Scan(
		&resetToken.ID,
		&resetToken.UserID,
		&resetToken.Token,
		&resetToken.ExpiresAt,
		&usedAt,
		&resetToken.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("password reset token not found or expired")
		}
		return nil, fmt.Errorf("failed to get password reset token: %w", err)
	}

	if usedAt.Valid {
		resetToken.UsedAt = &usedAt.Time
	}

	return &resetToken, nil
}

func (s *SQLiteStorage) UsePasswordResetToken(token string) error {
	query := `UPDATE password_reset_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL`

	result, err := s.db.Exec(query, time.Now(), token)
	if err != nil {
		return fmt.Errorf("failed to use password reset token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("password reset token not found or already used")
	}

	return nil
}

func (s *SQLiteStorage) CleanupExpiredPasswordResetTokens() error {
	query := `DELETE FROM password_reset_tokens WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)`

	cutoffTime := time.Now().Add(-24 * time.Hour) // Keep used tokens for 24 hours

	_, err := s.db.Exec(query, time.Now(), cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired password reset tokens: %w", err)
	}

	return nil
}

// Health check
func (s *SQLiteStorage) Ping() error {
	return s.db.Ping()
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}
