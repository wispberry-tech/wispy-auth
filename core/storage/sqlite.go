package storage

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
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
	if err := migrateSQLiteIDs(context.Background(), db); err != nil {
		return nil, fmt.Errorf("failed to migrate SQLite IDs to UUIDs: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Apply schema (idempotent)
	if _, err := db.Exec(SQLiteSchemaSQL()); err != nil {
		return nil, fmt.Errorf("failed to apply schema: %w", err)
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
func (s *SQLiteStorage) CreateUser(ctx context.Context, user *User) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `INSERT INTO users (id, email, username, first_name, last_name, password_hash, avatar_url,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		id, user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash, user.AvatarURL,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	user.ID = id
	return nil
}

func (s *SQLiteStorage) GetUserByEmail(ctx context.Context, email, provider string) (*User, error) {
	user := &User{}
	query := `SELECT id, email, username, first_name, last_name, password_hash, avatar_url,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = ? AND provider = ?`

	err := s.db.QueryRowContext(ctx, query, email, provider).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.AvatarURL, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByEmailAnyProvider(ctx context.Context, email string) (*User, error) {
	user := &User{}
	query := `SELECT id, email, username, first_name, last_name, password_hash, avatar_url,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = ? ORDER BY provider = 'email' DESC`

	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.AvatarURL, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByProviderID(ctx context.Context, provider, providerID string) (*User, error) {
	user := &User{}
	query := `SELECT id, email, username, first_name, last_name, password_hash, avatar_url,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE provider = ? AND provider_id = ?`

	err := s.db.QueryRowContext(ctx, query, provider, providerID).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.AvatarURL, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by provider ID: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user := &User{}
	query := `SELECT id, email, username, first_name, last_name, password_hash, avatar_url,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE id = ?`

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.AvatarURL, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return user, nil
}

func (s *SQLiteStorage) UpdateUser(ctx context.Context, user *User) error {
	query := `UPDATE users SET email = ?, username = ?, first_name = ?, last_name = ?,
			  password_hash = ?, avatar_url = ?, provider = ?, provider_id = ?, email_verified = ?,
			  is_active = ?, is_suspended = ?, updated_at = ?
			  WHERE id = ?`

	_, err := s.db.ExecContext(ctx, query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash, user.AvatarURL,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended, time.Now(), user.ID)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// CreateUserWithSecurity creates a user and their security record in a transaction
func (s *SQLiteStorage) CreateUserWithSecurity(ctx context.Context, user *User, security *UserSecurity) error {
	userID, err := newUUID()
	if err != nil {
		return err
	}
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
	userQuery := `INSERT INTO users (id, email, username, first_name, last_name, password_hash, avatar_url,
				  provider, provider_id, email_verified, is_active, is_suspended,
				  created_at, updated_at)
				  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.ExecContext(ctx, userQuery,
		userID, user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash, user.AvatarURL,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user in transaction: %w", err)
	}

	user.ID = userID
	security.UserID = user.ID

	// Create user security record
	securityQuery := `INSERT INTO user_security (user_id, login_attempts, last_login_ip,
					  password_changed_at, force_password_change, two_factor_enabled,
					  created_at, updated_at)
					  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.ExecContext(ctx, securityQuery,
		security.UserID, security.LoginAttempts, security.LastLoginIP,
		security.PasswordChangedAt, security.ForcePasswordChange, security.TwoFactorEnabled,
		time.Now(), time.Now())

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
func (s *SQLiteStorage) CreateUserSecurity(ctx context.Context, security *UserSecurity) error {
	query := `INSERT INTO user_security (user_id, login_attempts, last_login_ip,
			  password_changed_at, force_password_change, two_factor_enabled,
			  created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	// Convert string IP pointer to sql.NullString to handle NULL properly
	var lastLoginIP sql.NullString
	if security.LastLoginIP != nil {
		lastLoginIP.String = *security.LastLoginIP
		lastLoginIP.Valid = true
	}

	_, err := s.db.ExecContext(ctx, query,
		security.UserID, security.LoginAttempts, lastLoginIP,
		security.PasswordChangedAt, security.ForcePasswordChange, security.TwoFactorEnabled,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user security: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) GetUserSecurity(ctx context.Context, userID uuid.UUID) (*UserSecurity, error) {
	security := &UserSecurity{}
	query := `SELECT user_id, login_attempts, locked_until, last_login_at, last_login_ip,
			  last_failed_login_at, last_failed_login_ip, password_changed_at,
			  force_password_change, two_factor_enabled, two_factor_secret,
			  two_factor_verified_at, created_at, updated_at
			  FROM user_security WHERE user_id = ?`

	// Use sql.NullString for nullable string fields
	var lastLoginIP, lastFailedLoginIP, twoFactorSecret sql.NullString

	err := s.db.QueryRowContext(ctx, query, userID).Scan(
		&security.UserID, &security.LoginAttempts, &security.LockedUntil,
		&security.LastLoginAt, &lastLoginIP, &security.LastFailedLoginAt,
		&lastFailedLoginIP, &security.PasswordChangedAt, &security.ForcePasswordChange,
		&security.TwoFactorEnabled, &twoFactorSecret,
		&security.TwoFactorVerifiedAt, &security.CreatedAt, &security.UpdatedAt)

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

	return security, nil
}

func (s *SQLiteStorage) UpdateUserSecurity(ctx context.Context, security *UserSecurity) error {
	query := `UPDATE user_security SET login_attempts = ?, locked_until = ?,
			  last_login_at = ?, last_login_ip = ?, last_failed_login_at = ?,
			  last_failed_login_ip = ?, password_changed_at = ?, force_password_change = ?,
			  two_factor_enabled = ?, two_factor_secret = ?,
			  two_factor_verified_at = ?, updated_at = ?
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

	_, err := s.db.ExecContext(ctx, query,
		security.LoginAttempts, security.LockedUntil, security.LastLoginAt,
		lastLoginIP, security.LastFailedLoginAt, lastFailedLoginIP,
		security.PasswordChangedAt, security.ForcePasswordChange, security.TwoFactorEnabled,
		security.TwoFactorSecret, security.TwoFactorVerifiedAt,
		time.Now(), security.UserID)

	if err != nil {
		return fmt.Errorf("failed to update user security: %w", err)
	}

	return nil
}

// Optimized security operations
func (s *SQLiteStorage) ResetLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE user_security SET login_attempts = 0, locked_until = NULL, updated_at = ?
			  WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress *string) error {
	query := `UPDATE user_security SET last_login_at = ?, last_login_ip = ?, updated_at = ?
			  WHERE user_id = ?`

	// Convert string IP pointer to sql.NullString to handle NULL properly
	var ip sql.NullString
	if ipAddress != nil {
		ip.String = *ipAddress
		ip.Valid = true
	}

	_, err := s.db.ExecContext(ctx, query, time.Now(), ip, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// Session operations
func (s *SQLiteStorage) CreateSession(ctx context.Context, session *Session) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `INSERT INTO sessions (id, token, user_id, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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

	_, err = s.db.ExecContext(ctx, query,
		id, session.Token, session.UserID, session.ExpiresAt, deviceFingerprint,
		userAgent, ipAddress, session.IsActive, session.LastAccessedAt,
		time.Now())

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	session.ID = id
	return nil
}

func (s *SQLiteStorage) GetSession(ctx context.Context, token string) (*Session, error) {
	session := &Session{}
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at
			  FROM sessions WHERE token = ? AND is_active = 1`

	// Use sql.NullString for nullable fields to handle NULL values
	var ipAddress, userAgent, deviceFingerprint sql.NullString

	err := s.db.QueryRowContext(ctx, query, token).Scan(
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

func (s *SQLiteStorage) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at
			  FROM sessions WHERE user_id = ? ORDER BY last_accessed_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
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

func (s *SQLiteStorage) UpdateSession(ctx context.Context, session *Session) error {
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

	_, err := s.db.ExecContext(ctx, query,
		session.ExpiresAt, deviceFingerprint, userAgent,
		ipAddress, session.IsActive, session.LastAccessedAt, session.ID)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM sessions WHERE user_id = ?`
	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at < ? OR is_active = 0`
	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

// OAuth state operations
func (s *SQLiteStorage) StoreOAuthState(ctx context.Context, state *OAuthState) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `INSERT INTO oauth_states (id, state, provider, redirect_url, expires_at, created_at)
			  VALUES (?, ?, ?, ?, ?, ?)`

	// Convert string to sql.NullString to handle NULL properly
	var redirectURL sql.NullString
	if state.RedirectURL != "" {
		redirectURL.String = state.RedirectURL
		redirectURL.Valid = true
	}

	_, err = s.db.ExecContext(ctx, query,
		id, state.State, state.Provider, redirectURL,
		state.ExpiresAt, time.Now())

	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	state.ID = id
	return nil
}

func (s *SQLiteStorage) GetOAuthState(ctx context.Context, state string) (*OAuthState, error) {
	oauthState := &OAuthState{}
	query := `SELECT id, state, provider, redirect_url, expires_at, created_at
			  FROM oauth_states WHERE state = ?`

	// Use sql.NullString for redirect_url to handle NULL values
	var redirectURL sql.NullString

	err := s.db.QueryRowContext(ctx, query, state).Scan(
		&oauthState.ID, &oauthState.State, &oauthState.Provider,
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

func (s *SQLiteStorage) DeleteOAuthState(ctx context.Context, state string) error {
	query := `DELETE FROM oauth_states WHERE state = ?`
	_, err := s.db.ExecContext(ctx, query, state)
	if err != nil {
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}
	return nil
}

// Security Event operations
func (s *SQLiteStorage) CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `INSERT INTO security_events (id, user_id, event_type, description,
			  ip_address, user_agent, device_fingerprint, severity,
			  success, metadata, created_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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

	_, err = s.db.ExecContext(ctx, query,
		id, event.UserID, event.EventType, description, ipAddress,
		userAgent, deviceFingerprint, event.Severity,
		event.Success, metadata, time.Now())

	if err != nil {
		return fmt.Errorf("failed to create security event: %w", err)
	}

	event.ID = id
	return nil
}

// HandleFailedLogin atomically increments login attempts and locks account if needed
func (s *SQLiteStorage) HandleFailedLogin(ctx context.Context, userID uuid.UUID, maxAttempts int, lockoutDuration time.Duration) (bool, error) {
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

	err = tx.QueryRowContext(ctx, incrementQuery, time.Now(), userID).Scan(&currentAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to increment login attempts: %w", err)
	}

	// Check if we need to lock the account
	wasLocked := false
	if currentAttempts >= maxAttempts {
		lockUntil := time.Now().Add(lockoutDuration)
		lockQuery := `UPDATE user_security SET locked_until = ?, updated_at = ? WHERE user_id = ?`

		_, err = tx.ExecContext(ctx, lockQuery, lockUntil, time.Now(), userID)
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
func (s *SQLiteStorage) CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `
		INSERT INTO password_reset_tokens (id, user_id, token, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query, id, token.UserID, token.Token, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}
	token.ID = id

	return nil
}

func (s *SQLiteStorage) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token = ? AND used_at IS NULL AND expires_at > ?`

	var resetToken PasswordResetToken
	var usedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, token, time.Now()).Scan(
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

func (s *SQLiteStorage) UsePasswordResetToken(ctx context.Context, token string) error {
	query := `UPDATE password_reset_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL`

	result, err := s.db.ExecContext(ctx, query, time.Now(), token)
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

func (s *SQLiteStorage) CleanupExpiredPasswordResetTokens(ctx context.Context) error {
	query := `DELETE FROM password_reset_tokens WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)`

	cutoffTime := time.Now().Add(-24 * time.Hour) // Keep used tokens for 24 hours

	_, err := s.db.ExecContext(ctx, query, time.Now(), cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired password reset tokens: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) CleanupExpiredOAuthStates(ctx context.Context) error {
	query := `DELETE FROM oauth_states WHERE expires_at < ?`

	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired OAuth states: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) CleanupExpired2FACodes(ctx context.Context) error {
	query := `DELETE FROM two_factor_codes WHERE expires_at < ?`

	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired 2FA codes: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) CleanupExpiredRefreshTokens(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < ?`

	_, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired refresh tokens: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) Create2FACode(ctx context.Context, code *TwoFactorCode) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `INSERT INTO two_factor_codes (id, user_id, code, code_type, expires_at, created_at)
			  VALUES (?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		id, code.UserID, code.Code, code.CodeType, code.ExpiresAt, code.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create 2FA code: %w", err)
	}

	code.ID = id
	return nil
}

func (s *SQLiteStorage) Get2FACode(ctx context.Context, userID uuid.UUID, code string, codeType string) (*TwoFactorCode, error) {
	query := `SELECT id, user_id, code, code_type, expires_at, used_at, created_at
			  FROM two_factor_codes
			  WHERE user_id = ? AND code = ? AND code_type = ?`

	var twoFactorCode TwoFactorCode
	var usedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, userID, code, codeType).Scan(
		&twoFactorCode.ID,
		&twoFactorCode.UserID,
		&twoFactorCode.Code,
		&twoFactorCode.CodeType,
		&twoFactorCode.ExpiresAt,
		&usedAt,
		&twoFactorCode.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get 2FA code: %w", err)
	}

	if usedAt.Valid {
		twoFactorCode.UsedAt = &usedAt.Time
	}

	return &twoFactorCode, nil
}

func (s *SQLiteStorage) GetLatestPending2FACode(ctx context.Context, code string, codeType string) (*TwoFactorCode, error) {
	query := `SELECT id, user_id, code, code_type, expires_at, used_at, created_at
			  FROM two_factor_codes
			  WHERE code = ? AND used_at IS NULL AND code_type = ?
			  ORDER BY created_at DESC
			  LIMIT 1`

	var twoFactorCode TwoFactorCode
	var usedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, code, codeType).Scan(
		&twoFactorCode.ID,
		&twoFactorCode.UserID,
		&twoFactorCode.Code,
		&twoFactorCode.CodeType,
		&twoFactorCode.ExpiresAt,
		&usedAt,
		&twoFactorCode.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get latest pending 2FA code: %w", err)
	}

	if usedAt.Valid {
		twoFactorCode.UsedAt = &usedAt.Time
	}

	return &twoFactorCode, nil
}

func (s *SQLiteStorage) Use2FACode(ctx context.Context, userID uuid.UUID, code string) error {
	query := `UPDATE two_factor_codes SET used_at = ? WHERE user_id = ? AND code = ? AND used_at IS NULL`

	_, err := s.db.ExecContext(ctx, query, time.Now(), userID, code)
	if err != nil {
		return fmt.Errorf("failed to use 2FA code: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) Create2FABackupCode(ctx context.Context, code *TwoFactorBackupCode) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `INSERT INTO two_factor_backup_codes (id, user_id, code, created_at) VALUES (?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query, id, code.UserID, code.Code, code.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create 2FA backup code: %w", err)
	}

	code.ID = id
	return nil
}

func (s *SQLiteStorage) Get2FABackupCodes(ctx context.Context, userID uuid.UUID) ([]*TwoFactorBackupCode, error) {
	query := `SELECT id, user_id, code, used_at, created_at
			  FROM two_factor_backup_codes
			  WHERE user_id = ?
			  ORDER BY id`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get 2FA backup codes: %w", err)
	}
	defer rows.Close()

	var codes []*TwoFactorBackupCode
	for rows.Next() {
		var code TwoFactorBackupCode
		var usedAt sql.NullTime

		err := rows.Scan(&code.ID, &code.UserID, &code.Code, &usedAt, &code.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan 2FA backup code: %w", err)
		}

		if usedAt.Valid {
			code.UsedAt = &usedAt.Time
		}

		codes = append(codes, &code)
	}

	return codes, nil
}

func (s *SQLiteStorage) GetBackupCodeByCode(ctx context.Context, code string) (*TwoFactorBackupCode, error) {
	query := `SELECT id, user_id, code, used_at, created_at
			  FROM two_factor_backup_codes
			  WHERE code = ? AND used_at IS NULL`

	var backupCode TwoFactorBackupCode
	var usedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, code).Scan(
		&backupCode.ID,
		&backupCode.UserID,
		&backupCode.Code,
		&usedAt,
		&backupCode.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get 2FA backup code: %w", err)
	}

	if usedAt.Valid {
		backupCode.UsedAt = &usedAt.Time
	}

	return &backupCode, nil
}

func (s *SQLiteStorage) Use2FABackupCode(ctx context.Context, userID uuid.UUID, code string) error {
	query := `UPDATE two_factor_backup_codes SET used_at = ? WHERE user_id = ? AND code = ? AND used_at IS NULL`

	result, err := s.db.ExecContext(ctx, query, time.Now(), userID, code)
	if err != nil {
		return fmt.Errorf("failed to use 2FA backup code: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("2FA backup code not found or already used")
	}

	return nil
}

func (s *SQLiteStorage) Regenerate2FABackupCodes(ctx context.Context, userID uuid.UUID) ([]*TwoFactorBackupCode, error) {
	// Delete old backup codes
	if _, err := s.db.ExecContext(ctx, "DELETE FROM two_factor_backup_codes WHERE user_id = ?", userID); err != nil {
		return nil, fmt.Errorf("failed to delete old 2FA backup codes: %w", err)
	}

	// Create new backup codes
	backupCodes := make([]*TwoFactorBackupCode, 0, 10)
	for i := 0; i < 10; i++ {
		code, err := GenerateNumericCode(12)
		if err != nil {
			return nil, fmt.Errorf("failed to generate 2FA backup code: %w", err)
		}

		backupCode := &TwoFactorBackupCode{
			UserID:    userID,
			Code:      code,
			CreatedAt: time.Now(),
		}

		if err := s.Create2FABackupCode(ctx, backupCode); err != nil {
			return nil, fmt.Errorf("failed to create 2FA backup code: %w", err)
		}

		backupCodes = append(backupCodes, backupCode)
	}

	return backupCodes, nil
}

func (s *SQLiteStorage) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	query := `INSERT INTO refresh_tokens (id, token, user_id, session_id, expires_at, created_at)
			  VALUES (?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		id, token.Token, token.UserID, token.SessionID, token.ExpiresAt, token.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}

	token.ID = id
	return nil
}

func (s *SQLiteStorage) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	query := `SELECT id, token, user_id, session_id, expires_at, created_at, last_used_at
			  FROM refresh_tokens
			  WHERE token = ?`

	var refreshToken RefreshToken
	var lastUsedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, token).Scan(
		&refreshToken.ID,
		&refreshToken.Token,
		&refreshToken.UserID,
		&refreshToken.SessionID,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
		&lastUsedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if lastUsedAt.Valid {
		refreshToken.LastUsedAt = &lastUsedAt.Time
	}

	return &refreshToken, nil
}

func (s *SQLiteStorage) UpdateRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `UPDATE refresh_tokens SET session_id = ?, last_used_at = ? WHERE token = ?`

	_, err := s.db.ExecContext(ctx, query, token.SessionID, time.Now(), token.Token)
	if err != nil {
		return fmt.Errorf("failed to update refresh token: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = ?`

	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) DeleteUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = ?`

	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user refresh tokens: %w", err)
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
