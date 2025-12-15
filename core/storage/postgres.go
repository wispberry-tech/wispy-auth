package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	. "github.com/wispberry-tech/wispy-auth/core"
)

// PostgresStorage implements Storage interface for PostgreSQL databases
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage creates a new PostgreSQL storage instance
func NewPostgresStorage(databaseDSN string) (*PostgresStorage, error) {
	// Parse the connection string
	config, err := pgx.ParseConfig(databaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database DSN: %w", err)
	}

	// Register the pgx driver
	db := stdlib.OpenDB(*config)

	// Configure connection pool to reduce statement name conflicts
	// Set reasonable connection pool limits to prevent resource exhaustion
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close() // #nosec G104 - Close error can be ignored in error path
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	storage := &PostgresStorage{
		db: db,
	}

	return storage, nil
}

// GetDB returns the underlying database connection for sharing with extensions
func (p *PostgresStorage) GetDB() (*sql.DB, error) {
	return p.db, nil
}

// User operations
func (p *PostgresStorage) CreateUser(user *User) error {
	query := `INSERT INTO users (email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, uuid`

	err := p.db.QueryRow(query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended,
		time.Now(), time.Now()).Scan(&user.ID, &user.UUID)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetUserByEmail(email, provider string) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = $1 AND provider = $2`

	err := p.db.QueryRow(query, email, provider).Scan(
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

func (p *PostgresStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = $1`

	err := p.db.QueryRow(query, email).Scan(
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

func (p *PostgresStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE provider = $1 AND provider_id = $2`

	err := p.db.QueryRow(query, provider, providerID).Scan(
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

func (p *PostgresStorage) GetUserByID(id uint) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE id = $1`

	err := p.db.QueryRow(query, id).Scan(
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

func (p *PostgresStorage) GetUserByUUID(uuid string) (*User, error) {
	user := &User{}
	query := `SELECT id, uuid, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE uuid = $1`

	err := p.db.QueryRow(query, uuid).Scan(
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

func (p *PostgresStorage) UpdateUser(user *User) error {
	query := `UPDATE users SET email = $1, username = $2, first_name = $3, last_name = $4,
			  password_hash = $5, provider = $6, provider_id = $7, email_verified = $8,
			  is_active = $9, is_suspended = $10, updated_at = $11
			  WHERE id = $12`

	_, err := p.db.Exec(query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended, time.Now(), user.ID)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// CreateUserWithSecurity creates a user and their security record in a transaction
func (p *PostgresStorage) CreateUserWithSecurity(user *User, security *UserSecurity) error {
	// Begin transaction
	tx, err := p.db.Begin()
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
				  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, uuid`

	err = tx.QueryRow(userQuery,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified,
		user.IsActive, user.IsSuspended,
		time.Now(), time.Now()).Scan(&user.ID, &user.UUID)

	if err != nil {
		return fmt.Errorf("failed to create user in transaction: %w", err)
	}

	// Set the user ID in security record
	security.UserID = user.ID

	// Create user security record
	securityQuery := `INSERT INTO user_security (user_id, login_attempts, last_login_ip,
					  password_changed_at, force_password_change, two_factor_enabled,
					  concurrent_sessions, security_version, risk_score, suspicious_activity_count,
					  created_at, updated_at)
					  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	// Convert string IP to sql.NullString to handle NULL properly
	var lastLoginIP sql.NullString
	if security.LastLoginIP != nil {
		lastLoginIP.String = *security.LastLoginIP
		lastLoginIP.Valid = true
	}

	_, err = tx.Exec(securityQuery,
		security.UserID, security.LoginAttempts, lastLoginIP,
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

// HandleFailedLogin atomically increments login attempts and locks account if needed
func (p *PostgresStorage) HandleFailedLogin(userID uint, maxAttempts int, lockoutDuration time.Duration) (bool, error) {
	// Begin transaction
	tx, err := p.db.Begin()
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
	incrementQuery := `UPDATE user_security SET login_attempts = login_attempts + 1, updated_at = $1
					   WHERE user_id = $2 RETURNING login_attempts`

	err = tx.QueryRow(incrementQuery, time.Now(), userID).Scan(&currentAttempts)
	if err != nil {
		return false, fmt.Errorf("failed to increment login attempts: %w", err)
	}

	// Check if we need to lock the account
	wasLocked := false
	if currentAttempts >= maxAttempts {
		lockUntil := time.Now().Add(lockoutDuration)
		lockQuery := `UPDATE user_security SET locked_until = $1, updated_at = $2 WHERE user_id = $3`

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

// User Security operations
func (p *PostgresStorage) CreateUserSecurity(security *UserSecurity) error {
	query := `INSERT INTO user_security (user_id, login_attempts, last_login_ip,
			  password_changed_at, force_password_change, two_factor_enabled,
			  concurrent_sessions, security_version, risk_score, suspicious_activity_count,
			  created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	// Convert string IP to sql.NullString to handle NULL properly
	var lastLoginIP sql.NullString
	if security.LastLoginIP != nil {
		lastLoginIP.String = *security.LastLoginIP
		lastLoginIP.Valid = true
	}

	_, err := p.db.Exec(query,
		security.UserID, security.LoginAttempts, lastLoginIP,
		security.PasswordChangedAt, security.ForcePasswordChange, security.TwoFactorEnabled,
		security.ConcurrentSessions, security.SecurityVersion, security.RiskScore,
		security.SuspiciousActivityCount, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user security: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetUserSecurity(userID uint) (*UserSecurity, error) {
	security := &UserSecurity{}
	query := `SELECT user_id, login_attempts, locked_until, last_login_at, last_login_ip,
			  last_failed_login_at, last_failed_login_ip, password_changed_at,
			  force_password_change, two_factor_enabled, two_factor_secret,
			  two_factor_backup_codes, two_factor_verified_at, concurrent_sessions,
			  last_session_token, device_fingerprint, known_devices,
			  security_version, risk_score, suspicious_activity_count,
			  created_at, updated_at
			  FROM user_security WHERE user_id = $1`

	// Use sql.NullString for nullable string fields to handle NULL values
	var lastLoginIP, lastFailedLoginIP, twoFactorSecret, twoFactorBackupCodes sql.NullString
	var lastSessionToken, deviceFingerprint, knownDevices sql.NullString

	err := p.db.QueryRow(query, userID).Scan(
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

func (p *PostgresStorage) UpdateUserSecurity(security *UserSecurity) error {
	query := `UPDATE user_security SET login_attempts = $1, locked_until = $2,
			  last_login_at = $3, last_login_ip = $4, last_failed_login_at = $5,
			  last_failed_login_ip = $6, password_changed_at = $7, force_password_change = $8,
			  two_factor_enabled = $9, two_factor_secret = $10, two_factor_backup_codes = $11,
			  two_factor_verified_at = $12, concurrent_sessions = $13, last_session_token = $14,
			  device_fingerprint = $15, known_devices = $16, security_version = $17,
			  risk_score = $18, suspicious_activity_count = $19, updated_at = $20
			  WHERE user_id = $21`

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

	_, err := p.db.Exec(query,
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
func (p *PostgresStorage) IncrementLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = login_attempts + 1, updated_at = $1
			  WHERE user_id = $2`
	_, err := p.db.Exec(query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to increment login attempts: %w", err)
	}
	return nil
}

func (p *PostgresStorage) ResetLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = 0, locked_until = NULL, updated_at = $1
			  WHERE user_id = $2`
	_, err := p.db.Exec(query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}
	return nil
}

func (p *PostgresStorage) SetUserLocked(userID uint, until time.Time) error {
	query := `UPDATE user_security SET locked_until = $1, updated_at = $2
			  WHERE user_id = $3`
	_, err := p.db.Exec(query, until, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to set user locked: %w", err)
	}
	return nil
}

func (p *PostgresStorage) UpdateLastLogin(userID uint, ipAddress *string) error {
	query := `UPDATE user_security SET last_login_at = $1, last_login_ip = $2, updated_at = $3
			  WHERE user_id = $4`

	// Convert string IP pointer to sql.NullString to handle NULL properly
	var ip sql.NullString
	if ipAddress != nil {
		ip.String = *ipAddress
		ip.Valid = true
	}

	_, err := p.db.Exec(query, time.Now(), ip, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}

// Session operations
func (p *PostgresStorage) CreateSession(session *Session) error {
	query := `INSERT INTO sessions (token, user_id, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`

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

	err := p.db.QueryRow(query,
		session.Token, session.UserID, session.ExpiresAt, deviceFingerprint,
		userAgent, ipAddress, session.IsActive, session.LastAccessedAt,
		time.Now()).Scan(&session.ID)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetSession(token string) (*Session, error) {
	session := &Session{}
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at
			  FROM sessions WHERE token = $1 AND is_active = true`

	// Use sql.NullString for nullable fields to handle NULL values
	var ipAddress, userAgent, deviceFingerprint sql.NullString

	err := p.db.QueryRow(query, token).Scan(
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

func (p *PostgresStorage) GetUserSessions(userID uint) ([]*Session, error) {
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, is_active, last_accessed_at, created_at
			  FROM sessions WHERE user_id = $1 ORDER BY last_accessed_at DESC`

	rows, err := p.db.Query(query, userID)
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

func (p *PostgresStorage) UpdateSession(session *Session) error {
	query := `UPDATE sessions SET expires_at = $1, device_fingerprint = $2,
			  user_agent = $3, ip_address = $4, is_active = $5, last_accessed_at = $6
			  WHERE id = $7`

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

	_, err := p.db.Exec(query,
		session.ExpiresAt, deviceFingerprint, userAgent,
		ipAddress, session.IsActive, session.LastAccessedAt, session.ID)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

func (p *PostgresStorage) DeleteSession(token string) error {
	query := `DELETE FROM sessions WHERE token = $1`
	_, err := p.db.Exec(query, token)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

func (p *PostgresStorage) DeleteUserSessions(userID uint) error {
	query := `DELETE FROM sessions WHERE user_id = $1`
	_, err := p.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return nil
}

func (p *PostgresStorage) CleanupExpiredSessions() error {
	query := `DELETE FROM sessions WHERE expires_at < $1 OR is_active = false`
	_, err := p.db.Exec(query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

func (p *PostgresStorage) CountActiveSessions(userID uint) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND is_active = true AND expires_at > $2`
	err := p.db.QueryRow(query, userID, time.Now()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active sessions: %w", err)
	}
	return count, nil
}

// OAuth state operations
func (p *PostgresStorage) StoreOAuthState(state *OAuthState) error {
	query := `INSERT INTO oauth_states (state, csrf, provider, redirect_url, expires_at, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`

	// Convert string to sql.NullString to handle NULL properly
	var redirectURL sql.NullString
	if state.RedirectURL != "" {
		redirectURL.String = state.RedirectURL
		redirectURL.Valid = true
	}

	err := p.db.QueryRow(query,
		state.State, state.CSRF, state.Provider, redirectURL,
		state.ExpiresAt, time.Now()).Scan(&state.ID)

	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetOAuthState(state string) (*OAuthState, error) {
	oauthState := &OAuthState{}
	query := `SELECT id, state, csrf, provider, redirect_url, expires_at, created_at
			  FROM oauth_states WHERE state = $1`

	// Use sql.NullString for redirect_url to handle NULL values
	var redirectURL sql.NullString

	err := p.db.QueryRow(query, state).Scan(
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

func (p *PostgresStorage) DeleteOAuthState(state string) error {
	query := `DELETE FROM oauth_states WHERE state = $1`
	_, err := p.db.Exec(query, state)
	if err != nil {
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}
	return nil
}

// Security Event operations
func (p *PostgresStorage) CreateSecurityEvent(event *SecurityEvent) error {
	query := `INSERT INTO security_events (user_id, event_type, description,
			  ip_address, user_agent, device_fingerprint, severity,
			  success, metadata, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`

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

	err := p.db.QueryRow(query,
		event.UserID, event.EventType, description, ipAddress,
		userAgent, deviceFingerprint, event.Severity,
		event.Success, metadata, time.Now()).Scan(&event.ID)

	if err != nil {
		return fmt.Errorf("failed to create security event: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetSecurityEvents(userID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	query := `SELECT id, user_id, event_type, description, ip_address,
			  user_agent, device_fingerprint, severity, success, metadata, created_at
			  FROM security_events WHERE true`
	args := []interface{}{}
	argCount := 0

	if userID != nil {
		argCount++
		query += fmt.Sprintf(` AND user_id = $%d`, argCount)
		args = append(args, *userID)
	}

	if eventType != "" {
		argCount++
		query += fmt.Sprintf(` AND event_type = $%d`, argCount)
		args = append(args, eventType)
	}

	argCount++
	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, argCount)
	args = append(args, limit)

	argCount++
	query += fmt.Sprintf(` OFFSET $%d`, argCount)
	args = append(args, offset)

	rows, err := p.db.Query(query, args...)
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

func (p *PostgresStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return p.GetSecurityEvents(&userID, "", limit, offset)
}

// Health check
func (p *PostgresStorage) Ping() error {
	return p.db.Ping()
}

func (p *PostgresStorage) Close() error {
	return p.db.Close()
}
