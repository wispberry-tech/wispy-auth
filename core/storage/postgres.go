package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/wispberry-tech/wispy-auth/core"
	. "github.com/wispberry-tech/wispy-auth/core"
	_ "github.com/jackc/pgx/v5/stdlib"
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

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	storage := &PostgresStorage{
		db: db,
	}

	// Auto-create missing tables
	schemaManager := core.NewSchemaManager(db, "postgres")
	if err := schemaManager.EnsureCoreSchema(); err != nil {
		return nil, fmt.Errorf("failed to ensure core schema: %w", err)
	}

	return storage, nil
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

// User Security operations
func (p *PostgresStorage) CreateUserSecurity(security *UserSecurity) error {
	query := `INSERT INTO user_security (user_id, login_attempts, last_login_ip,
			  password_changed_at, force_password_change, two_factor_enabled,
			  concurrent_sessions, security_version, risk_score, suspicious_activity_count,
			  created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := p.db.Exec(query,
		security.UserID, security.LoginAttempts, security.LastLoginIP,
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

	err := p.db.QueryRow(query, userID).Scan(
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

func (p *PostgresStorage) UpdateUserSecurity(security *UserSecurity) error {
	query := `UPDATE user_security SET login_attempts = $1, locked_until = $2,
			  last_login_at = $3, last_login_ip = $4, last_failed_login_at = $5,
			  last_failed_login_ip = $6, password_changed_at = $7, force_password_change = $8,
			  two_factor_enabled = $9, two_factor_secret = $10, two_factor_backup_codes = $11,
			  two_factor_verified_at = $12, concurrent_sessions = $13, last_session_token = $14,
			  device_fingerprint = $15, known_devices = $16, security_version = $17,
			  risk_score = $18, suspicious_activity_count = $19, updated_at = $20
			  WHERE user_id = $21`

	_, err := p.db.Exec(query,
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

func (p *PostgresStorage) UpdateLastLogin(userID uint, ipAddress string) error {
	query := `UPDATE user_security SET last_login_at = $1, last_login_ip = $2, updated_at = $3
			  WHERE user_id = $4`
	_, err := p.db.Exec(query, time.Now(), ipAddress, time.Now(), userID)
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

	err := p.db.QueryRow(query,
		session.Token, session.UserID, session.ExpiresAt, session.DeviceFingerprint,
		session.UserAgent, session.IPAddress, session.IsActive, session.LastAccessedAt,
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

	err := p.db.QueryRow(query, token).Scan(
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

func (p *PostgresStorage) UpdateSession(session *Session) error {
	query := `UPDATE sessions SET expires_at = $1, device_fingerprint = $2,
			  user_agent = $3, ip_address = $4, is_active = $5, last_accessed_at = $6
			  WHERE id = $7`

	_, err := p.db.Exec(query,
		session.ExpiresAt, session.DeviceFingerprint, session.UserAgent,
		session.IPAddress, session.IsActive, session.LastAccessedAt, session.ID)

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

	err := p.db.QueryRow(query,
		state.State, state.CSRF, state.Provider, state.RedirectURL,
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

	err := p.db.QueryRow(query, state).Scan(
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

	err := p.db.QueryRow(query,
		event.UserID, event.EventType, event.Description, event.IPAddress,
		event.UserAgent, event.DeviceFingerprint, event.Severity,
		event.Success, event.Metadata, time.Now()).Scan(&event.ID)

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