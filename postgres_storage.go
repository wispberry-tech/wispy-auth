package auth

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// PostgresStorage implements StorageInterface for PostgreSQL databases using pure SQL
type PostgresStorage struct {
	db     *sql.DB
	config StorageConfig
}

// OAuth State storage methods
func (p *PostgresStorage) StoreOAuthState(state *OAuthState) error {
	query := `INSERT INTO oauth_states (state_id, csrf_token, created_at, expires_at) 
			  VALUES ($1, $2, $3, $4)`

	_, err := p.db.Exec(query, state.State, state.CSRF, state.CreatedAt, state.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetOAuthState(stateID string) (*OAuthState, error) {
	query := `SELECT state_id, csrf_token, created_at, expires_at 
			  FROM oauth_states WHERE state_id = $1`

	var state OAuthState
	err := p.db.QueryRow(query, stateID).Scan(
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

func (p *PostgresStorage) DeleteOAuthState(stateID string) error {
	query := `DELETE FROM oauth_states WHERE state_id = $1`

	result, err := p.db.Exec(query, stateID)
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

// NewPostgresStorage creates a new PostgreSQL storage instance
func NewPostgresStorage(dsn string, config StorageConfig) (StorageInterface, error) {
	// Parse the connection string and convert to pgx config
	pgxConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSN: %w", err)
	}

	// Create a database connection using pgx with database/sql
	db := stdlib.OpenDB(*pgxConfig)

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	storage := &PostgresStorage{
		db:     db,
		config: config,
	}

	return storage, nil
}

// CreateUser creates a new user in the database
func (p *PostgresStorage) CreateUser(user *User) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (
			%s, %s, %s, %s, %s, %s, %s, %s, 
			%s, %s, %s, 
			%s, %s, %s, 
			%s, %s, %s, %s,
			%s, %s, 
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11,
			$12, $13, $14,
			$15, $16, $17, $18,
			$19, $20,
			$21, $22, $23,
			$24, $25, $26, $27,
			$28, $29
		) RETURNING %s`,
		p.config.UsersTable,
		// Basic fields
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamps
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		// Return ID
		p.config.UserColumns.ID,
	)

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	err := p.db.QueryRow(query,
		user.Email, user.PasswordHash, user.Username, user.FirstName, user.LastName, user.AvatarURL, user.Provider, user.ProviderID,
		user.EmailVerified, user.EmailVerifiedAt, user.VerificationToken,
		user.PasswordResetToken, user.PasswordResetExpiresAt, user.PasswordChangedAt,
		user.LoginAttempts, user.LastFailedLoginAt, user.LockedUntil, user.LastLoginAt,
		user.LastKnownIP, user.LastLoginLocation,
		user.TwoFactorEnabled, user.TwoFactorSecret, user.BackupCodes,
		user.IsActive, user.IsSuspended, user.SuspendedAt, user.SuspendReason,
		user.CreatedAt, user.UpdatedAt,
	).Scan(&user.ID)

	return err
}

// GetUserByEmail retrieves a user by email and provider
func (p *PostgresStorage) GetUserByEmail(email, provider string) (*User, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1 AND %s = $2`,
		// Basic fields
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamps
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		// Table and conditions
		p.config.UsersTable,
		p.config.UserColumns.Email,
		p.config.UserColumns.Provider,
	)

	var user User
	err := p.db.QueryRow(query, email, provider).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Username, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.EmailVerifiedAt, &user.VerificationToken,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt, &user.PasswordChangedAt,
		&user.LoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.LastLoginAt,
		&user.LastKnownIP, &user.LastLoginLocation,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.BackupCodes,
		&user.IsActive, &user.IsSuspended, &user.SuspendedAt, &user.SuspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// GetUserByEmailAnyProvider retrieves a user by email regardless of provider
func (p *PostgresStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1`,
		// Basic fields
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamps
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		// Table and condition
		p.config.UsersTable,
		p.config.UserColumns.Email,
	)

	var user User
	err := p.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Username, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.EmailVerifiedAt, &user.VerificationToken,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt, &user.PasswordChangedAt,
		&user.LoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.LastLoginAt,
		&user.LastKnownIP, &user.LastLoginLocation,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.BackupCodes,
		&user.IsActive, &user.IsSuspended, &user.SuspendedAt, &user.SuspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// GetUserByProviderID retrieves a user by provider and provider ID
func (p *PostgresStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1 AND %s = $2`,
		// Basic fields
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamps
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		// Table and conditions
		p.config.UsersTable,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
	)

	var user User
	err := p.db.QueryRow(query, provider, providerID).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Username, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.EmailVerifiedAt, &user.VerificationToken,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt, &user.PasswordChangedAt,
		&user.LoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.LastLoginAt,
		&user.LastKnownIP, &user.LastLoginLocation,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.BackupCodes,
		&user.IsActive, &user.IsSuspended, &user.SuspendedAt, &user.SuspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (p *PostgresStorage) GetUserByID(id uint) (*User, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1`,
		// Basic fields
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamps
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		// Table and condition
		p.config.UsersTable,
		p.config.UserColumns.ID,
	)

	var user User
	err := p.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Username, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.EmailVerifiedAt, &user.VerificationToken,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt, &user.PasswordChangedAt,
		&user.LoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.LastLoginAt,
		&user.LastKnownIP, &user.LastLoginLocation,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.BackupCodes,
		&user.IsActive, &user.IsSuspended, &user.SuspendedAt, &user.SuspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUser updates an existing user
func (p *PostgresStorage) UpdateUser(user *User) error {
	query := fmt.Sprintf(`
		UPDATE %s SET 
			%s = $1, %s = $2, %s = $3, %s = $4, %s = $5, %s = $6,
			%s = $7, %s = $8, %s = $9,
			%s = $10, %s = $11, %s = $12,
			%s = $13, %s = $14, %s = $15, %s = $16,
			%s = $17, %s = $18,
			%s = $19, %s = $20, %s = $21,
			%s = $22, %s = $23, %s = $24, %s = $25,
			%s = $26, %s = $27, %s = $28
		WHERE %s = $29`,
		p.config.UsersTable,
		// Basic fields
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamp
		p.config.UserColumns.UpdatedAt,
		// WHERE condition
		p.config.UserColumns.ID,
	)

	user.UpdatedAt = time.Now()

	_, err := p.db.Exec(query,
		user.Email, user.PasswordHash, user.Username, user.FirstName, user.LastName, user.AvatarURL, user.Provider, user.ProviderID,
		user.EmailVerified, user.EmailVerifiedAt, user.VerificationToken,
		user.PasswordResetToken, user.PasswordResetExpiresAt, user.PasswordChangedAt,
		user.LoginAttempts, user.LastFailedLoginAt, user.LockedUntil, user.LastLoginAt,
		user.LastKnownIP, user.LastLoginLocation,
		user.TwoFactorEnabled, user.TwoFactorSecret, user.BackupCodes,
		user.IsActive, user.IsSuspended, user.SuspendedAt, user.SuspendReason,
		user.UpdatedAt,
		user.ID,
	)

	return err
}

// CreateSession creates a new session
func (p *PostgresStorage) CreateSession(session *Session) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (
			%s, %s, %s, %s,
			%s, %s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12,
			$13, $14
		)`,
		p.config.SessionsTable,
		// Basic fields
		p.config.SessionColumns.ID,
		p.config.SessionColumns.UserID,
		p.config.SessionColumns.Token,
		p.config.SessionColumns.ExpiresAt,
		// Device & location
		p.config.SessionColumns.DeviceFingerprint,
		p.config.SessionColumns.UserAgent,
		p.config.SessionColumns.IPAddress,
		p.config.SessionColumns.Location,
		// Security features
		p.config.SessionColumns.IsActive,
		p.config.SessionColumns.LastActivity,
		p.config.SessionColumns.RequiresTwoFactor,
		p.config.SessionColumns.TwoFactorVerified,
		// Timestamps
		p.config.SessionColumns.CreatedAt,
		p.config.SessionColumns.UpdatedAt,
	)

	now := time.Now()
	session.CreatedAt = now
	session.UpdatedAt = now
	session.LastActivity = now

	_, err := p.db.Exec(query,
		session.ID, session.UserID, session.Token, session.ExpiresAt,
		session.DeviceFingerprint, session.UserAgent, session.IPAddress, session.Location,
		session.IsActive, session.LastActivity, session.RequiresTwoFactor, session.TwoFactorVerified,
		session.CreatedAt, session.UpdatedAt,
	)

	return err
}

// GetSession retrieves a session by token
func (p *PostgresStorage) GetSession(token string) (*Session, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s,
			%s, %s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1 AND %s > $2 AND %s = true`,
		// Basic fields
		p.config.SessionColumns.ID,
		p.config.SessionColumns.UserID,
		p.config.SessionColumns.Token,
		p.config.SessionColumns.ExpiresAt,
		// Device & location
		p.config.SessionColumns.DeviceFingerprint,
		p.config.SessionColumns.UserAgent,
		p.config.SessionColumns.IPAddress,
		p.config.SessionColumns.Location,
		// Security features
		p.config.SessionColumns.IsActive,
		p.config.SessionColumns.LastActivity,
		p.config.SessionColumns.RequiresTwoFactor,
		p.config.SessionColumns.TwoFactorVerified,
		// Timestamps
		p.config.SessionColumns.CreatedAt,
		p.config.SessionColumns.UpdatedAt,
		// Table and conditions
		p.config.SessionsTable,
		p.config.SessionColumns.Token,
		p.config.SessionColumns.ExpiresAt,
		p.config.SessionColumns.IsActive,
	)

	var session Session
	err := p.db.QueryRow(query, token, time.Now()).Scan(
		&session.ID, &session.UserID, &session.Token, &session.ExpiresAt,
		&session.DeviceFingerprint, &session.UserAgent, &session.IPAddress, &session.Location,
		&session.IsActive, &session.LastActivity, &session.RequiresTwoFactor, &session.TwoFactorVerified,
		&session.CreatedAt, &session.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	return &session, nil
}

// GetUserSessions retrieves all sessions for a user
func (p *PostgresStorage) GetUserSessions(userID uint) ([]*Session, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s,
			%s, %s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1 AND %s > $2 AND %s = true
		ORDER BY %s DESC`,
		// Basic fields
		p.config.SessionColumns.ID,
		p.config.SessionColumns.UserID,
		p.config.SessionColumns.Token,
		p.config.SessionColumns.ExpiresAt,
		// Device & location
		p.config.SessionColumns.DeviceFingerprint,
		p.config.SessionColumns.UserAgent,
		p.config.SessionColumns.IPAddress,
		p.config.SessionColumns.Location,
		// Security features
		p.config.SessionColumns.IsActive,
		p.config.SessionColumns.LastActivity,
		p.config.SessionColumns.RequiresTwoFactor,
		p.config.SessionColumns.TwoFactorVerified,
		// Timestamps
		p.config.SessionColumns.CreatedAt,
		p.config.SessionColumns.UpdatedAt,
		// Table and conditions
		p.config.SessionsTable,
		p.config.SessionColumns.UserID,
		p.config.SessionColumns.ExpiresAt,
		p.config.SessionColumns.IsActive,
		// Order by
		p.config.SessionColumns.LastActivity,
	)

	rows, err := p.db.Query(query, userID, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var session Session
		err := rows.Scan(
			&session.ID, &session.UserID, &session.Token, &session.ExpiresAt,
			&session.DeviceFingerprint, &session.UserAgent, &session.IPAddress, &session.Location,
			&session.IsActive, &session.LastActivity, &session.RequiresTwoFactor, &session.TwoFactorVerified,
			&session.CreatedAt, &session.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, &session)
	}

	return sessions, rows.Err()
}

// UpdateSession updates an existing session
func (p *PostgresStorage) UpdateSession(session *Session) error {
	query := fmt.Sprintf(`
		UPDATE %s SET 
			%s = $1, %s = $2, %s = $3,
			%s = $4, %s = $5, %s = $6,
			%s = $7, %s = $8, %s = $9, 
			%s = $10
		WHERE %s = $11`,
		p.config.SessionsTable,
		// Basic fields
		p.config.SessionColumns.ExpiresAt,
		p.config.SessionColumns.Location,
		// Security features
		p.config.SessionColumns.IsActive,
		p.config.SessionColumns.LastActivity,
		p.config.SessionColumns.RequiresTwoFactor,
		p.config.SessionColumns.TwoFactorVerified,
		// Update device info (less frequently)
		p.config.SessionColumns.DeviceFingerprint,
		p.config.SessionColumns.UserAgent,
		p.config.SessionColumns.IPAddress,
		// Timestamp
		p.config.SessionColumns.UpdatedAt,
		// WHERE condition
		p.config.SessionColumns.ID,
	)

	session.UpdatedAt = time.Now()
	session.LastActivity = time.Now()

	_, err := p.db.Exec(query,
		session.ExpiresAt, session.Location,
		session.IsActive, session.LastActivity, session.RequiresTwoFactor, session.TwoFactorVerified,
		session.DeviceFingerprint, session.UserAgent, session.IPAddress,
		session.UpdatedAt,
		session.ID,
	)

	return err
}

// DeleteSession deletes a session by token
func (p *PostgresStorage) DeleteSession(token string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`, p.config.SessionsTable, p.config.SessionColumns.Token)
	_, err := p.db.Exec(query, token)
	return err
}

// DeleteUserSessions deletes all sessions for a user
func (p *PostgresStorage) DeleteUserSessions(userID uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`, p.config.SessionsTable, p.config.SessionColumns.UserID)
	_, err := p.db.Exec(query, userID)
	return err
}

// CleanupExpiredSessions removes all expired sessions
func (p *PostgresStorage) CleanupExpiredSessions() error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s < $1`, p.config.SessionsTable, p.config.SessionColumns.ExpiresAt)
	_, err := p.db.Exec(query, time.Now())
	return err
}

// CountActiveSessions counts active sessions for a user
func (p *PostgresStorage) CountActiveSessions(userID uint) (int, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM %s 
		WHERE %s = $1 AND %s > $2 AND %s = true`,
		p.config.SessionsTable,
		p.config.SessionColumns.UserID,
		p.config.SessionColumns.ExpiresAt,
		p.config.SessionColumns.IsActive,
	)

	var count int
	err := p.db.QueryRow(query, userID, time.Now()).Scan(&count)
	return count, err
}

// CreateSecurityEvent creates a new security event
func (p *PostgresStorage) CreateSecurityEvent(event *SecurityEvent) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (
			%s, %s, %s, %s, %s, %s, %s, %s, %s
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`,
		p.config.SecurityEventsTable,
		p.config.SecurityEventColumns.UserID,
		p.config.SecurityEventColumns.TenantID,
		p.config.SecurityEventColumns.EventType,
		p.config.SecurityEventColumns.Description,
		p.config.SecurityEventColumns.IPAddress,
		p.config.SecurityEventColumns.UserAgent,
		p.config.SecurityEventColumns.Location,
		p.config.SecurityEventColumns.Metadata,
		p.config.SecurityEventColumns.CreatedAt,
	)

	_, err := p.db.Exec(query,
		event.UserID, event.TenantID, event.EventType, event.Description,
		event.IPAddress, event.UserAgent, event.Location, event.Metadata,
		event.CreatedAt,
	)

	return err
}

// GetSecurityEvents retrieves security events with filters
func (p *PostgresStorage) GetSecurityEvents(userID *uint, tenantID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	baseQuery := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		FROM %s
		WHERE 1=1`,
		p.config.SecurityEventColumns.ID,
		p.config.SecurityEventColumns.UserID,
		p.config.SecurityEventColumns.TenantID,
		p.config.SecurityEventColumns.EventType,
		p.config.SecurityEventColumns.Description,
		p.config.SecurityEventColumns.IPAddress,
		p.config.SecurityEventColumns.UserAgent,
		p.config.SecurityEventColumns.Location,
		p.config.SecurityEventColumns.Metadata,
		p.config.SecurityEventColumns.CreatedAt,
		p.config.SecurityEventsTable,
	)

	var args []interface{}
	argIndex := 1

	if userID != nil {
		baseQuery += fmt.Sprintf(` AND %s = $%d`, p.config.SecurityEventColumns.UserID, argIndex)
		args = append(args, *userID)
		argIndex++
	}

	if tenantID != nil {
		baseQuery += fmt.Sprintf(` AND %s = $%d`, p.config.SecurityEventColumns.TenantID, argIndex)
		args = append(args, *tenantID)
		argIndex++
	}

	if eventType != "" {
		baseQuery += fmt.Sprintf(` AND %s = $%d`, p.config.SecurityEventColumns.EventType, argIndex)
		args = append(args, eventType)
		argIndex++
	}

	baseQuery += fmt.Sprintf(` ORDER BY %s DESC`, p.config.SecurityEventColumns.CreatedAt)

	if limit > 0 {
		baseQuery += fmt.Sprintf(` LIMIT $%d`, argIndex)
		args = append(args, limit)
		argIndex++
	}

	if offset > 0 {
		baseQuery += fmt.Sprintf(` OFFSET $%d`, argIndex)
		args = append(args, offset)
	}

	rows, err := p.db.Query(baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*SecurityEvent
	for rows.Next() {
		var event SecurityEvent
		err := rows.Scan(
			&event.ID, &event.UserID, &event.TenantID, &event.EventType, &event.Description,
			&event.IPAddress, &event.UserAgent, &event.Location, &event.Metadata,
			&event.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		events = append(events, &event)
	}

	return events, rows.Err()
}

// GetSecurityEventsByUser retrieves security events for a specific user
func (p *PostgresStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return p.GetSecurityEvents(&userID, nil, "", limit, offset)
}

// Password Reset operations
func (p *PostgresStorage) CreatePasswordResetToken(userID uint, token string, expiresAt time.Time) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2, %s = $3 
		WHERE %s = $4`,
		p.config.UsersTable,
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	_, err := p.db.Exec(query, token, expiresAt, time.Now(), userID)
	return err
}

func (p *PostgresStorage) GetUserByPasswordResetToken(token string) (*User, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1 AND %s > $2`,
		// Basic fields
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamps
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		// Table and conditions
		p.config.UsersTable,
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
	)

	var user User
	err := p.db.QueryRow(query, token, time.Now()).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Username, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.EmailVerifiedAt, &user.VerificationToken,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt, &user.PasswordChangedAt,
		&user.LoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.LastLoginAt,
		&user.LastKnownIP, &user.LastLoginLocation,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.BackupCodes,
		&user.IsActive, &user.IsSuspended, &user.SuspendedAt, &user.SuspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (p *PostgresStorage) ClearPasswordResetToken(userID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = '', %s = NULL, %s = $1 
		WHERE %s = $2`,
		p.config.UsersTable,
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	_, err := p.db.Exec(query, time.Now(), userID)
	return err
}

// Email Verification operations
func (p *PostgresStorage) SetEmailVerificationToken(userID uint, token string) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2 
		WHERE %s = $3`,
		p.config.UsersTable,
		p.config.UserColumns.VerificationToken,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	_, err := p.db.Exec(query, token, time.Now(), userID)
	return err
}

func (p *PostgresStorage) GetUserByVerificationToken(token string) (*User, error) {
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1`,
		// Basic fields
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Username,
		p.config.UserColumns.FirstName,
		p.config.UserColumns.LastName,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		// Email security
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		// Password security
		p.config.UserColumns.PasswordResetToken,
		p.config.UserColumns.PasswordResetExpiresAt,
		p.config.UserColumns.PasswordChangedAt,
		// Login security
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LastLoginAt,
		// Location & device
		p.config.UserColumns.LastKnownIP,
		p.config.UserColumns.LastLoginLocation,
		// 2FA
		p.config.UserColumns.TwoFactorEnabled,
		p.config.UserColumns.TwoFactorSecret,
		p.config.UserColumns.BackupCodes,
		// Account security
		p.config.UserColumns.IsActive,
		p.config.UserColumns.IsSuspended,
		p.config.UserColumns.SuspendedAt,
		p.config.UserColumns.SuspendReason,
		// Timestamps
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		// Table and condition
		p.config.UsersTable,
		p.config.UserColumns.VerificationToken,
	)

	var user User
	err := p.db.QueryRow(query, token).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Username, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Provider, &user.ProviderID,
		&user.EmailVerified, &user.EmailVerifiedAt, &user.VerificationToken,
		&user.PasswordResetToken, &user.PasswordResetExpiresAt, &user.PasswordChangedAt,
		&user.LoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.LastLoginAt,
		&user.LastKnownIP, &user.LastLoginLocation,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.BackupCodes,
		&user.IsActive, &user.IsSuspended, &user.SuspendedAt, &user.SuspendReason,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (p *PostgresStorage) MarkEmailAsVerified(userID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = true, %s = $1, %s = '', %s = $2 
		WHERE %s = $3`,
		p.config.UsersTable,
		p.config.UserColumns.EmailVerified,
		p.config.UserColumns.EmailVerifiedAt,
		p.config.UserColumns.VerificationToken,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	now := time.Now()
	_, err := p.db.Exec(query, now, now, userID)
	return err
}

// Login Attempt operations
func (p *PostgresStorage) IncrementLoginAttempts(userID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = %s + 1, %s = $1, %s = $2 
		WHERE %s = $3`,
		p.config.UsersTable,
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	now := time.Now()
	_, err := p.db.Exec(query, now, now, userID)
	return err
}

func (p *PostgresStorage) ResetLoginAttempts(userID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = 0, %s = NULL, %s = NULL, %s = $1 
		WHERE %s = $2`,
		p.config.UsersTable,
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	_, err := p.db.Exec(query, time.Now(), userID)
	return err
}

func (p *PostgresStorage) LockUser(userID uint, until time.Time) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2 
		WHERE %s = $3`,
		p.config.UsersTable,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	_, err := p.db.Exec(query, until, time.Now(), userID)
	return err
}

func (p *PostgresStorage) UnlockUser(userID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = NULL, %s = 0, %s = NULL, %s = $1 
		WHERE %s = $2`,
		p.config.UsersTable,
		p.config.UserColumns.LockedUntil,
		p.config.UserColumns.LoginAttempts,
		p.config.UserColumns.LastFailedLoginAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	_, err := p.db.Exec(query, time.Now(), userID)
	return err
}

// Close closes the database connection
func (p *PostgresStorage) Close() error {
	return p.db.Close()
}
