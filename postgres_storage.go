package auth

import (
	"database/sql"
	"fmt"
	"log/slog"
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
		slog.Error("Failed to store OAuth state", "error", err, "state_id", state.State)
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
		slog.Warn("OAuth state not found", "state_id", stateID)
		return nil, fmt.Errorf("OAuth state not found")
	}
	if err != nil {
		slog.Error("Failed to get OAuth state", "error", err, "state_id", stateID)
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	return &state, nil
}

func (p *PostgresStorage) DeleteOAuthState(stateID string) error {
	query := `DELETE FROM oauth_states WHERE state_id = $1`

	result, err := p.db.Exec(query, stateID)
	if err != nil {
		slog.Error("Failed to delete OAuth state", "error", err, "state_id", stateID)
		return fmt.Errorf("failed to delete OAuth state: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("Failed to get rows affected", "error", err, "state_id", stateID)
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		slog.Warn("OAuth state not found for deletion", "state_id", stateID)
		return fmt.Errorf("OAuth state not found")
	}

	return nil
}

// NewPostgresStorage creates a new PostgreSQL storage instance
func NewPostgresStorage(dsn string, config StorageConfig) (StorageInterface, error) {
	// Parse the connection string and convert to pgx config
	pgxConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		slog.Error("Failed to parse DSN", "error", err, "dsn", dsn)
		return nil, fmt.Errorf("failed to parse DSN: %w", err)
	}

	// Create a database connection using pgx with database/sql
	db := stdlib.OpenDB(*pgxConfig)

	// Test the connection
	if err := db.Ping(); err != nil {
		slog.Error("Failed to ping database", "error", err)
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

	// Debug: Log the generated query
	slog.Debug("Generated GetUserByEmail query", "query", query)

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

// Multi-tenant operations for PostgreSQL storage using pure SQL

// CreateTenant creates a new tenant
func (p *PostgresStorage) CreateTenant(tenant *Tenant) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5, $6, $7) 
		RETURNING %s`,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantColumns.ID,
	)

	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now

	err := p.db.QueryRow(query,
		tenant.Name,
		tenant.Slug,
		tenant.Domain,
		tenant.IsActive,
		tenant.Settings,
		tenant.CreatedAt,
		tenant.UpdatedAt,
	).Scan(&tenant.ID)

	return err
}

// GetTenantByID retrieves a tenant by ID
func (p *PostgresStorage) GetTenantByID(id uint) (*Tenant, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = $1`,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.ID,
	)

	var tenant Tenant
	err := p.db.QueryRow(query, id).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.Domain,
		&tenant.IsActive,
		&tenant.Settings,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrTenantNotFound
		}
		return nil, err
	}

	return &tenant, nil
}

// GetTenantBySlug retrieves a tenant by slug
func (p *PostgresStorage) GetTenantBySlug(slug string) (*Tenant, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = $1`,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.Slug,
	)

	var tenant Tenant
	err := p.db.QueryRow(query, slug).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Slug,
		&tenant.Domain,
		&tenant.IsActive,
		&tenant.Settings,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrTenantNotFound
		}
		return nil, err
	}

	return &tenant, nil
}

// UpdateTenant updates an existing tenant
func (p *PostgresStorage) UpdateTenant(tenant *Tenant) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2, %s = $3, %s = $4, %s = $5, %s = $6
		WHERE %s = $7`,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantColumns.ID,
	)

	tenant.UpdatedAt = time.Now()

	_, err := p.db.Exec(query,
		tenant.Name,
		tenant.Slug,
		tenant.Domain,
		tenant.IsActive,
		tenant.Settings,
		tenant.UpdatedAt,
		tenant.ID,
	)

	return err
}

// ListTenants retrieves all tenants
func (p *PostgresStorage) ListTenants() ([]*Tenant, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		ORDER BY %s`,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		p.config.MultiTenant.TenantColumns.Settings,
		p.config.MultiTenant.TenantColumns.CreatedAt,
		p.config.MultiTenant.TenantColumns.UpdatedAt,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.TenantColumns.Name,
	)

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		var tenant Tenant
		err := rows.Scan(
			&tenant.ID,
			&tenant.Name,
			&tenant.Slug,
			&tenant.Domain,
			&tenant.IsActive,
			&tenant.Settings,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, &tenant)
	}

	return tenants, rows.Err()
}

// CreateRole creates a new role
func (p *PostgresStorage) CreateRole(role *Role) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5, $6) 
		RETURNING %s`,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RoleColumns.ID,
	)

	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now

	err := p.db.QueryRow(query,
		role.TenantID,
		role.Name,
		role.Description,
		role.IsSystem,
		role.CreatedAt,
		role.UpdatedAt,
	).Scan(&role.ID)

	return err
}

// GetRoleByID retrieves a role by ID
func (p *PostgresStorage) GetRoleByID(id uint) (*Role, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1`,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.ID,
	)

	var role Role
	err := p.db.QueryRow(query, id).Scan(
		&role.ID,
		&role.TenantID,
		&role.Name,
		&role.Description,
		&role.IsSystem,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrRoleNotFound
		}
		return nil, err
	}

	return &role, nil
}

// GetRolesByTenant retrieves all roles for a tenant
func (p *PostgresStorage) GetRolesByTenant(tenantID uint) ([]*Role, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1
		ORDER BY %s`,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
	)

	rows, err := p.db.Query(query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		var role Role
		err := rows.Scan(
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, &role)
	}

	return roles, rows.Err()
}

// UpdateRole updates an existing role
func (p *PostgresStorage) UpdateRole(role *Role) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2, %s = $3, %s = $4, %s = $5
		WHERE %s = $6`,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		p.config.MultiTenant.RoleColumns.ID,
	)

	role.UpdatedAt = time.Now()

	_, err := p.db.Exec(query,
		role.TenantID,
		role.Name,
		role.Description,
		role.IsSystem,
		role.UpdatedAt,
		role.ID,
	)

	return err
}

// DeleteRole deletes a role
func (p *PostgresStorage) DeleteRole(id uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RoleColumns.ID)

	_, err := p.db.Exec(query, id)
	return err
}

// CreatePermission creates a new permission
func (p *PostgresStorage) CreatePermission(permission *Permission) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5, $6) 
		RETURNING %s`,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionColumns.ID,
	)

	now := time.Now()
	permission.CreatedAt = now
	permission.UpdatedAt = now

	err := p.db.QueryRow(query,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.CreatedAt,
		permission.UpdatedAt,
	).Scan(&permission.ID)

	return err
}

// GetPermissionByID retrieves a permission by ID
func (p *PostgresStorage) GetPermissionByID(id uint) (*Permission, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.ID,
	)

	var permission Permission
	err := p.db.QueryRow(query, id).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrPermissionNotFound
		}
		return nil, err
	}

	return &permission, nil
}

// GetPermissionByName retrieves a permission by name
func (p *PostgresStorage) GetPermissionByName(name string) (*Permission, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		WHERE %s = $1`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	var permission Permission
	err := p.db.QueryRow(query, name).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound // Could create ErrPermissionNotFound
		}
		return nil, err
	}

	return &permission, nil
}

// ListPermissions retrieves all permissions
func (p *PostgresStorage) ListPermissions() ([]*Permission, error) {
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s
		FROM %s 
		ORDER BY %s`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		var permission Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	return permissions, rows.Err()
}

// UpdatePermission updates an existing permission
func (p *PostgresStorage) UpdatePermission(permission *Permission) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2, %s = $3, %s = $4, %s = $5
		WHERE %s = $6`,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionColumns.ID,
	)

	permission.UpdatedAt = time.Now()

	_, err := p.db.Exec(query,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.UpdatedAt,
		permission.ID,
	)

	return err
}

// DeletePermission deletes a permission
func (p *PostgresStorage) DeletePermission(id uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.PermissionColumns.ID)

	_, err := p.db.Exec(query, id)
	return err
}

// AssignPermissionToRole assigns a permission to a role
func (p *PostgresStorage) AssignPermissionToRole(roleID, permissionID uint) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4)`,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.RolePermissionColumns.CreatedAt,
		p.config.MultiTenant.RolePermissionColumns.UpdatedAt,
	)

	now := time.Now()
	_, err := p.db.Exec(query, roleID, permissionID, now, now)
	return err
}

// RemovePermissionFromRole removes a permission from a role
func (p *PostgresStorage) RemovePermissionFromRole(roleID, permissionID uint) error {
	query := fmt.Sprintf(`
		DELETE FROM %s 
		WHERE %s = $1 AND %s = $2`,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
	)

	_, err := p.db.Exec(query, roleID, permissionID)
	return err
}

// GetRolePermissions retrieves all permissions for a role
func (p *PostgresStorage) GetRolePermissions(roleID uint) ([]*Permission, error) {
	query := fmt.Sprintf(`
		SELECT p.%s, p.%s, p.%s, p.%s, p.%s, p.%s, p.%s
		FROM %s p
		JOIN %s rp ON p.%s = rp.%s
		WHERE rp.%s = $1
		ORDER BY p.%s`,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		p.config.MultiTenant.PermissionsTable,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	rows, err := p.db.Query(query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		var permission Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	return permissions, rows.Err()
}

// AssignUserToTenant assigns a user to a tenant with a role
func (p *PostgresStorage) AssignUserToTenant(userID, tenantID, roleID uint) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (%s, %s) 
		DO UPDATE SET %s = $3, %s = $5`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		// ON CONFLICT columns
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		// DO UPDATE SET
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
	)

	now := time.Now()
	_, err := p.db.Exec(query, userID, tenantID, roleID, now, now)
	return err
}

// RemoveUserFromTenant removes a user from a tenant
func (p *PostgresStorage) RemoveUserFromTenant(userID, tenantID uint) error {
	query := fmt.Sprintf(`
		DELETE FROM %s 
		WHERE %s = $1 AND %s = $2`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
	)

	_, err := p.db.Exec(query, userID, tenantID)
	return err
}

// GetUserTenants retrieves all tenants for a user
func (p *PostgresStorage) GetUserTenants(userID uint) ([]*UserTenant, error) {
	query := fmt.Sprintf(`
		SELECT ut.%s, ut.%s, ut.%s, ut.%s,
			   t.%s, t.%s, t.%s, t.%s, t.%s,
			   r.%s, r.%s, r.%s, r.%s, r.%s, r.%s, r.%s
		FROM %s ut
		JOIN %s t ON ut.%s = t.%s
		JOIN %s r ON ut.%s = r.%s
		WHERE ut.%s = $1
		ORDER BY t.%s`,
		// UserTenant fields
		p.config.MultiTenant.UserTenantColumns.ID,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		// Tenant fields
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.TenantColumns.Name,
		p.config.MultiTenant.TenantColumns.Slug,
		p.config.MultiTenant.TenantColumns.Domain,
		p.config.MultiTenant.TenantColumns.IsActive,
		// Role fields
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.TenantsTable,
		p.config.MultiTenant.RolesTable,
		// Joins
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.TenantColumns.ID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		// Where
		p.config.MultiTenant.UserTenantColumns.UserID,
		// Order by
		p.config.MultiTenant.TenantColumns.Name,
	)

	rows, err := p.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userTenants []*UserTenant
	for rows.Next() {
		var userTenant UserTenant
		var tenant Tenant
		var role Role

		err := rows.Scan(
			// UserTenant fields
			&userTenant.UserID,
			&userTenant.TenantID,
			&userTenant.RoleID,
			&userTenant.CreatedAt,
			&userTenant.UpdatedAt,
			// Tenant fields
			&tenant.ID,
			&tenant.Name,
			&tenant.Slug,
			&tenant.Domain,
			&tenant.IsActive,
			&tenant.Settings,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
			// Role fields
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		userTenant.Tenant = &tenant
		userTenant.Role = &role
		userTenants = append(userTenants, &userTenant)
	}

	return userTenants, rows.Err()
}

// GetTenantUsers retrieves all users for a tenant
func (p *PostgresStorage) GetTenantUsers(tenantID uint) ([]*UserTenant, error) {
	query := fmt.Sprintf(`
		SELECT ut.%s, ut.%s, ut.%s, ut.%s, ut.%s,
			   r.%s, r.%s, r.%s, r.%s, r.%s, r.%s, r.%s
		FROM %s ut
		JOIN %s r ON ut.%s = r.%s
		WHERE ut.%s = $1
		ORDER BY ut.%s`,
		// UserTenant fields
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		// Role fields
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.TenantID,
		p.config.MultiTenant.RoleColumns.Name,
		p.config.MultiTenant.RoleColumns.Description,
		p.config.MultiTenant.RoleColumns.IsSystem,
		p.config.MultiTenant.RoleColumns.CreatedAt,
		p.config.MultiTenant.RoleColumns.UpdatedAt,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		// Join
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		// Where
		p.config.MultiTenant.UserTenantColumns.TenantID,
		// Order by
		p.config.MultiTenant.UserTenantColumns.CreatedAt,
	)

	rows, err := p.db.Query(query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userTenants []*UserTenant
	for rows.Next() {
		var userTenant UserTenant
		var role Role

		err := rows.Scan(
			// UserTenant fields
			&userTenant.UserID,
			&userTenant.TenantID,
			&userTenant.RoleID,
			&userTenant.CreatedAt,
			&userTenant.UpdatedAt,
			// Role fields
			&role.ID,
			&role.TenantID,
			&role.Name,
			&role.Description,
			&role.IsSystem,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		userTenant.Role = &role
		userTenants = append(userTenants, &userTenant)
	}

	return userTenants, rows.Err()
}

// UpdateUserTenantRole updates a user's role in a tenant
func (p *PostgresStorage) UpdateUserTenantRole(userID, tenantID, roleID uint) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = $1, %s = $2
		WHERE %s = $3 AND %s = $4`,
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.UserTenantColumns.UpdatedAt,
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
	)

	_, err := p.db.Exec(query, roleID, time.Now(), userID, tenantID)
	return err
}

// UserHasPermission checks if a user has a specific permission in a tenant
func (p *PostgresStorage) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM %s ut
		JOIN %s r ON ut.%s = r.%s
		JOIN %s rp ON r.%s = rp.%s
		JOIN %s p ON rp.%s = p.%s
		WHERE ut.%s = $1 AND ut.%s = $2 AND p.%s = $3`,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.PermissionsTable,
		// Joins
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.PermissionColumns.ID,
		// Where conditions
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		p.config.MultiTenant.PermissionColumns.Name,
	)

	var count int
	err := p.db.QueryRow(query, userID, tenantID, permission).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetUserPermissionsInTenant gets all permissions for a user in a specific tenant
func (p *PostgresStorage) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	query := fmt.Sprintf(`
		SELECT DISTINCT p.%s, p.%s, p.%s, p.%s, p.%s, p.%s, p.%s
		FROM %s ut
		JOIN %s r ON ut.%s = r.%s
		JOIN %s rp ON r.%s = rp.%s
		JOIN %s p ON rp.%s = p.%s
		WHERE ut.%s = $1 AND ut.%s = $2
		ORDER BY p.%s`,
		// Permission fields
		p.config.MultiTenant.PermissionColumns.ID,
		p.config.MultiTenant.PermissionColumns.Name,
		p.config.MultiTenant.PermissionColumns.Resource,
		p.config.MultiTenant.PermissionColumns.Action,
		p.config.MultiTenant.PermissionColumns.Description,
		p.config.MultiTenant.PermissionColumns.CreatedAt,
		p.config.MultiTenant.PermissionColumns.UpdatedAt,
		// Tables
		p.config.MultiTenant.UserTenantsTable,
		p.config.MultiTenant.RolesTable,
		p.config.MultiTenant.RolePermissionsTable,
		p.config.MultiTenant.PermissionsTable,
		// Joins
		p.config.MultiTenant.UserTenantColumns.RoleID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RoleColumns.ID,
		p.config.MultiTenant.RolePermissionColumns.RoleID,
		p.config.MultiTenant.RolePermissionColumns.PermissionID,
		p.config.MultiTenant.PermissionColumns.ID,
		// Where conditions
		p.config.MultiTenant.UserTenantColumns.UserID,
		p.config.MultiTenant.UserTenantColumns.TenantID,
		// Order by
		p.config.MultiTenant.PermissionColumns.Name,
	)

	rows, err := p.db.Query(query, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*Permission
	for rows.Next() {
		var permission Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, &permission)
	}

	return permissions, rows.Err()
}

// Close closes the database connection
func (p *PostgresStorage) Close() error {
	return p.db.Close()
}
