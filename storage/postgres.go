package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStorage implements Interface for PostgreSQL databases
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

	return storage, nil
}

// User operations
func (p *PostgresStorage) CreateUser(user *User) error {
	query := `INSERT INTO users (email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`

	err := p.db.QueryRow(query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified, user.IsActive, user.IsSuspended,
		time.Now(), time.Now()).Scan(&user.ID)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetUserByEmail(email, provider string) (*User, error) {
	query := `SELECT id, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE email = $1 AND provider = $2`

	user := &User{}

	err := p.db.QueryRow(query, email, provider).Scan(
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

func (p *PostgresStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	return p.GetUserByEmail(email, "email")
}

func (p *PostgresStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *PostgresStorage) GetUserByID(id uint) (*User, error) {
	query := `SELECT id, email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, is_active, is_suspended,
			  created_at, updated_at
			  FROM users WHERE id = $1`

	user := &User{}

	err := p.db.QueryRow(query, id).Scan(
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

func (p *PostgresStorage) UpdateUser(user *User) error {
	query := `UPDATE users SET username = $1, first_name = $2, last_name = $3,
			  password_hash = $4, email_verified = $5, is_active = $6, is_suspended = $7,
			  updated_at = $8 WHERE id = $9`

	_, err := p.db.Exec(query, user.Username, user.FirstName, user.LastName,
		user.PasswordHash, user.EmailVerified, user.IsActive, user.IsSuspended,
		time.Now(), user.ID)

	return err
}

// UserSecurity operations
func (p *PostgresStorage) CreateUserSecurity(security *UserSecurity) error {
	query := `INSERT INTO user_security (user_id, email_verified_at, verification_token,
			  password_reset_token, password_reset_expires_at, password_changed_at,
			  login_attempts, last_failed_login_at, locked_until, last_login_at,
			  last_known_ip, last_login_location, two_factor_enabled, two_factor_secret,
			  backup_codes, suspended_at, suspend_reason, referred_by_code,
			  created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`

	_, err := p.db.Exec(query,
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

func (p *PostgresStorage) GetUserSecurity(userID uint) (*UserSecurity, error) {
	query := `SELECT user_id, email_verified_at, verification_token,
			  password_reset_token, password_reset_expires_at, password_changed_at,
			  login_attempts, last_failed_login_at, locked_until, last_login_at,
			  last_known_ip, last_login_location, two_factor_enabled, two_factor_secret,
			  backup_codes, suspended_at, suspend_reason, referred_by_code,
			  created_at, updated_at
			  FROM user_security WHERE user_id = $1`

	security := &UserSecurity{}
	var emailVerifiedAt, passwordResetExpiresAt, passwordChangedAt sql.NullTime
	var lastFailedLoginAt, lockedUntil, lastLoginAt, suspendedAt sql.NullTime
	var verificationToken, passwordResetToken sql.NullString
	var lastKnownIP, lastLoginLocation, twoFactorSecret, backupCodes sql.NullString
	var suspendReason, referredByCode sql.NullString

	err := p.db.QueryRow(query, userID).Scan(
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

	// Handle nullable fields (same logic as SQLite)
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

func (p *PostgresStorage) UpdateUserSecurity(security *UserSecurity) error {
	query := `UPDATE user_security SET email_verified_at = $1, verification_token = $2,
			  password_reset_token = $3, password_reset_expires_at = $4, password_changed_at = $5,
			  login_attempts = $6, last_failed_login_at = $7, locked_until = $8, last_login_at = $9,
			  last_known_ip = $10, last_login_location = $11, two_factor_enabled = $12, two_factor_secret = $13,
			  backup_codes = $14, suspended_at = $15, suspend_reason = $16, referred_by_code = $17,
			  updated_at = $18 WHERE user_id = $19`

	_, err := p.db.Exec(query,
		security.EmailVerifiedAt, security.VerificationToken,
		security.PasswordResetToken, security.PasswordResetExpiresAt, security.PasswordChangedAt,
		security.LoginAttempts, security.LastFailedLoginAt, security.LockedUntil, security.LastLoginAt,
		security.LastKnownIP, security.LastLoginLocation, security.TwoFactorEnabled, security.TwoFactorSecret,
		security.BackupCodes, security.SuspendedAt, security.SuspendReason, security.ReferredByCode,
		time.Now(), security.UserID)

	return err
}

// Optimized security operations for common use cases
func (p *PostgresStorage) IncrementLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = login_attempts + 1,
			  last_failed_login_at = $1, updated_at = $2 WHERE user_id = $3`
	_, err := p.db.Exec(query, time.Now(), time.Now(), userID)
	return err
}

func (p *PostgresStorage) ResetLoginAttempts(userID uint) error {
	query := `UPDATE user_security SET login_attempts = 0, locked_until = NULL,
			  updated_at = $1 WHERE user_id = $2`
	_, err := p.db.Exec(query, time.Now(), userID)
	return err
}

func (p *PostgresStorage) SetUserLocked(userID uint, until time.Time) error {
	query := `UPDATE user_security SET locked_until = $1, updated_at = $2 WHERE user_id = $3`
	_, err := p.db.Exec(query, until, time.Now(), userID)
	return err
}

func (p *PostgresStorage) UpdateLastLogin(userID uint, ipAddress string) error {
	query := `UPDATE user_security SET last_login_at = $1, last_known_ip = $2,
			  updated_at = $3 WHERE user_id = $4`
	_, err := p.db.Exec(query, time.Now(), ipAddress, time.Now(), userID)
	return err
}

// Session operations
func (p *PostgresStorage) CreateSession(session *Session) error {
	query := `INSERT INTO sessions (id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, location, is_active, last_activity,
			  requires_two_factor, two_factor_verified, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := p.db.Exec(query,
		session.ID, session.UserID, session.Token, session.ExpiresAt,
		session.DeviceFingerprint, session.UserAgent, session.IPAddress,
		session.Location, session.IsActive, session.LastActivity,
		session.RequiresTwoFactor, session.TwoFactorVerified,
		time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

func (p *PostgresStorage) GetSession(token string) (*Session, error) {
	query := `SELECT id, user_id, token, expires_at, device_fingerprint,
			  user_agent, ip_address, location, is_active, last_activity,
			  requires_two_factor, two_factor_verified, created_at, updated_at
			  FROM sessions WHERE token = $1 AND is_active = TRUE`

	session := &Session{}
	err := p.db.QueryRow(query, token).Scan(
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
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

// OAuth operations
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

func (p *PostgresStorage) Close() error {
	return p.db.Close()
}

// Stub implementations for other required methods
func (p *PostgresStorage) GetUserSessions(userID uint) ([]*Session, error)          { return nil, nil }
func (p *PostgresStorage) UpdateSession(session *Session) error                     { return nil }
func (p *PostgresStorage) DeleteSession(token string) error                         { return nil }
func (p *PostgresStorage) DeleteUserSessions(userID uint) error                     { return nil }
func (p *PostgresStorage) CleanupExpiredSessions() error                            { return nil }
func (p *PostgresStorage) CountActiveSessions(userID uint) (int, error)             { return 0, nil }
func (p *PostgresStorage) CreateTenant(tenant *Tenant) error                        { return nil }
func (p *PostgresStorage) GetTenantByID(id uint) (*Tenant, error)                   { return nil, nil }
func (p *PostgresStorage) GetTenantBySlug(slug string) (*Tenant, error)             { return nil, nil }
func (p *PostgresStorage) UpdateTenant(tenant *Tenant) error                        { return nil }
func (p *PostgresStorage) ListTenants() ([]*Tenant, error)                          { return nil, nil }
func (p *PostgresStorage) CreateRole(role *Role) error                              { return nil }
func (p *PostgresStorage) GetRoleByID(id uint) (*Role, error)                       { return nil, nil }
func (p *PostgresStorage) GetRolesByTenant(tenantID uint) ([]*Role, error)          { return nil, nil }
func (p *PostgresStorage) UpdateRole(role *Role) error                              { return nil }
func (p *PostgresStorage) DeleteRole(id uint) error                                 { return nil }
func (p *PostgresStorage) CreatePermission(permission *Permission) error            { return nil }
func (p *PostgresStorage) GetPermissionByID(id uint) (*Permission, error)           { return nil, nil }
func (p *PostgresStorage) GetPermissionByName(name string) (*Permission, error)     { return nil, nil }
func (p *PostgresStorage) ListPermissions() ([]*Permission, error)                  { return nil, nil }
func (p *PostgresStorage) UpdatePermission(permission *Permission) error            { return nil }
func (p *PostgresStorage) DeletePermission(id uint) error                           { return nil }
func (p *PostgresStorage) AssignPermissionToRole(roleID, permissionID uint) error   { return nil }
func (p *PostgresStorage) RemovePermissionFromRole(roleID, permissionID uint) error { return nil }
func (p *PostgresStorage) GetRolePermissions(roleID uint) ([]*Permission, error)    { return nil, nil }
func (p *PostgresStorage) AssignUserToTenant(userID, tenantID, roleID uint) error   { return nil }
func (p *PostgresStorage) RemoveUserFromTenant(userID, tenantID uint) error         { return nil }
func (p *PostgresStorage) GetUserTenants(userID uint) ([]*UserTenant, error)        { return nil, nil }
func (p *PostgresStorage) GetTenantUsers(tenantID uint) ([]*UserTenant, error)      { return nil, nil }
func (p *PostgresStorage) UpdateUserTenantRole(userID, tenantID, roleID uint) error { return nil }
func (p *PostgresStorage) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	return false, nil
}
func (p *PostgresStorage) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	return nil, nil
}
func (p *PostgresStorage) CreateSecurityEvent(event *SecurityEvent) error { return nil }
func (p *PostgresStorage) GetSecurityEvents(userID *uint, tenantID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	return nil, nil
}
func (p *PostgresStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return nil, nil
}
func (p *PostgresStorage) CreatePasswordResetToken(userID uint, token string, expiresAt time.Time) error {
	return nil
}
func (p *PostgresStorage) GetUserByPasswordResetToken(token string) (*User, error) { return nil, nil }
func (p *PostgresStorage) GetUserByVerificationToken(token string) (*User, error)  { return nil, nil }

// Referral Code operations - Stub implementations for now
func (p *PostgresStorage) CreateReferralCode(code *ReferralCode) error {
	return fmt.Errorf("referral code creation not implemented yet")
}

func (p *PostgresStorage) GetReferralCodeByCode(code string) (*ReferralCode, error) {
	return nil, fmt.Errorf("referral code not found")
}

func (p *PostgresStorage) GetReferralCodesByUser(userID uint) ([]*ReferralCode, error) {
	return []*ReferralCode{}, nil
}

func (p *PostgresStorage) UpdateReferralCode(code *ReferralCode) error {
	return fmt.Errorf("referral code update not implemented yet")
}

func (p *PostgresStorage) DeactivateReferralCode(codeID uint) error {
	return fmt.Errorf("referral code deactivation not implemented yet")
}

func (p *PostgresStorage) CountActiveReferralsByUserRole(userID, roleID uint) (int, error) {
	return 0, nil
}

// User Referral operations - Stub implementations for now
func (p *PostgresStorage) CreateUserReferral(referral *UserReferral) error {
	return fmt.Errorf("user referral creation not implemented yet")
}

func (p *PostgresStorage) GetUserReferralsByReferrer(referrerUserID uint) ([]*UserReferral, error) {
	return []*UserReferral{}, nil
}

func (p *PostgresStorage) GetUserReferralByReferred(referredUserID uint) (*UserReferral, error) {
	return nil, fmt.Errorf("user referral not found")
}

func (p *PostgresStorage) GetReferralStatsByUser(userID uint) (int, int, error) {
	return 0, 0, nil
}
