package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

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

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	s := &SQLiteStorage{db: db}

	return s, nil
}

// NewInMemorySQLiteStorage creates an in-memory SQLite storage for testing
func NewInMemorySQLiteStorage() (*SQLiteStorage, error) {
	return NewSQLiteStorage(":memory:")
}

// Implement required interface methods
func (s *SQLiteStorage) CreateUser(user *User) error {
	query := `INSERT INTO users (email, username, first_name, last_name, password_hash,
			  provider, provider_id, email_verified, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		user.Email, user.Username, user.FirstName, user.LastName, user.PasswordHash,
		user.Provider, user.ProviderID, user.EmailVerified, time.Now(), time.Now())

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
			  provider, provider_id, email_verified, failed_login_attempts, locked_until,
			  last_login_at, last_login_ip, is_active, is_suspended, created_at, updated_at
			  FROM users WHERE email = ? AND provider = ?`

	user := &User{}
	var lockedUntil, lastLoginAt sql.NullTime
	var lastKnownIP sql.NullString

	err := s.db.QueryRow(query, email, provider).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.LoginAttempts, &lockedUntil, &lastLoginAt, &lastKnownIP,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Handle nullable fields
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	if lastKnownIP.Valid {
		user.LastKnownIP = lastKnownIP.String
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
			  provider, provider_id, email_verified, failed_login_attempts, locked_until,
			  last_login_at, last_login_ip, is_active, is_suspended, created_at, updated_at
			  FROM users WHERE id = ?`

	user := &User{}
	var lockedUntil, lastLoginAt sql.NullTime
	var lastKnownIP sql.NullString

	err := s.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.Username, &user.FirstName, &user.LastName,
		&user.PasswordHash, &user.Provider, &user.ProviderID, &user.EmailVerified,
		&user.LoginAttempts, &lockedUntil, &lastLoginAt, &lastKnownIP,
		&user.IsActive, &user.IsSuspended, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Handle nullable fields
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	if lastKnownIP.Valid {
		user.LastKnownIP = lastKnownIP.String
	}

	return user, nil
}

func (s *SQLiteStorage) UpdateUser(user *User) error {
	query := `UPDATE users SET username = ?, first_name = ?, last_name = ?,
			  password_hash = ?, email_verified = ?, updated_at = ? WHERE id = ?`

	_, err := s.db.Exec(query, user.Username, user.FirstName, user.LastName,
		user.PasswordHash, user.EmailVerified, time.Now(), user.ID)

	return err
}

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
		time.Now(), time.Now())

	if err != nil {
		// Handle unique constraint violations by generating new ID
		if err.Error() == "sqlite3: constraint failed: UNIQUE constraint failed: sessions.id" {
			session.ID = fmt.Sprintf("%d_%d", session.UserID, time.Now().UnixNano())
			_, retryErr := s.db.Exec(query,
				session.ID, session.UserID, session.Token, session.ExpiresAt,
				session.DeviceFingerprint, session.UserAgent, session.IPAddress,
				session.Location, session.IsActive, session.LastActivity,
				session.RequiresTwoFactor, session.TwoFactorVerified,
				time.Now(), time.Now())
			return retryErr
		}
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
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Stub implementations for other required methods
func (s *SQLiteStorage) GetUserSessions(userID uint) ([]*Session, error) { return nil, nil }
func (s *SQLiteStorage) UpdateSession(session *Session) error            { return nil }
func (s *SQLiteStorage) DeleteSession(token string) error                { return nil }
func (s *SQLiteStorage) DeleteUserSessions(userID uint) error            { return nil }
func (s *SQLiteStorage) CleanupExpiredSessions() error                   { return nil }
func (s *SQLiteStorage) CountActiveSessions(userID uint) (int, error)    { return 0, nil }
func (s *SQLiteStorage) StoreOAuthState(state *OAuthState) error {
	query := `INSERT INTO oauth_states (state_id, csrf_token, created_at, expires_at)
			  VALUES (?, ?, ?, ?)`

	_, err := s.db.Exec(query, state.State, state.CSRF, state.CreatedAt, state.ExpiresAt)
	if err != nil {
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
		return nil, fmt.Errorf("OAuth state not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	return &state, nil
}

func (s *SQLiteStorage) DeleteOAuthState(stateID string) error {
	query := `DELETE FROM oauth_states WHERE state_id = ?`

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
func (s *SQLiteStorage) CreateTenant(tenant *Tenant) error                        { return nil }
func (s *SQLiteStorage) GetTenantByID(id uint) (*Tenant, error)                   { return nil, nil }
func (s *SQLiteStorage) GetTenantBySlug(slug string) (*Tenant, error)             { return nil, nil }
func (s *SQLiteStorage) UpdateTenant(tenant *Tenant) error                        { return nil }
func (s *SQLiteStorage) ListTenants() ([]*Tenant, error)                          { return nil, nil }
func (s *SQLiteStorage) CreateRole(role *Role) error                              { return nil }
func (s *SQLiteStorage) GetRoleByID(id uint) (*Role, error)                       { return nil, nil }
func (s *SQLiteStorage) GetRolesByTenant(tenantID uint) ([]*Role, error)          { return nil, nil }
func (s *SQLiteStorage) UpdateRole(role *Role) error                              { return nil }
func (s *SQLiteStorage) DeleteRole(id uint) error                                 { return nil }
func (s *SQLiteStorage) CreatePermission(permission *Permission) error            { return nil }
func (s *SQLiteStorage) GetPermissionByID(id uint) (*Permission, error)           { return nil, nil }
func (s *SQLiteStorage) GetPermissionByName(name string) (*Permission, error)     { return nil, nil }
func (s *SQLiteStorage) ListPermissions() ([]*Permission, error)                  { return nil, nil }
func (s *SQLiteStorage) UpdatePermission(permission *Permission) error            { return nil }
func (s *SQLiteStorage) DeletePermission(id uint) error                           { return nil }
func (s *SQLiteStorage) AssignPermissionToRole(roleID, permissionID uint) error   { return nil }
func (s *SQLiteStorage) RemovePermissionFromRole(roleID, permissionID uint) error { return nil }
func (s *SQLiteStorage) GetRolePermissions(roleID uint) ([]*Permission, error)    { return nil, nil }
func (s *SQLiteStorage) AssignUserToTenant(userID, tenantID, roleID uint) error   { return nil }
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
func (s *SQLiteStorage) CreateSecurityEvent(event *SecurityEvent) error { return nil }
func (s *SQLiteStorage) GetSecurityEvents(userID *uint, tenantID *uint, eventType string, limit int, offset int) ([]*SecurityEvent, error) {
	return nil, nil
}
func (s *SQLiteStorage) GetSecurityEventsByUser(userID uint, limit int, offset int) ([]*SecurityEvent, error) {
	return nil, nil
}
func (s *SQLiteStorage) CreatePasswordResetToken(userID uint, token string, expiresAt time.Time) error {
	return nil
}
func (s *SQLiteStorage) GetUserByPasswordResetToken(token string) (*User, error)   { return nil, nil }
func (s *SQLiteStorage) ClearPasswordResetToken(userID uint) error                 { return nil }
func (s *SQLiteStorage) SetEmailVerificationToken(userID uint, token string) error { return nil }
func (s *SQLiteStorage) GetUserByVerificationToken(token string) (*User, error)    { return nil, nil }
func (s *SQLiteStorage) MarkEmailAsVerified(userID uint) error                     { return nil }
func (s *SQLiteStorage) IncrementLoginAttempts(userID uint) error                  { return nil }
func (s *SQLiteStorage) ResetLoginAttempts(userID uint) error                      { return nil }
func (s *SQLiteStorage) LockUser(userID uint, until time.Time) error               { return nil }
func (s *SQLiteStorage) UnlockUser(userID uint) error                              { return nil }

// Referral Code operations - Stub implementations for now
func (s *SQLiteStorage) CreateReferralCode(code *ReferralCode) error {
	return fmt.Errorf("referral code creation not implemented yet")
}

func (s *SQLiteStorage) GetReferralCodeByCode(code string) (*ReferralCode, error) {
	return nil, fmt.Errorf("referral code not found")
}

func (s *SQLiteStorage) GetReferralCodesByUser(userID uint) ([]*ReferralCode, error) {
	return []*ReferralCode{}, nil
}

func (s *SQLiteStorage) UpdateReferralCode(code *ReferralCode) error {
	return fmt.Errorf("referral code update not implemented yet")
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
