package auth

import (
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// PostgresStorage implements StorageInterface for PostgreSQL databases
type PostgresStorage struct {
	db     *gorm.DB
	config StorageConfig
}

// NewPostgresStorage creates a new PostgreSQL storage instance
func NewPostgresStorage(dsn string, config StorageConfig) (StorageInterface, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
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
		INSERT INTO %s (%s, %s, %s, %s, %s, %s, %s, %s) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) 
		RETURNING %s`,
		p.config.UsersTable,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Name,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	return p.db.Raw(query,
		user.Email,
		user.PasswordHash,
		user.Name,
		user.AvatarURL,
		user.Provider,
		user.ProviderID,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(&user.ID).Error
}

// GetUserByEmail retrieves a user by email and provider
func (p *PostgresStorage) GetUserByEmail(email, provider string) (*User, error) {
	var user User
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ? AND %s = ?`,
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Name,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UsersTable,
		p.config.UserColumns.Email,
		p.config.UserColumns.Provider,
	)

	err := p.db.Raw(query, email, provider).Scan(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByEmailAnyProvider retrieves a user by email regardless of provider
func (p *PostgresStorage) GetUserByEmailAnyProvider(email string) (*User, error) {
	var user User
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?`,
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Name,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UsersTable,
		p.config.UserColumns.Email,
	)

	err := p.db.Raw(query, email).Scan(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByProviderID retrieves a user by provider and provider ID
func (p *PostgresStorage) GetUserByProviderID(provider, providerID string) (*User, error) {
	var user User
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ? AND %s = ?`,
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Name,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UsersTable,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
	)

	err := p.db.Raw(query, provider, providerID).Scan(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (p *PostgresStorage) GetUserByID(id uint) (*User, error) {
	var user User
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?`,
		p.config.UserColumns.ID,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Name,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		p.config.UserColumns.CreatedAt,
		p.config.UserColumns.UpdatedAt,
		p.config.UsersTable,
		p.config.UserColumns.ID,
	)

	err := p.db.Raw(query, id).Scan(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates an existing user
func (p *PostgresStorage) UpdateUser(user *User) error {
	query := fmt.Sprintf(`
		UPDATE %s 
		SET %s = ?, %s = ?, %s = ?, %s = ?, %s = ?, %s = ?, %s = ?
		WHERE %s = ?`,
		p.config.UsersTable,
		p.config.UserColumns.Email,
		p.config.UserColumns.PasswordHash,
		p.config.UserColumns.Name,
		p.config.UserColumns.AvatarURL,
		p.config.UserColumns.Provider,
		p.config.UserColumns.ProviderID,
		p.config.UserColumns.UpdatedAt,
		p.config.UserColumns.ID,
	)

	user.UpdatedAt = time.Now()

	return p.db.Exec(query,
		user.Email,
		user.PasswordHash,
		user.Name,
		user.AvatarURL,
		user.Provider,
		user.ProviderID,
		user.UpdatedAt,
		user.ID,
	).Error
}

// CreateSession creates a new session
func (p *PostgresStorage) CreateSession(session *Session) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		p.config.SessionsTable,
		p.config.SessionColumns.ID,
		p.config.SessionColumns.UserID,
		p.config.SessionColumns.Token,
		p.config.SessionColumns.ExpiresAt,
		p.config.SessionColumns.CreatedAt,
		p.config.SessionColumns.UpdatedAt,
	)

	now := time.Now()
	session.CreatedAt = now
	session.UpdatedAt = now

	return p.db.Exec(query,
		session.ID,
		session.UserID,
		session.Token,
		session.ExpiresAt,
		session.CreatedAt,
		session.UpdatedAt,
	).Error
}

// GetSession retrieves a session by token
func (p *PostgresStorage) GetSession(token string) (*Session, error) {
	var session Session
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ? AND %s > ?`,
		p.config.SessionColumns.ID,
		p.config.SessionColumns.UserID,
		p.config.SessionColumns.Token,
		p.config.SessionColumns.ExpiresAt,
		p.config.SessionColumns.CreatedAt,
		p.config.SessionColumns.UpdatedAt,
		p.config.SessionsTable,
		p.config.SessionColumns.Token,
		p.config.SessionColumns.ExpiresAt,
	)

	err := p.db.Raw(query, token, time.Now()).Scan(&session).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return &session, nil
}

// DeleteSession deletes a session by token
func (p *PostgresStorage) DeleteSession(token string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, p.config.SessionsTable, p.config.SessionColumns.Token)
	return p.db.Exec(query, token).Error
}

// DeleteUserSessions deletes all sessions for a user
func (p *PostgresStorage) DeleteUserSessions(userID uint) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, p.config.SessionsTable, p.config.SessionColumns.UserID)
	return p.db.Exec(query, userID).Error
}

// CleanupExpiredSessions removes all expired sessions
func (p *PostgresStorage) CleanupExpiredSessions() error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s < ?`, p.config.SessionsTable, p.config.SessionColumns.ExpiresAt)
	return p.db.Exec(query, time.Now()).Error
}

// Close closes the database connection
func (p *PostgresStorage) Close() error {
	sqlDB, err := p.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}