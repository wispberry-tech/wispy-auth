package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
	"github.com/wispberry-tech/wispy-auth/core/storage"
	"github.com/wispberry-tech/wispy-auth/referrals"
)

// SQLiteStorage wraps core SQLite storage and adds referral functionality
type SQLiteStorage struct {
	*storage.SQLiteStorage // Embed core SQLite storage
	db                     *sql.DB
}

// Ensure SQLiteStorage implements referrals.Storage interface
var _ referrals.Storage = (*SQLiteStorage)(nil)

// NewSQLiteStorage creates a new SQLite storage with referral support
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	// Create core storage first
	coreStorage, err := storage.NewSQLiteStorage(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create core storage: %w", err)
	}

	// Get the database connection from core storage instead of creating a new one
	// This prevents connection conflicts and statement name collisions
	db, err := coreStorage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection from core storage: %w", err)
	}

	// Auto-create missing referral tables using the shared connection
	schemaManager := referrals.NewReferralSchemaManager(db, "sqlite")
	if err := schemaManager.EnsureReferralSchema(); err != nil {
		return nil, fmt.Errorf("failed to ensure referral schema: %w", err)
	}

	return &SQLiteStorage{
		SQLiteStorage: coreStorage,
		db:            db,
	}, nil
}

// NewInMemorySQLiteStorage creates a new in-memory SQLite storage with referral support
func NewInMemorySQLiteStorage() (*SQLiteStorage, error) {
	// Create core storage first
	coreStorage, err := storage.NewInMemorySQLiteStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to create core storage: %w", err)
	}

	// Get the database connection from core storage instead of creating a new one
	// This prevents connection conflicts and maintains referential integrity
	db, err := coreStorage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection from core storage: %w", err)
	}

	// Auto-create missing referral tables using the shared connection
	schemaManager := referrals.NewReferralSchemaManager(db, "sqlite")
	if err := schemaManager.EnsureReferralSchema(); err != nil {
		return nil, fmt.Errorf("failed to ensure referral schema: %w", err)
	}

	return &SQLiteStorage{
		SQLiteStorage: coreStorage,
		db:            db,
	}, nil
}

// Referral Code operations

func (s *SQLiteStorage) CreateReferralCode(code *referrals.ReferralCode) error {
	query := `INSERT INTO referral_codes (code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		code.Code, code.GeneratedBy, code.MaxUses, code.CurrentUses,
		code.IsActive, code.ExpiresAt, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create referral code: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get referral code ID: %w", err)
	}

	code.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetReferralCodeByID(id uint) (*referrals.ReferralCode, error) {
	code := &referrals.ReferralCode{}
	query := `SELECT id, code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at
			  FROM referral_codes WHERE id = ?`

	err := s.db.QueryRow(query, id).Scan(
		&code.ID, &code.Code, &code.GeneratedBy, &code.MaxUses, &code.CurrentUses,
		&code.IsActive, &code.ExpiresAt, &code.CreatedAt, &code.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get referral code: %w", err)
	}

	return code, nil
}

func (s *SQLiteStorage) GetReferralCodeByCode(code string) (*referrals.ReferralCode, error) {
	refCode := &referrals.ReferralCode{}
	query := `SELECT id, code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at
			  FROM referral_codes WHERE code = ?`

	err := s.db.QueryRow(query, code).Scan(
		&refCode.ID, &refCode.Code, &refCode.GeneratedBy, &refCode.MaxUses, &refCode.CurrentUses,
		&refCode.IsActive, &refCode.ExpiresAt, &refCode.CreatedAt, &refCode.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get referral code: %w", err)
	}

	return refCode, nil
}

func (s *SQLiteStorage) GetReferralCodesByUser(userID uint) ([]*referrals.ReferralCode, error) {
	query := `SELECT id, code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at
			  FROM referral_codes WHERE generated_by = ? ORDER BY created_at DESC`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get referral codes: %w", err)
	}
	defer rows.Close()

	var codes []*referrals.ReferralCode
	for rows.Next() {
		code := &referrals.ReferralCode{}
		err := rows.Scan(
			&code.ID, &code.Code, &code.GeneratedBy, &code.MaxUses, &code.CurrentUses,
			&code.IsActive, &code.ExpiresAt, &code.CreatedAt, &code.UpdatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan referral code: %w", err)
		}
		codes = append(codes, code)
	}

	return codes, nil
}

func (s *SQLiteStorage) UpdateReferralCode(code *referrals.ReferralCode) error {
	query := `UPDATE referral_codes SET code = ?, max_uses = ?, current_uses = ?,
			  is_active = ?, expires_at = ?, updated_at = ?
			  WHERE id = ?`

	_, err := s.db.Exec(query,
		code.Code, code.MaxUses, code.CurrentUses, code.IsActive,
		code.ExpiresAt, time.Now(), code.ID)

	if err != nil {
		return fmt.Errorf("failed to update referral code: %w", err)
	}

	return nil
}

func (s *SQLiteStorage) DeactivateReferralCode(codeID uint) error {
	query := `UPDATE referral_codes SET is_active = FALSE, updated_at = ? WHERE id = ?`
	_, err := s.db.Exec(query, time.Now(), codeID)
	if err != nil {
		return fmt.Errorf("failed to deactivate referral code: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) IncrementReferralCodeUse(codeID uint) error {
	query := `UPDATE referral_codes SET current_uses = current_uses + 1, updated_at = ? WHERE id = ?`
	_, err := s.db.Exec(query, time.Now(), codeID)
	if err != nil {
		return fmt.Errorf("failed to increment referral code use: %w", err)
	}
	return nil
}

// Referral Relationship operations

func (s *SQLiteStorage) CreateReferralRelationship(relationship *referrals.ReferralRelationship) error {
	query := `INSERT INTO referral_relationships (referrer_user_id, referred_user_id, referral_code_id, created_at)
			  VALUES (?, ?, ?, ?)`

	result, err := s.db.Exec(query,
		relationship.ReferrerUserID, relationship.ReferredUserID,
		relationship.ReferralCodeID, time.Now())

	if err != nil {
		return fmt.Errorf("failed to create referral relationship: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get referral relationship ID: %w", err)
	}

	relationship.ID = uint(id)
	return nil
}

func (s *SQLiteStorage) GetReferralRelationshipsByReferrer(referrerUserID uint) ([]*referrals.ReferralRelationship, error) {
	query := `SELECT id, referrer_user_id, referred_user_id, referral_code_id, created_at
			  FROM referral_relationships WHERE referrer_user_id = ? ORDER BY created_at DESC`

	rows, err := s.db.Query(query, referrerUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get referral relationships: %w", err)
	}
	defer rows.Close()

	var relationships []*referrals.ReferralRelationship
	for rows.Next() {
		rel := &referrals.ReferralRelationship{}
		err := rows.Scan(&rel.ID, &rel.ReferrerUserID, &rel.ReferredUserID,
			&rel.ReferralCodeID, &rel.CreatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan referral relationship: %w", err)
		}
		relationships = append(relationships, rel)
	}

	return relationships, nil
}

func (s *SQLiteStorage) GetReferralRelationshipsByReferred(referredUserID uint) ([]*referrals.ReferralRelationship, error) {
	query := `SELECT id, referrer_user_id, referred_user_id, referral_code_id, created_at
			  FROM referral_relationships WHERE referred_user_id = ?`

	rows, err := s.db.Query(query, referredUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get referral relationships: %w", err)
	}
	defer rows.Close()

	var relationships []*referrals.ReferralRelationship
	for rows.Next() {
		rel := &referrals.ReferralRelationship{}
		err := rows.Scan(&rel.ID, &rel.ReferrerUserID, &rel.ReferredUserID,
			&rel.ReferralCodeID, &rel.CreatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan referral relationship: %w", err)
		}
		relationships = append(relationships, rel)
	}

	return relationships, nil
}

func (s *SQLiteStorage) GetReferralRelationshipByUsers(referrerUserID, referredUserID uint) (*referrals.ReferralRelationship, error) {
	rel := &referrals.ReferralRelationship{}
	query := `SELECT id, referrer_user_id, referred_user_id, referral_code_id, created_at
			  FROM referral_relationships WHERE referrer_user_id = ? AND referred_user_id = ?`

	err := s.db.QueryRow(query, referrerUserID, referredUserID).Scan(
		&rel.ID, &rel.ReferrerUserID, &rel.ReferredUserID, &rel.ReferralCodeID, &rel.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get referral relationship: %w", err)
	}

	return rel, nil
}

// Referral Statistics

func (s *SQLiteStorage) GetReferralStats(userID uint) (*referrals.ReferralStats, error) {
	stats := &referrals.ReferralStats{}
	query := `SELECT user_id, total_referred, active_codes, total_codes_used, successful_signups
			  FROM referral_stats WHERE user_id = ?`

	err := s.db.QueryRow(query, userID).Scan(
		&stats.UserID, &stats.TotalReferred, &stats.ActiveCodes,
		&stats.TotalCodesUsed, &stats.SuccessfulSignups)

	if err != nil {
		if err == sql.ErrNoRows {
			// Return empty stats for user
			return &referrals.ReferralStats{UserID: userID}, nil
		}
		return nil, fmt.Errorf("failed to get referral stats: %w", err)
	}

	return stats, nil
}

func (s *SQLiteStorage) GetTopReferrers(limit int) ([]*referrals.ReferralStats, error) {
	query := `SELECT user_id, total_referred, active_codes, total_codes_used, successful_signups
			  FROM referral_stats WHERE total_referred > 0
			  ORDER BY total_referred DESC, total_codes_used DESC
			  LIMIT ?`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get top referrers: %w", err)
	}
	defer rows.Close()

	var stats []*referrals.ReferralStats
	for rows.Next() {
		stat := &referrals.ReferralStats{}
		err := rows.Scan(&stat.UserID, &stat.TotalReferred, &stat.ActiveCodes,
			&stat.TotalCodesUsed, &stat.SuccessfulSignups)

		if err != nil {
			return nil, fmt.Errorf("failed to scan referral stats: %w", err)
		}
		stats = append(stats, stat)
	}

	return stats, nil
}

// Validation and constraints

func (s *SQLiteStorage) ValidateReferralCode(code string) (*referrals.ReferralCode, error) {
	refCode, err := s.GetReferralCodeByCode(code)
	if err != nil {
		return nil, err
	}

	if refCode == nil {
		return nil, nil
	}

	// Check if code is usable
	if !refCode.IsUsable() {
		return nil, nil
	}

	return refCode, nil
}

func (s *SQLiteStorage) CheckCodeAvailability(code string) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM referral_codes WHERE code = ?`
	err := s.db.QueryRow(query, code).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check code availability: %w", err)
	}
	return count == 0, nil
}

func (s *SQLiteStorage) CountActiveReferralCodes(userID uint) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM referral_codes
			  WHERE generated_by = ? AND is_active = TRUE
			  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`
	err := s.db.QueryRow(query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active referral codes: %w", err)
	}
	return count, nil
}

// ProcessReferralCodeUse atomically processes referral code usage
func (s *SQLiteStorage) ProcessReferralCodeUse(codeID, referrerUserID, referredUserID uint, maxUses int) error {
	// Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Rollback transaction if we exit with an error
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Create referral relationship
	relationshipQuery := `INSERT INTO referral_relationships (referrer_user_id, referred_user_id, referral_code_id, created_at)
						  VALUES (?, ?, ?, ?)`
	_, err = tx.Exec(relationshipQuery, referrerUserID, referredUserID, codeID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to create referral relationship: %w", err)
	}

	// Increment code usage and get current count
	var currentUses int
	incrementQuery := `UPDATE referral_codes SET current_uses = current_uses + 1, updated_at = ?
					   WHERE id = ? RETURNING current_uses`
	err = tx.QueryRow(incrementQuery, time.Now(), codeID).Scan(&currentUses)
	if err != nil {
		return fmt.Errorf("failed to increment referral code usage: %w", err)
	}

	// Check if code should be deactivated (reached max uses)
	if maxUses > 0 && currentUses >= maxUses {
		deactivateQuery := `UPDATE referral_codes SET is_active = FALSE, updated_at = ? WHERE id = ?`
		_, err = tx.Exec(deactivateQuery, time.Now(), codeID)
		if err != nil {
			return fmt.Errorf("failed to deactivate referral code: %w", err)
		}
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Close closes the storage connection
func (s *SQLiteStorage) Close() error {
	// Only close the core storage, as we're sharing the database connection
	// The core storage will handle closing the actual database connection
	return s.SQLiteStorage.Close()
}
