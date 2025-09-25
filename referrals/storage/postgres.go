package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/wispberry-tech/wispy-auth/core/storage"
	"github.com/wispberry-tech/wispy-auth/referrals"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStorage wraps core PostgreSQL storage and adds referral functionality
type PostgresStorage struct {
	*storage.PostgresStorage // Embed core PostgreSQL storage
	db                       *sql.DB
}

// Ensure PostgresStorage implements referrals.Storage interface
var _ referrals.Storage = (*PostgresStorage)(nil)

// NewPostgresStorage creates a new PostgreSQL storage with referral support
func NewPostgresStorage(databaseDSN string) (*PostgresStorage, error) {
	// Create core storage first
	coreStorage, err := storage.NewPostgresStorage(databaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to create core storage: %w", err)
	}

	// Parse the connection string for referral operations
	config, err := pgx.ParseConfig(databaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database DSN: %w", err)
	}

	// Create database connection
	db := stdlib.OpenDB(*config)

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-create missing referral tables
	schemaManager := referrals.NewReferralSchemaManager(db, "postgres")
	if err := schemaManager.EnsureReferralSchema(); err != nil {
		return nil, fmt.Errorf("failed to ensure referral schema: %w", err)
	}

	return &PostgresStorage{
		PostgresStorage: coreStorage,
		db:              db,
	}, nil
}

// Referral Code operations

func (s *PostgresStorage) CreateReferralCode(code *referrals.ReferralCode) error {
	query := `INSERT INTO referral_codes (code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`

	err := s.db.QueryRow(query,
		code.Code, code.GeneratedBy, code.MaxUses, code.CurrentUses,
		code.IsActive, code.ExpiresAt, time.Now(), time.Now()).Scan(&code.ID)

	if err != nil {
		return fmt.Errorf("failed to create referral code: %w", err)
	}

	return nil
}

func (s *PostgresStorage) GetReferralCodeByID(id uint) (*referrals.ReferralCode, error) {
	code := &referrals.ReferralCode{}
	query := `SELECT id, code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at
			  FROM referral_codes WHERE id = $1`

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

func (s *PostgresStorage) GetReferralCodeByCode(code string) (*referrals.ReferralCode, error) {
	refCode := &referrals.ReferralCode{}
	query := `SELECT id, code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at
			  FROM referral_codes WHERE code = $1`

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

func (s *PostgresStorage) GetReferralCodesByUser(userID uint) ([]*referrals.ReferralCode, error) {
	query := `SELECT id, code, generated_by, max_uses, current_uses, is_active, expires_at, created_at, updated_at
			  FROM referral_codes WHERE generated_by = $1 ORDER BY created_at DESC`

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

func (s *PostgresStorage) UpdateReferralCode(code *referrals.ReferralCode) error {
	query := `UPDATE referral_codes SET code = $1, max_uses = $2, current_uses = $3,
			  is_active = $4, expires_at = $5, updated_at = $6
			  WHERE id = $7`

	_, err := s.db.Exec(query,
		code.Code, code.MaxUses, code.CurrentUses, code.IsActive,
		code.ExpiresAt, time.Now(), code.ID)

	if err != nil {
		return fmt.Errorf("failed to update referral code: %w", err)
	}

	return nil
}

func (s *PostgresStorage) DeactivateReferralCode(codeID uint) error {
	query := `UPDATE referral_codes SET is_active = FALSE, updated_at = $1 WHERE id = $2`
	_, err := s.db.Exec(query, time.Now(), codeID)
	if err != nil {
		return fmt.Errorf("failed to deactivate referral code: %w", err)
	}
	return nil
}

func (s *PostgresStorage) IncrementReferralCodeUse(codeID uint) error {
	query := `UPDATE referral_codes SET current_uses = current_uses + 1, updated_at = $1 WHERE id = $2`
	_, err := s.db.Exec(query, time.Now(), codeID)
	if err != nil {
		return fmt.Errorf("failed to increment referral code use: %w", err)
	}
	return nil
}

// Referral Relationship operations

func (s *PostgresStorage) CreateReferralRelationship(relationship *referrals.ReferralRelationship) error {
	query := `INSERT INTO referral_relationships (referrer_user_id, referred_user_id, referral_code_id, created_at)
			  VALUES ($1, $2, $3, $4) RETURNING id`

	err := s.db.QueryRow(query,
		relationship.ReferrerUserID, relationship.ReferredUserID,
		relationship.ReferralCodeID, time.Now()).Scan(&relationship.ID)

	if err != nil {
		return fmt.Errorf("failed to create referral relationship: %w", err)
	}

	return nil
}

func (s *PostgresStorage) GetReferralRelationshipsByReferrer(referrerUserID uint) ([]*referrals.ReferralRelationship, error) {
	query := `SELECT id, referrer_user_id, referred_user_id, referral_code_id, created_at
			  FROM referral_relationships WHERE referrer_user_id = $1 ORDER BY created_at DESC`

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

func (s *PostgresStorage) GetReferralRelationshipsByReferred(referredUserID uint) ([]*referrals.ReferralRelationship, error) {
	query := `SELECT id, referrer_user_id, referred_user_id, referral_code_id, created_at
			  FROM referral_relationships WHERE referred_user_id = $1`

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

func (s *PostgresStorage) GetReferralRelationshipByUsers(referrerUserID, referredUserID uint) (*referrals.ReferralRelationship, error) {
	rel := &referrals.ReferralRelationship{}
	query := `SELECT id, referrer_user_id, referred_user_id, referral_code_id, created_at
			  FROM referral_relationships WHERE referrer_user_id = $1 AND referred_user_id = $2`

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

func (s *PostgresStorage) GetReferralStats(userID uint) (*referrals.ReferralStats, error) {
	stats := &referrals.ReferralStats{}
	query := `SELECT user_id, total_referred, active_codes, total_codes_used, successful_signups
			  FROM referral_stats WHERE user_id = $1`

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

func (s *PostgresStorage) GetTopReferrers(limit int) ([]*referrals.ReferralStats, error) {
	query := `SELECT user_id, total_referred, active_codes, total_codes_used, successful_signups
			  FROM referral_stats WHERE total_referred > 0
			  ORDER BY total_referred DESC, total_codes_used DESC
			  LIMIT $1`

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

func (s *PostgresStorage) ValidateReferralCode(code string) (*referrals.ReferralCode, error) {
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

func (s *PostgresStorage) CheckCodeAvailability(code string) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM referral_codes WHERE code = $1`
	err := s.db.QueryRow(query, code).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check code availability: %w", err)
	}
	return count == 0, nil
}

func (s *PostgresStorage) CountActiveReferralCodes(userID uint) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM referral_codes
			  WHERE generated_by = $1 AND is_active = TRUE
			  AND (expires_at IS NULL OR expires_at > NOW())`
	err := s.db.QueryRow(query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active referral codes: %w", err)
	}
	return count, nil
}

// Close closes the storage connection
func (s *PostgresStorage) Close() error {
	if err := s.PostgresStorage.Close(); err != nil {
		return err
	}
	return s.db.Close()
}