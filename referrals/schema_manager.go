package referrals

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	"github.com/wispberry-tech/wispy-auth/core"
)

//go:embed sql/*.sql
var schemaFiles embed.FS

// ReferralSchemaManager handles automatic table creation for referral tables
type ReferralSchemaManager struct {
	db       *sql.DB
	dbType   string // "sqlite" or "postgres"
	logLevel slog.Level
}

// NewReferralSchemaManager creates a new referral schema manager
func NewReferralSchemaManager(db *sql.DB, dbType string) *ReferralSchemaManager {
	return &ReferralSchemaManager{
		db:       db,
		dbType:   dbType,
		logLevel: slog.LevelWarn, // Default to warning level for missing tables
	}
}

// SetLogLevel sets the log level for schema operations
func (rsm *ReferralSchemaManager) SetLogLevel(level slog.Level) {
	rsm.logLevel = level
}

// EnsureReferralSchema ensures all referral tables exist, creating missing ones
// This should be called after the core schema is already in place
func (rsm *ReferralSchemaManager) EnsureReferralSchema() error {
	// First ensure core schema exists using core schema manager
	coreManager := core.NewSchemaManager(rsm.db, rsm.dbType)
	if err := coreManager.EnsureCoreSchema(); err != nil {
		return fmt.Errorf("failed to ensure core schema before referral tables: %w", err)
	}

	requiredTables := []string{
		"referral_codes",
		"referral_relationships",
	}

	missingTables, err := rsm.checkMissingTables(requiredTables)
	if err != nil {
		return fmt.Errorf("failed to check missing referral tables: %w", err)
	}

	if len(missingTables) > 0 {
		slog.Log(nil, rsm.logLevel, "Missing referral tables detected",
			"missing_tables", missingTables,
			"action", "auto_creating",
			"database_type", rsm.dbType)

		if err := rsm.createReferralSchema(); err != nil {
			return fmt.Errorf("failed to create referral schema: %w", err)
		}

		slog.Info("Successfully created missing referral tables",
			"created_tables", missingTables,
			"database_type", rsm.dbType)
	} else {
		slog.Debug("All referral tables exist", "database_type", rsm.dbType)
	}

	return nil
}

// checkMissingTables checks which tables from the required list are missing
func (rsm *ReferralSchemaManager) checkMissingTables(requiredTables []string) ([]string, error) {
	var missingTables []string

	for _, tableName := range requiredTables {
		exists, err := rsm.tableExists(tableName)
		if err != nil {
			return nil, fmt.Errorf("failed to check if table %s exists: %w", tableName, err)
		}

		if !exists {
			missingTables = append(missingTables, tableName)
		}
	}

	return missingTables, nil
}

// tableExists checks if a table exists in the database
func (rsm *ReferralSchemaManager) tableExists(tableName string) (bool, error) {
	var query string
	var args []interface{}

	switch rsm.dbType {
	case "sqlite":
		query = `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`
		args = []interface{}{tableName}
	case "postgres":
		query = `SELECT table_name FROM information_schema.tables
		         WHERE table_schema = 'public' AND table_name = $1`
		args = []interface{}{tableName}
	default:
		return false, fmt.Errorf("unsupported database type: %s", rsm.dbType)
	}

	var foundTable string
	err := rsm.db.QueryRow(query, args...).Scan(&foundTable)

	if err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return foundTable == tableName, nil
}

// createReferralSchema creates all referral tables from embedded SQL files
func (rsm *ReferralSchemaManager) createReferralSchema() error {
	var schemaFile string

	switch rsm.dbType {
	case "sqlite":
		schemaFile = "sql/sqlite_referrals.sql"
	case "postgres":
		schemaFile = "sql/postgres_referrals.sql"
	default:
		return fmt.Errorf("unsupported database type: %s", rsm.dbType)
	}

	slog.Debug("Reading referral schema file", "file", schemaFile, "database_type", rsm.dbType)

	schemaSQL, err := schemaFiles.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("failed to read referral schema file %s: %w", schemaFile, err)
	}

	// Execute the schema SQL
	if _, err := rsm.db.Exec(string(schemaSQL)); err != nil {
		return fmt.Errorf("failed to execute referral schema: %w", err)
	}

	return nil
}

// ValidateReferralSchema performs basic referral schema validation
func (rsm *ReferralSchemaManager) ValidateReferralSchema() error {
	requiredTables := []string{
		"referral_codes",
		"referral_relationships",
	}

	missingTables, err := rsm.checkMissingTables(requiredTables)
	if err != nil {
		return fmt.Errorf("referral schema validation failed: %w", err)
	}

	if len(missingTables) > 0 {
		return fmt.Errorf("referral schema validation failed: missing tables %s", strings.Join(missingTables, ", "))
	}

	slog.Debug("Referral schema validation passed", "database_type", rsm.dbType)
	return nil
}