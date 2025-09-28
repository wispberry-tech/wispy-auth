package referrals

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"
)

//go:embed sql/*.sql
var schemaFiles embed.FS

// ReferralSchemaManager handles schema validation for referral tables
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
		logLevel: slog.LevelWarn,
	}
}

// SetLogLevel sets the log level for schema operations
func (rsm *ReferralSchemaManager) SetLogLevel(level slog.Level) {
	rsm.logLevel = level
}

// ExecuteReferralSchema executes the referral schema SQL to create tables
func (rsm *ReferralSchemaManager) ExecuteReferralSchema() error {
	var schemaFile string

	switch rsm.dbType {
	case "sqlite":
		schemaFile = "sql/sqlite_referrals.sql"
	case "postgres":
		schemaFile = "sql/postgres_referrals.sql"
	default:
		return fmt.Errorf("unsupported database type: %s", rsm.dbType)
	}

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

// ValidateReferralSchema performs basic referral schema validation
func (rsm *ReferralSchemaManager) ValidateReferralSchema() error {
	requiredTables := []string{
		"referral_codes",
		"referral_relationships",
	}

	var missingTables []string
	for _, tableName := range requiredTables {
		exists, err := rsm.tableExists(tableName)
		if err != nil {
			return fmt.Errorf("failed to check if table %s exists: %w", tableName, err)
		}
		if !exists {
			missingTables = append(missingTables, tableName)
		}
	}

	if len(missingTables) > 0 {
		return fmt.Errorf("referral schema validation failed: missing tables %s", strings.Join(missingTables, ", "))
	}

	slog.Debug("Referral schema validation passed", "database_type", rsm.dbType)
	return nil
}
