package core

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"
)

//go:embed sql/*.sql
var schemaFiles embed.FS

// SchemaManager handles schema validation and information
type SchemaManager struct {
	db       *sql.DB
	dbType   string // "sqlite" or "postgres"
	logLevel slog.Level
}

// NewSchemaManager creates a new schema manager
func NewSchemaManager(db *sql.DB, dbType string) *SchemaManager {
	return &SchemaManager{
		db:       db,
		dbType:   dbType,
		logLevel: slog.LevelWarn,
	}
}

// SetLogLevel sets the log level for schema operations
func (sm *SchemaManager) SetLogLevel(level slog.Level) {
	sm.logLevel = level
}

// ExecuteCoreSchema executes the core schema SQL to create tables
func (sm *SchemaManager) ExecuteCoreSchema() error {
	var schemaFile string

	switch sm.dbType {
	case "sqlite":
		schemaFile = "sql/sqlite_core.sql"
	case "postgres":
		schemaFile = "sql/postgres_core.sql"
	default:
		return fmt.Errorf("unsupported database type: %s", sm.dbType)
	}

	schemaSQL, err := schemaFiles.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("failed to read schema file %s: %w", schemaFile, err)
	}

	// Execute the schema SQL
	if _, err := sm.db.Exec(string(schemaSQL)); err != nil {
		return fmt.Errorf("failed to execute core schema: %w", err)
	}

	return nil
}

// tableExists checks if a table exists in the database
func (sm *SchemaManager) tableExists(tableName string) (bool, error) {
	var query string
	var args []interface{}

	switch sm.dbType {
	case "sqlite":
		query = `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`
		args = []interface{}{tableName}
	case "postgres":
		query = `SELECT table_name FROM information_schema.tables
		         WHERE table_schema = 'public' AND table_name = $1`
		args = []interface{}{tableName}
	default:
		return false, fmt.Errorf("unsupported database type: %s", sm.dbType)
	}

	var foundTable string
	err := sm.db.QueryRow(query, args...).Scan(&foundTable)

	if err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return foundTable == tableName, nil
}

// ValidateSchema performs basic schema validation
func (sm *SchemaManager) ValidateSchema() error {
	requiredTables := []string{
		"users",
		"user_security",
		"sessions",
		"security_events",
		"oauth_states",
	}

	var missingTables []string
	for _, tableName := range requiredTables {
		exists, err := sm.tableExists(tableName)
		if err != nil {
			return fmt.Errorf("failed to check if table %s exists: %w", tableName, err)
		}
		if !exists {
			missingTables = append(missingTables, tableName)
		}
	}

	if len(missingTables) > 0 {
		return fmt.Errorf("schema validation failed: missing tables %s", strings.Join(missingTables, ", "))
	}

	slog.Debug("Schema validation passed", "database_type", sm.dbType)
	return nil
}

// GetSchemaInfo returns information about the current schema
func (sm *SchemaManager) GetSchemaInfo() (*SchemaInfo, error) {
	info := &SchemaInfo{
		DatabaseType: sm.dbType,
		Tables:       make(map[string]*TableInfo),
	}

	var query string
	switch sm.dbType {
	case "sqlite":
		query = `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
	case "postgres":
		query = `SELECT table_name FROM information_schema.tables
		         WHERE table_schema = 'public' ORDER BY table_name`
	default:
		return nil, fmt.Errorf("unsupported database type: %s", sm.dbType)
	}

	rows, err := sm.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %w", err)
		}

		info.Tables[tableName] = &TableInfo{
			Name:   tableName,
			Exists: true,
		}
	}

	return info, nil
}

// SchemaInfo contains information about the database schema
type SchemaInfo struct {
	DatabaseType string                `json:"database_type"`
	Tables       map[string]*TableInfo `json:"tables"`
}

// TableInfo contains information about a specific table
type TableInfo struct {
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
}
