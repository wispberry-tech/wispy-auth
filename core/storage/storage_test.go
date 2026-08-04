package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/ncruces/go-sqlite3"
	"github.com/wispberry-tech/wispy-auth/core"
)

// TestDB provides test database setup and teardown
type TestDB struct {
	DB   *sql.DB
	Path string
	Type string // "sqlite" or "postgres"
}

// SetupTestDB creates a test database for testing
func SetupTestDB(t *testing.T, dbType string) *TestDB {
	t.Helper()

	var testDB *TestDB

	switch dbType {
	case "sqlite":
		testDB = setupSQLiteTestDB(t)
	case "postgres":
		testDB = setupPostgresTestDB(t)
	default:
		t.Fatalf("Unsupported database type: %s", dbType)
	}

	// Run migrations
	if err := runMigrations(testDB, t); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return testDB
}

// TeardownTestDB cleans up test database
func TeardownTestDB(t *testing.T, testDB *TestDB) {
	t.Helper()

	if testDB.DB != nil {
		if err := testDB.DB.Close(); err != nil {
			t.Errorf("Failed to close database: %v", err)
		}
	}

	if testDB.Type == "sqlite" && testDB.Path != "" {
		if err := os.Remove(testDB.Path); err != nil {
			t.Logf("Warning: Failed to remove test database: %v", err)
		}
	}
}

// setupSQLiteTestDB creates an in-memory SQLite database
func setupSQLiteTestDB(t *testing.T) *TestDB {
	t.Helper()

	dbPath := filepath.Join(os.TempDir(), fmt.Sprintf("wispy_test_%d.db", time.Now().UnixNano()))
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		t.Fatalf("Failed to open SQLite database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping SQLite database: %v", err)
	}

	return &TestDB{
		DB:   db,
		Path: dbPath,
		Type: "sqlite",
	}
}

// setupPostgresTestDB creates a PostgreSQL test database
func setupPostgresTestDB(t *testing.T) *TestDB {
	t.Helper()

	// Read PostgreSQL connection from environment or use defaults
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/wispy_test?sslmode=disable"
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Skipf("Skipping PostgreSQL tests: Failed to connect to database: %v (set TEST_POSTGRES_DSN)", err)
		return nil
	}

	if err := db.Ping(); err != nil {
		t.Skipf("Skipping PostgreSQL tests: Failed to ping database: %v", err)
		return nil
	}

	// Clean up any existing test data
	_, _ = db.Exec("DROP SCHEMA public CASCADE")
	_, _ = db.Exec("CREATE SCHEMA public")

	return &TestDB{
		DB:   db,
		Type: "postgres",
	}
}

// runMigrations runs database schema migrations
func runMigrations(testDB *TestDB, t *testing.T) error {
	t.Helper()

	var schemaSQL string
	switch testDB.Type {
	case "sqlite":
		schemaSQL = core.SQLiteSchemaSQL()
	case "postgres":
		schemaSQL = core.PostgresSchemaSQL()
	default:
		return fmt.Errorf("unsupported database type: %s", testDB.Type)
	}

	if _, err := testDB.DB.Exec(schemaSQL); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// AssertTimeWithin checks if two timestamps are within a given duration
func AssertTimeWithin(t *testing.T, expected, actual time.Time, duration time.Duration) {
	t.Helper()
	diff := expected.Sub(actual)
	if diff < 0 {
		diff = -diff
	}
	if diff > duration {
		t.Errorf("Time difference exceeds %v: got %v", duration, diff)
	}
}

// AssertTimeAfter checks if actual time is after expected time
func AssertTimeAfter(t *testing.T, expected, actual time.Time) {
	t.Helper()
	if !actual.After(expected) {
		t.Errorf("Expected time %v to be after %v", actual, expected)
	}
}

// AssertTimeBefore checks if actual time is before expected time
func AssertTimeBefore(t *testing.T, expected, actual time.Time) {
	t.Helper()
	if !actual.Before(expected) {
		t.Errorf("Expected time %v to be before %v", actual, expected)
	}
}
