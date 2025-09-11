package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	// Load environment variables
	if err := godotenv.Load("../.env"); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Connected to database successfully")

	// Create migrations table if it doesn't exist
	if err := createMigrationsTable(db); err != nil {
		log.Fatalf("Failed to create migrations table: %v", err)
	}

	// Run migrations
	if err := runMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Println("All migrations completed successfully!")
}

func createMigrationsTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS migrations (
		id SERIAL PRIMARY KEY,
		filename VARCHAR(255) UNIQUE NOT NULL,
		executed_at TIMESTAMP DEFAULT NOW()
	);`

	_, err := db.Exec(query)
	return err
}

func runMigrations(db *sql.DB) error {
	// Get list of migration files
	files, err := filepath.Glob("*.sql")
	if err != nil {
		return fmt.Errorf("failed to list migration files: %w", err)
	}

	// Sort files to ensure correct execution order
	sort.Strings(files)

	for _, file := range files {
		// Check if migration has already been run
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM migrations WHERE filename = $1", file).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check migration status for %s: %w", file, err)
		}

		if count > 0 {
			log.Printf("Skipping %s (already executed)", file)
			continue
		}

		// Read migration file
		content, err := ioutil.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		log.Printf("Executing migration: %s", file)

		// Execute migration in a transaction
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for %s: %w", file, err)
		}

		// Execute the migration
		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}

		// Record the migration as completed
		if _, err := tx.Exec("INSERT INTO migrations (filename) VALUES ($1)", file); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", file, err)
		}

		// Commit the transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", file, err)
		}

		log.Printf("Successfully executed: %s", file)
	}

	return nil
}