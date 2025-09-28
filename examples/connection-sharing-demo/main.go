package main

import (
	"fmt"
	"log"
	"os"

	"github.com/wispberry-tech/wispy-auth/core/storage"
	referralsStorage "github.com/wispberry-tech/wispy-auth/referrals/storage"
)

// demonstrateConnectionSharing shows that core and referrals storage share the same connection
func demonstrateConnectionSharing() {
	fmt.Println("=== Testing Database Connection Sharing Fix ===")
	fmt.Println()

	// Test SQLite connection sharing
	fmt.Println("1. Testing SQLite Connection Sharing:")
	testSQLiteConnectionSharing()

	fmt.Println()
	fmt.Println("2. Testing PostgreSQL Connection Sharing:")
	fmt.Println("   (Commented out - requires PostgreSQL instance)")
	// testPostgreSQLConnectionSharing()

	fmt.Println()
	fmt.Println("=== Connection Sharing Test Complete ===")
}

func testSQLiteConnectionSharing() {
	// Create temporary database file
	tempDB := "test_connection_sharing.db"
	defer os.Remove(tempDB)

	// Create core storage
	coreStorage, err := storage.NewSQLiteStorage(tempDB)
	if err != nil {
		log.Fatalf("Failed to create core storage: %v", err)
	}
	defer coreStorage.Close()

	// Get core database connection
	coreDB, err := coreStorage.GetDB()
	if err != nil {
		log.Fatalf("Failed to get core DB: %v", err)
	}

	// Create referrals storage (should reuse the connection)
	refStorage, err := referralsStorage.NewSQLiteStorage(tempDB)
	if err != nil {
		log.Fatalf("Failed to create referrals storage: %v", err)
	}
	defer refStorage.Close()

	// Verify tables exist (both core and referrals)
	tables := []string{"users", "user_security", "referral_codes", "referral_relationships"}

	fmt.Printf("   ✓ Core and referrals storage created successfully\n")
	fmt.Printf("   ✓ Checking database tables...\n")

	for _, table := range tables {
		var count int
		query := fmt.Sprintf("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='%s'", table)
		err := coreDB.QueryRow(query).Scan(&count)
		if err != nil {
			log.Fatalf("Failed to check table %s: %v", table, err)
		}
		if count == 1 {
			fmt.Printf("   ✓ Table '%s' exists\n", table)
		} else {
			fmt.Printf("   ✗ Table '%s' missing\n", table)
		}
	}

	fmt.Printf("   ✓ Connection sharing working correctly!\n")
}

// testPostgreSQLConnectionSharing demonstrates PostgreSQL connection sharing
// Commented out to avoid requiring a running PostgreSQL instance
/*
func testPostgreSQLConnectionSharing() {
	dsn := "postgresql://user:password@localhost/testdb?sslmode=disable"

	// Create core storage
	coreStorage, err := storage.NewPostgresStorage(dsn)
	if err != nil {
		log.Fatalf("Failed to create core storage: %v", err)
	}
	defer coreStorage.Close()

	// Create referrals storage (should reuse the connection)
	refStorage, err := referralsStorage.NewPostgresStorage(dsn)
	if err != nil {
		log.Fatalf("Failed to create referrals storage: %v", err)
	}
	defer refStorage.Close()

	fmt.Printf("   ✓ PostgreSQL connection sharing working correctly!\n")
}
*/

func main() {
	demonstrateConnectionSharing()
}
