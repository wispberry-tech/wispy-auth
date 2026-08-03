package storage

import (
	"context"
	"testing"
	"time"

	. "github.com/wispberry-tech/wispy-auth/core"
)

// Guards the avatar_url column through every users-table query path.
func TestAvatarURLRoundTrip(t *testing.T) {
	testDB := SetupTestDB(t, "sqlite")
	defer TeardownTestDB(t, testDB)

	store, err := NewSQLiteStorageFromDB(testDB.DB)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	user := &User{
		Email:         "avatar@example.com",
		Username:      "avatar",
		FirstName:     "Av",
		LastName:      "Atar",
		PasswordHash:  "hash",
		AvatarURL:     "https://example.com/avatar.png",
		Provider:      "email",
		EmailVerified: true,
		IsActive:      true,
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// INSERT path (CreateUser)
	byID, err := store.GetUserByID(context.Background(), user.ID)
	if err != nil || byID == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.AvatarURL != "https://example.com/avatar.png" {
		t.Errorf("GetUserByID avatar = %q", byID.AvatarURL)
	}

	// SELECT paths
	byEmail, err := store.GetUserByEmail(context.Background(), "avatar@example.com", "email")
	if err != nil || byEmail == nil || byEmail.AvatarURL != "https://example.com/avatar.png" {
		t.Errorf("GetUserByEmail avatar = %q, err %v", byEmail.AvatarURL, err)
	}
	byAny, err := store.GetUserByEmailAnyProvider(context.Background(), "avatar@example.com")
	if err != nil || byAny == nil || byAny.AvatarURL != "https://example.com/avatar.png" {
		t.Errorf("GetUserByEmailAnyProvider avatar = %q, err %v", byAny.AvatarURL, err)
	}
	byUUID, err := store.GetUserByUUID(context.Background(), user.UUID)
	if err != nil || byUUID == nil || byUUID.AvatarURL != "https://example.com/avatar.png" {
		t.Errorf("GetUserByUUID avatar = %q, err %v", byUUID.AvatarURL, err)
	}

	// UPDATE path
	user.AvatarURL = "https://example.com/new.png"
	user.UpdatedAt = time.Now()
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	byID2, _ := store.GetUserByID(context.Background(), user.ID)
	if byID2 == nil || byID2.AvatarURL != "https://example.com/new.png" {
		t.Errorf("avatar after update = %q", byID2.AvatarURL)
	}

	// CreateUserWithSecurity INSERT path
	sec := &UserSecurity{UserID: user.ID, LoginAttempts: 0}
	u2 := &User{
		Email:        "avatar2@example.com",
		Username:     "avatar2",
		PasswordHash: "hash2",
		AvatarURL:    "https://example.com/tx.png",
		Provider:     "email",
		IsActive:     true,
	}
	if err := store.CreateUserWithSecurity(context.Background(), u2, sec); err != nil {
		t.Fatalf("CreateUserWithSecurity: %v", err)
	}
	byID3, _ := store.GetUserByID(context.Background(), u2.ID)
	if byID3 == nil || byID3.AvatarURL != "https://example.com/tx.png" {
		t.Errorf("CreateUserWithSecurity avatar = %q", byID3.AvatarURL)
	}
}
