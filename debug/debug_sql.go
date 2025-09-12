package main

import (
	"fmt"
	auth "github.com/wispberry-tech/wispy-auth"
)

func main() {
	config := auth.DefaultStorageConfig()
	
	query := fmt.Sprintf(`
		SELECT 
			%s, %s, %s, %s, %s, %s, %s, %s, %s,
			%s, %s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s,
			%s, %s, %s,
			%s, %s, %s, %s,
			%s, %s
		FROM %s 
		WHERE %s = $1 AND %s = $2`,
		// Basic fields
		config.UserColumns.ID,
		config.UserColumns.Email,
		config.UserColumns.PasswordHash,
		config.UserColumns.Username,
		config.UserColumns.FirstName,
		config.UserColumns.LastName,
		config.UserColumns.AvatarURL,
		config.UserColumns.Provider,
		config.UserColumns.ProviderID,
		// Email security
		config.UserColumns.EmailVerified,
		config.UserColumns.EmailVerifiedAt,
		config.UserColumns.VerificationToken,
		// Password security
		config.UserColumns.PasswordResetToken,
		config.UserColumns.PasswordResetExpiresAt,
		config.UserColumns.PasswordChangedAt,
		// Login security
		config.UserColumns.LoginAttempts,
		config.UserColumns.LastFailedLoginAt,
		config.UserColumns.LockedUntil,
		config.UserColumns.LastLoginAt,
		// Location & device
		config.UserColumns.LastKnownIP,
		config.UserColumns.LastLoginLocation,
		// 2FA
		config.UserColumns.TwoFactorEnabled,
		config.UserColumns.TwoFactorSecret,
		config.UserColumns.BackupCodes,
		// Account security
		config.UserColumns.IsActive,
		config.UserColumns.IsSuspended,
		config.UserColumns.SuspendedAt,
		config.UserColumns.SuspendReason,
		// Timestamps
		config.UserColumns.CreatedAt,
		config.UserColumns.UpdatedAt,
		// Table and conditions
		config.UsersTable,
		config.UserColumns.Email,
		config.UserColumns.Provider,
	)
	
	fmt.Println("Generated SQL Query:")
	fmt.Println(query)
}