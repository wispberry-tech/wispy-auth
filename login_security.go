package auth

import (
	"fmt"
	"time"
)

// Login security functionality
func (a *AuthService) recordLoginSuccess(user *User, ip, userAgent, location string) error {
	// Reset login attempts and update last login info
	if err := a.storage.ResetLoginAttempts(user.ID); err != nil {
		return fmt.Errorf("failed to reset login attempts: %w", err)
	}

	if err := a.storage.UpdateLastLogin(user.ID, ip); err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

func (a *AuthService) recordLoginFailure(user *User, ip, userAgent string) error {
	// Increment login attempts
	if err := a.storage.IncrementLoginAttempts(user.ID); err != nil {
		return fmt.Errorf("failed to increment login attempts: %w", err)
	}

	// Get current security info to check attempt count
	userSecurity, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		return fmt.Errorf("failed to get user security: %w", err)
	}

	// Check if we should lock the account
	if userSecurity.LoginAttempts >= a.securityConfig.MaxLoginAttempts {
		lockDuration := time.Duration(a.securityConfig.LockoutDuration) * time.Minute
		lockedUntil := time.Now().Add(lockDuration)

		if err := a.storage.SetUserLocked(user.ID, lockedUntil); err != nil {
			return fmt.Errorf("failed to lock user account: %w", err)
		}

		// Log account lockout
		a.logSecurityEvent(&user.ID, nil, EventAccountLocked,
			fmt.Sprintf("Account locked for %d minutes due to %d failed login attempts",
				a.securityConfig.LockoutDuration, userSecurity.LoginAttempts),
			ip, userAgent, "")
	}

	return nil
}

func (a *AuthService) isAccountLocked(user *User) bool {
	userSecurity, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		return false // If we can't get security info, don't block login
	}

	if userSecurity.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*userSecurity.LockedUntil)
}

func (a *AuthService) validateLoginAttempt(user *User, ip, userAgent string) error {
	// Check if account is suspended
	if user.IsSuspended {
		a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
			"Login attempt on suspended account",
			ip, userAgent, "")
		userSecurity, _ := a.storage.GetUserSecurity(user.ID)
		suspendReason := "account suspended"
		if userSecurity != nil && userSecurity.SuspendReason != "" {
			suspendReason = userSecurity.SuspendReason
		}
		return fmt.Errorf("account is suspended: %s", suspendReason)
	}

	// Check if account is inactive
	if !user.IsActive {
		a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
			"Login attempt on inactive account",
			ip, userAgent, "")
		return fmt.Errorf("account is inactive")
	}

	// Check if account is locked
	if a.isAccountLocked(user) {
		a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
			"Login attempt on locked account",
			ip, userAgent, "")
		userSecurity, _ := a.storage.GetUserSecurity(user.ID)
		lockTime := "unknown"
		if userSecurity != nil && userSecurity.LockedUntil != nil {
			lockTime = userSecurity.LockedUntil.Format(time.RFC3339)
		}
		return fmt.Errorf("account is locked until %v", lockTime)
	}

	return nil
}
