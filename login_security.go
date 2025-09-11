package auth

import (
	"fmt"
	"time"
)

// Login security functionality
func (a *AuthService) recordLoginSuccess(user *User, ip, userAgent, location string) error {
	now := time.Now()
	user.LastLoginAt = &now
	user.LastKnownIP = ip
	user.LastLoginLocation = location
	user.LoginAttempts = 0 // Reset failed attempts on successful login
	user.LockedUntil = nil // Clear any lock

	return a.storage.UpdateUser(user)
}

func (a *AuthService) recordLoginFailure(user *User, ip, userAgent string) error {
	now := time.Now()
	user.LoginAttempts++
	user.LastFailedLoginAt = &now

	// Check if we should lock the account
	if user.LoginAttempts >= a.securityConfig.MaxLoginAttempts {
		lockDuration := time.Duration(a.securityConfig.LockoutDuration) * time.Minute
		lockedUntil := now.Add(lockDuration)
		user.LockedUntil = &lockedUntil

		// Log account lockout
		a.logSecurityEvent(&user.ID, nil, EventAccountLocked,
			fmt.Sprintf("Account locked for %d minutes due to %d failed login attempts",
				a.securityConfig.LockoutDuration, user.LoginAttempts),
			ip, userAgent, "")
	}

	return a.storage.UpdateUser(user)
}

func (a *AuthService) isAccountLocked(user *User) bool {
	if user.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*user.LockedUntil)
}

func (a *AuthService) validateLoginAttempt(user *User, ip, userAgent string) error {
	// Check if account is suspended
	if user.IsSuspended {
		a.logSecurityEvent(&user.ID, nil, EventLoginFailed,
			"Login attempt on suspended account",
			ip, userAgent, "")
		return fmt.Errorf("account is suspended: %s", user.SuspendReason)
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
		return fmt.Errorf("account is locked until %v", user.LockedUntil.Format(time.RFC3339))
	}

	return nil
}
