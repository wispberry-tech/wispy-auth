package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Password utilities
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Token generation utilities
func generateRandomPassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func generateVerificationToken() (string, error) {
	return generateSecureToken(32)
}

func generatePasswordResetToken() (string, error) {
	return generateSecureToken(48)
}

// Device fingerprinting
func generateDeviceFingerprint(userAgent, ip string) string {
	combined := fmt.Sprintf("%s|%s|%d", userAgent, ip, time.Now().Unix()/3600) // Changes every hour
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes
}

// Password validation
func validatePasswordStrength(password string, config SecurityConfig) error {
	if len(password) < config.MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", config.MinPasswordLength)
	}
	
	if config.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	
	if config.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	
	if config.RequireNumbers && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one number")
	}
	
	if config.RequireSpecialChars && !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}
	
	return nil
}

// Email validation
func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	return emailRegex.MatchString(strings.ToLower(email))
}

// IP utilities
func extractIPFromRequest(remoteAddr, xForwardedFor, xRealIP string) string {
	// Check X-Forwarded-For header first (can contain multiple IPs)
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		clientIP := strings.TrimSpace(ips[0])
		if net.ParseIP(clientIP) != nil {
			return clientIP
		}
	}
	
	// Check X-Real-IP header
	if xRealIP != "" {
		if net.ParseIP(xRealIP) != nil {
			return xRealIP
		}
	}
	
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// Session utilities
func isSessionExpired(expiresAt time.Time) bool {
	return time.Now().After(expiresAt)
}

func calculateSessionExpiry(config SecurityConfig) time.Time {
	return time.Now().Add(config.SessionTimeout)
}

// Rate limiting key generation
func generateRateLimitKey(ip, endpoint string) string {
	return fmt.Sprintf("rate_limit:%s:%s", ip, endpoint)
}

// Security event types
const (
	EventLoginSuccess       = "login_success"
	EventLoginFailed        = "login_failed"
	EventPasswordReset      = "password_reset"
	EventPasswordChanged    = "password_changed"
	EventEmailVerified      = "email_verified"
	EventAccountLocked      = "account_locked"
	EventAccountUnlocked    = "account_unlocked"
	Event2FAEnabled         = "2fa_enabled"
	Event2FADisabled        = "2fa_disabled"
	EventSessionCreated     = "session_created"
	EventSessionTerminated  = "session_terminated"
	EventSuspiciousActivity = "suspicious_activity"
)
