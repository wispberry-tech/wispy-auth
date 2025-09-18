package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
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
	if len(password) < config.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters long", config.PasswordMinLength)
	}

	if config.PasswordRequireUpper && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if config.PasswordRequireLower && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if config.PasswordRequireNumber && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one number")
	}

	if config.PasswordRequireSpecial && !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
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

// calculateSessionExpiry calculates when a session should expire
func calculateSessionExpiry(config SecurityConfig) time.Time {
	return time.Now().Add(config.SessionLifetime)
}

// extractTokenFromRequest extracts session token from Authorization header or auth_token cookie
func extractTokenFromRequest(r *http.Request) string {
	// First, try to get token from Authorization header
	token := r.Header.Get("Authorization")
	if token != "" {
		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			return token[7:]
		}
		return token
	}

	// If no Authorization header, try to get token from auth_token cookie
	if cookie, err := r.Cookie("auth_token"); err == nil {
		return cookie.Value
	}

	return ""
}

// extractIP extracts client IP from HTTP request
func extractIP(r *http.Request) string {
	return extractIPFromRequest(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
}

// Helper function to format validation errors
func formatValidationErrors(err error) string {
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		var errorMessages []string
		for _, fieldError := range validationErrors {
			switch fieldError.Tag() {
			case "required":
				errorMessages = append(errorMessages, fmt.Sprintf("%s is required", fieldError.Field()))
			case "email":
				errorMessages = append(errorMessages, fmt.Sprintf("%s must be a valid email address", fieldError.Field()))
			case "min":
				errorMessages = append(errorMessages, fmt.Sprintf("%s must be at least %s characters long", fieldError.Field(), fieldError.Param()))
			case "max":
				errorMessages = append(errorMessages, fmt.Sprintf("%s must be at most %s characters long", fieldError.Field(), fieldError.Param()))
			default:
				errorMessages = append(errorMessages, fmt.Sprintf("%s is invalid", fieldError.Field()))
			}
		}
		return strings.Join(errorMessages, "; ")
	}
	return err.Error()
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
