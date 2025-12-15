package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
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

func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
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
	slog.Debug("Extracting token from request",
		"method", r.Method,
		"url", r.URL.String(),
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
		"authorization_header", r.Header.Get("Authorization"),
		"all_headers", r.Header,
		"cookie_count", len(r.Cookies()))

	// Log all cookies
	for i, cookie := range r.Cookies() {
		slog.Debug("Request cookie",
			"cookie_index", i,
			"name", cookie.Name,
			"value_length", len(cookie.Value),
			"domain", cookie.Domain,
			"path", cookie.Path,
			"secure", cookie.Secure,
			"http_only", cookie.HttpOnly)
	}

	// First, try to get token from Authorization header
	token := r.Header.Get("Authorization")
	if token != "" {
		slog.Debug("Token found in Authorization header", "token_length", len(token), "has_bearer_prefix", len(token) > 7 && token[:7] == "Bearer ")
		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			extractedToken := token[7:]
			slog.Debug("Extracted token from Bearer header", "token_prefix", extractedToken[:min(8, len(extractedToken))], "token_length", len(extractedToken))
			return extractedToken
		}
		slog.Debug("Using raw Authorization header as token", "token_prefix", token[:min(8, len(token))], "token_length", len(token))
		return token
	}

	// If no Authorization header, try to get token from auth_token cookie
	if cookie, err := r.Cookie("auth_token"); err == nil {
		slog.Debug("Token found in auth_token cookie", "token_prefix", cookie.Value[:min(8, len(cookie.Value))], "token_length", len(cookie.Value))
		return cookie.Value
	}

	slog.Debug("No token found in Authorization header or auth_token cookie")
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

// RateLimiter provides in-memory rate limiting functionality
type RateLimiter struct {
	requests    map[string][]time.Time
	maxRequests int
	window      time.Duration
	mu          sync.RWMutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:    make(map[string][]time.Time),
		maxRequests: maxRequests,
		window:      window,
	}
}

// IsAllowed checks if a request from the given key (IP address) is allowed
func (rl *RateLimiter) IsAllowed(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	requests := rl.requests[key]

	// Remove old requests outside the window
	var validRequests []time.Time
	for _, reqTime := range requests {
		if now.Sub(reqTime) < rl.window {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Check if under limit
	if len(validRequests) < rl.maxRequests {
		validRequests = append(validRequests, now)
		rl.requests[key] = validRequests
		return true
	}

	rl.requests[key] = validRequests
	return false
}

// Cleanup removes old entries to prevent memory leaks
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, requests := range rl.requests {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if now.Sub(reqTime) < rl.window {
				validRequests = append(validRequests, reqTime)
			}
		}
		if len(validRequests) == 0 {
			delete(rl.requests, key)
		} else {
			rl.requests[key] = validRequests
		}
	}
}
