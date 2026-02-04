package core

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Request and Response Types

// SignUpRequest represents a user registration request
type SignUpRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// SignUpResponse represents the response for user registration
type SignUpResponse struct {
	Token      string `json:"token"`           // Session token for authentication
	User       *User  `json:"user"`            // Created user information
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// SignInRequest represents a user login request
type SignInRequest struct {
	Email    string `json:"email" validate:"required,email"` // User's email address
	Password string `json:"password" validate:"required"`    // User's password (plaintext)
}

// SignInResponse represents the response for user authentication
type SignInResponse struct {
	Token            string    `json:"token"`              // Session token for authentication
	User             *User     `json:"user"`               // Authenticated user information
	SessionID        string    `json:"session_id"`         // Session identifier
	Requires2FA      bool      `json:"requires_2fa"`       // Whether two-factor authentication is required
	SessionExpiresAt time.Time `json:"session_expires_at"` // When the session expires
	StatusCode       int       `json:"-"`                  // HTTP status code (not serialized)
	Error            string    `json:"error,omitempty"`    // Error message if any
}

// ValidateResponse represents the response for token validation
type ValidateResponse struct {
	User       *User  `json:"user"`            // Validated user information
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// OAuthResponse represents the response for OAuth operations
type OAuthResponse struct {
	URL        string `json:"url,omitempty"`         // OAuth authorization URL (for initial request)
	Token      string `json:"token,omitempty"`       // Session token (for callback)
	User       *User  `json:"user,omitempty"`        // User information (for callback)
	IsNewUser  bool   `json:"is_new_user,omitempty"` // Whether this is a new user registration
	StatusCode int    `json:"-"`                     // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"`       // Error message if any
}

// SessionsResponse represents the response for user session listing
type SessionsResponse struct {
	Sessions   []*Session `json:"sessions"`        // List of user sessions
	StatusCode int        `json:"-"`               // HTTP status code (not serialized)
	Error      string     `json:"error,omitempty"` // Error message if any
}

// LogoutResponse represents the response for user logout
type LogoutResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// ForgotPasswordRequest represents a password reset request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"` // User's email address
}

// ForgotPasswordResponse represents the response for password reset request
type ForgotPasswordResponse struct {
	Message    string `json:"message"`         // Success message with instructions
	Token      string `json:"token,omitempty"` // Reset token (for development/testing)
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// ResetPasswordRequest represents a password reset confirmation
type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`          // Reset token from email
	Password string `json:"password" validate:"required,min=8"` // New password
}

// ResetPasswordResponse represents the response for password reset confirmation
type ResetPasswordResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// ChangePasswordRequest represents a password change request (authenticated user)
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`   // Current password
	NewPassword     string `json:"new_password" validate:"required,min=8"` // New password
}

// ChangePasswordResponse represents the response for password change
type ChangePasswordResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// SignUpHandler processes user registration requests
func (a *AuthService) SignUpHandler(r *http.Request) SignUpResponse {
	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode signup request", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	// Validate request
	if err := a.validator.Struct(req); err != nil {
		slog.Debug("Signup validation failed", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Check if user already exists
	existingUser, err := a.storage.GetUserByEmailAnyProvider(req.Email)
	if err != nil {
		slog.Error("Failed to check existing user", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while checking user existence",
		}
	}

	if existingUser != nil {
		slog.Debug("User already exists", "email", req.Email)
		return SignUpResponse{
			StatusCode: http.StatusConflict,
			Error:      "User already exists",
		}
	}

	// Validate password strength
	if err := validatePasswordStrength(req.Password, a.securityConfig); err != nil {
		slog.Debug("Password validation failed", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusBadRequest,
			Error:      err.Error(),
		}
	}

	// Hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Password hashing failed",
		}
	}

	// Create user
	user := &User{
		Email:         strings.ToLower(req.Email),
		Username:      req.Username,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		PasswordHash:  hashedPassword,
		Provider:      "email",
		EmailVerified: false,
		IsActive:      true,
		IsSuspended:   false,
	}

	// Create user security record
	userSecurity := &UserSecurity{
		LoginAttempts:           0,
		TwoFactorEnabled:        false,
		ConcurrentSessions:      0,
		SecurityVersion:         1,
		RiskScore:               0,
		SuspiciousActivityCount: 0,
	}

	// Create user and security record atomically in a transaction
	if err := a.storage.CreateUserWithSecurity(user, userSecurity); err != nil {
		slog.Error("Failed to create user with security", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to create user",
		}
	}

	// Create session
	sessionToken, err := generateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session token generation failed",
		}
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()
	deviceFingerprint := generateDeviceFingerprint(userAgent, ip)

	session := &Session{
		Token:             sessionToken,
		UserID:            user.ID,
		ExpiresAt:         calculateSessionExpiry(a.securityConfig),
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
		IPAddress:         ip,
		IsActive:          true,
		LastAccessedAt:    time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		slog.Error("Failed to create session", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session creation failed",
		}
	}

	// Log security event
	a.logSecurityEvent(&user.ID, "user_signup", "User successfully registered", ip, userAgent, true)

	slog.Info("User registered successfully", "user_id", user.ID, "email", user.Email)

	// Clear password hash from response
	user.PasswordHash = ""

	return SignUpResponse{
		StatusCode: http.StatusCreated,
		Token:      sessionToken,
		User:       user,
	}
}

// SignInHandler processes user authentication requests
func (a *AuthService) SignInHandler(r *http.Request) SignInResponse {
	var req SignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode signin request", "error", err)
		return SignInResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	// Validate request
	if err := a.validator.Struct(req); err != nil {
		slog.Debug("Signin validation failed", "error", err)
		return SignInResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()

	// Find user
	user, err := a.storage.GetUserByEmail(req.Email, "email")
	if err != nil {
		slog.Error("Failed to get user", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user",
		}
	}

	if user == nil {
		slog.Debug("User not found", "email", req.Email)
		a.logSecurityEvent(nil, "login_failed", "Login attempt for non-existent user", ip, userAgent, false)
		return SignInResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid credentials",
		}
	}

	// Check if user is active
	if !user.IsActive || user.IsSuspended {
		slog.Debug("User account is inactive or suspended", "user_id", user.ID)
		a.logSecurityEvent(&user.ID, "login_failed", "Login attempt on inactive/suspended account", ip, userAgent, false)
		return SignInResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is not active",
		}
	}

	// Get user security information
	userSecurity, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user security",
		}
	}

	// Check if account is locked
	if userSecurity != nil && userSecurity.LockedUntil != nil && time.Now().Before(*userSecurity.LockedUntil) {
		slog.Debug("Account is locked", "user_id", user.ID, "locked_until", userSecurity.LockedUntil)
		a.logSecurityEvent(&user.ID, "login_failed", "Login attempt on locked account", ip, userAgent, false)
		return SignInResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is temporarily locked",
		}
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		slog.Debug("Invalid password", "user_id", user.ID)

		// Handle failed login (increment attempts and potentially lock account atomically)
		wasLocked, err := a.storage.HandleFailedLogin(user.ID, a.securityConfig.MaxLoginAttempts, a.securityConfig.LockoutDuration)
		if err != nil {
			slog.Error("Failed to handle failed login", "error", err)
		} else if wasLocked {
			a.logSecurityEvent(&user.ID, "account_locked", "Account locked due to too many failed login attempts", ip, userAgent, true)
		}

		a.logSecurityEvent(&user.ID, "login_failed", "Invalid password provided", ip, userAgent, false)
		return SignInResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid credentials",
		}
	}

	// Reset login attempts on successful authentication
	if err := a.storage.ResetLoginAttempts(user.ID); err != nil {
		slog.Error("Failed to reset login attempts", "error", err)
	}

	// Update last login
	if err := a.storage.UpdateLastLogin(user.ID, &ip); err != nil {
		slog.Error("Failed to update last login", "error", err)
	}

	// Create session
	sessionToken, err := generateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session token generation failed",
		}
	}

	deviceFingerprint := generateDeviceFingerprint(userAgent, ip)
	expiresAt := calculateSessionExpiry(a.securityConfig)

	session := &Session{
		Token:             sessionToken,
		UserID:            user.ID,
		ExpiresAt:         expiresAt,
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
		IPAddress:         ip,
		IsActive:          true,
		LastAccessedAt:    time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		slog.Error("Failed to create session", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session creation failed",
		}
	}

	// Log successful login
	a.logSecurityEvent(&user.ID, EventLoginSuccess, "User successfully logged in", ip, userAgent, true)

	slog.Info("User logged in successfully", "user_id", user.ID, "email", user.Email)

	// Clear password hash from response
	user.PasswordHash = ""

	// Check if 2FA is required
	requires2FA := false
	if userSecurity != nil {
		requires2FA = userSecurity.TwoFactorEnabled || a.securityConfig.RequireTwoFactor
	}

	return SignInResponse{
		StatusCode:       http.StatusOK,
		Token:            sessionToken,
		User:             user,
		SessionID:        fmt.Sprintf("%d", session.ID),
		Requires2FA:      requires2FA,
		SessionExpiresAt: expiresAt,
	}
}

// ValidateHandler validates a session token and returns user information
func (a *AuthService) ValidateHandler(r *http.Request) ValidateResponse {
	token := extractTokenFromRequest(r)
	if token == "" {
		return ValidateResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "No token provided",
		}
	}

	// Get session
	session, err := a.storage.GetSession(token)
	if err != nil {
		slog.Error("Failed to get session", "error", err)
		return ValidateResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving session",
		}
	}

	if session == nil {
		return ValidateResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid token",
		}
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		if err := a.storage.DeleteSession(token); err != nil {
			slog.Error("Failed to delete expired session", "error", err)
		}
		return ValidateResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Token expired",
		}
	}

	// Get user
	user, err := a.storage.GetUserByID(session.UserID)
	if err != nil {
		slog.Error("Failed to get user", "error", err)
		return ValidateResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user",
		}
	}

	if user == nil {
		return ValidateResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not found",
		}
	}

	// Check if user is active
	if !user.IsActive || user.IsSuspended {
		return ValidateResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is not active",
		}
	}

	// Update session last accessed time
	session.LastAccessedAt = time.Now()
	if err := a.storage.UpdateSession(session); err != nil {
		slog.Error("Failed to update session", "error", err)
	}

	// Clear password hash from response
	user.PasswordHash = ""

	return ValidateResponse{
		StatusCode: http.StatusOK,
		User:       user,
	}
}

// LogoutHandler processes user logout requests
func (a *AuthService) LogoutHandler(r *http.Request) LogoutResponse {
	token := extractTokenFromRequest(r)
	if token == "" {
		return LogoutResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "No token provided",
		}
	}

	// Delete session
	if err := a.storage.DeleteSession(token); err != nil {
		slog.Error("Failed to delete session", "error", err)
		return LogoutResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while deleting session",
		}
	}

	return LogoutResponse{
		StatusCode: http.StatusOK,
		Message:    "Successfully logged out",
	}
}

// GetSessionsHandler returns all active sessions for a user
func (a *AuthService) GetSessionsHandler(r *http.Request) SessionsResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return SessionsResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	sessions, err := a.storage.GetUserSessions(user.ID)
	if err != nil {
		slog.Error("Failed to get user sessions", "error", err)
		return SessionsResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user sessions",
		}
	}

	return SessionsResponse{
		StatusCode: http.StatusOK,
		Sessions:   sessions,
	}
}

// ForgotPasswordHandler processes password reset requests
func (a *AuthService) ForgotPasswordHandler(r *http.Request) ForgotPasswordResponse {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode forgot password request", "error", err)
		return ForgotPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	// Validate request
	if err := a.validator.Struct(req); err != nil {
		return ForgotPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Check if user password reset is allowed
	if !a.securityConfig.AllowUserPasswordReset {
		slog.Warn("Password reset attempted but disabled in configuration")
		return ForgotPasswordResponse{
			StatusCode: http.StatusForbidden,
			Error:      "Password reset is not enabled",
		}
	}

	// Find user by email (any provider)
	user, err := a.storage.GetUserByEmailAnyProvider(req.Email)
	if err != nil {
		// Don't reveal if email exists or not for security
		slog.Info("Password reset requested for unknown email", "email", req.Email)
		return ForgotPasswordResponse{
			StatusCode: http.StatusOK,
			Message:    "If an account with this email exists, a password reset link has been sent.",
		}
	}

	// Check if user has email provider (password-based auth)
	if user.Provider != "email" {
		slog.Info("Password reset attempted for OAuth user", "email", req.Email, "provider", user.Provider)
		return ForgotPasswordResponse{
			StatusCode: http.StatusOK,
			Message:    "If an account with this email exists, a password reset link has been sent.",
		}
	}

	// Generate secure reset token
	token, err := generateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate password reset token", "error", err)
		return ForgotPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to generate reset token",
		}
	}

	// Create reset token record
	resetToken := &PasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
		CreatedAt: time.Now(),
	}

	if err := a.storage.CreatePasswordResetToken(resetToken); err != nil {
		slog.Error("Failed to create password reset token", "error", err)
		return ForgotPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to create reset token",
		}
	}

	// Log security event
	a.logSecurityEvent(&user.ID, EventPasswordReset, "Password reset requested",
		extractIP(r), r.Header.Get("User-Agent"), true)

	// For development: return token in response
	// In production, this would send an email
	resetURL := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", token)
	slog.Info("Password reset requested", "email", req.Email, "reset_url", resetURL)

	return ForgotPasswordResponse{
		StatusCode: http.StatusOK,
		Message:    "If an account with this email exists, a password reset link has been sent.",
		Token:      token, // Remove this in production
	}
}

// ResetPasswordHandler processes password reset confirmations
func (a *AuthService) ResetPasswordHandler(r *http.Request) ResetPasswordResponse {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode reset password request", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	// Validate request
	if err := a.validator.Struct(req); err != nil {
		return ResetPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Validate password strength
	if err := validatePasswordStrength(req.Password, a.securityConfig); err != nil {
		return ResetPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      err.Error(),
		}
	}

	// Get and validate reset token
	resetToken, err := a.storage.GetPasswordResetToken(req.Token)
	if err != nil {
		slog.Warn("Invalid or expired password reset token used", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid or expired reset token",
		}
	}

	// Get user
	user, err := a.storage.GetUserByID(resetToken.UserID)
	if err != nil {
		slog.Error("Failed to get user for password reset", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to retrieve user",
		}
	}

	// Hash new password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		slog.Error("Failed to hash new password", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to process password",
		}
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()
	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to update user password", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to update password",
		}
	}

	// Update user security info
	security, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security for password update", "error", err)
	} else {
		now := time.Now()
		security.PasswordChangedAt = &now
		security.ForcePasswordChange = false
		if err := a.storage.UpdateUserSecurity(security); err != nil {
			slog.Error("Failed to update user security after password change", "error", err)
		}
	}

	// Mark token as used
	if err := a.storage.UsePasswordResetToken(req.Token); err != nil {
		slog.Error("Failed to mark reset token as used", "error", err)
		// Don't fail the request for this
	}

	// Delete all user sessions (security best practice)
	if err := a.storage.DeleteUserSessions(user.ID); err != nil {
		slog.Error("Failed to delete user sessions after password reset", "error", err)
	}

	// Log security event
	a.logSecurityEvent(&user.ID, EventPasswordChanged, "Password reset completed",
		extractIP(r), r.Header.Get("User-Agent"), true)

	return ResetPasswordResponse{
		StatusCode: http.StatusOK,
		Message:    "Password has been successfully reset",
	}
}

// ChangePasswordHandler processes password change requests for authenticated users
func (a *AuthService) ChangePasswordHandler(r *http.Request) ChangePasswordResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return ChangePasswordResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode change password request", "error", err)
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	// Validate request
	if err := a.validator.Struct(req); err != nil {
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Validate new password strength
	if err := validatePasswordStrength(req.NewPassword, a.securityConfig); err != nil {
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      err.Error(),
		}
	}

	// Verify current password
	if !checkPasswordHash(req.CurrentPassword, user.PasswordHash) {
		// Log failed password change attempt
		a.logSecurityEvent(&user.ID, EventPasswordChanged, "Password change failed - incorrect current password",
			extractIP(r), r.Header.Get("User-Agent"), false)
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Current password is incorrect",
		}
	}

	// Hash new password
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		slog.Error("Failed to hash new password", "error", err)
		return ChangePasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to process password",
		}
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()
	if err := a.storage.UpdateUser(user); err != nil {
		slog.Error("Failed to update user password", "error", err)
		return ChangePasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to update password",
		}
	}

	// Update user security info
	security, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security for password change", "error", err)
	} else {
		now := time.Now()
		security.PasswordChangedAt = &now
		security.ForcePasswordChange = false
		if err := a.storage.UpdateUserSecurity(security); err != nil {
			slog.Error("Failed to update user security after password change", "error", err)
		}
	}

	// Delete all other user sessions (keep current session)
	// Note: This is a security decision - password change invalidates other sessions
	currentToken := extractTokenFromRequest(r)
	sessions, err := a.storage.GetUserSessions(user.ID)
	if err == nil {
		for _, session := range sessions {
			if session.Token != currentToken {
				a.storage.DeleteSession(session.Token)
			}
		}
	}

	// Log security event
	a.logSecurityEvent(&user.ID, EventPasswordChanged, "Password changed successfully",
		extractIP(r), r.Header.Get("User-Agent"), true)

	return ChangePasswordResponse{
		StatusCode: http.StatusOK,
		Message:    "Password has been successfully changed",
	}
}
