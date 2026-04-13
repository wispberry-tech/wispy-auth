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
	Token      string `json:"token"`
	User       *User  `json:"user"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// SignInRequest represents a user login request
type SignInRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// SignInResponse represents the response for user authentication
type SignInResponse struct {
	Token            string    `json:"token"`
	User             *User     `json:"user"`
	SessionID        string    `json:"session_id"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	Requires2FA      bool      `json:"requires_2fa"`
	StatusCode       int       `json:"-"`
	Error            string    `json:"error,omitempty"`
}

// ValidateResponse represents the response for token validation
type ValidateResponse struct {
	User       *User  `json:"user"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// LogoutResponse represents the response for user logout
type LogoutResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// GetSessionsResponse represents the response for user session listing
type GetSessionsResponse struct {
	Sessions   []*Session `json:"sessions"`
	StatusCode int        `json:"-"`
	Error      string     `json:"error,omitempty"`
}

// ForgotPasswordRequest represents a password reset request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ForgotPasswordResponse represents the response for password reset request
type ForgotPasswordResponse struct {
	Message    string `json:"message"`
	Token      string `json:"token,omitempty"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// ResetPasswordRequest represents a password reset confirmation
type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
}

// ResetPasswordResponse represents the response for password reset confirmation
type ResetPasswordResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// ChangePasswordRequest represents a password change request (authenticated user)
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// ChangePasswordResponse represents the response for password change
type ChangePasswordResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// OAuth Request and Response Types

// OAuthResponse represents the response for OAuth operations
type OAuthResponse struct {
	Token      string `json:"token,omitempty"`
	URL        string `json:"url,omitempty"`
	User       *User  `json:"user,omitempty"`
	IsNewUser  bool   `json:"is_new_user,omitempty"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// 2FA Request and Response Types

// Enable2FARequest represents 2FA enablement request
type Enable2FARequest struct {
	Password string `json:"password" validate:"required"`
}

// Enable2FAResponse represents 2FA enablement response
type Enable2FAResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// VerifyEnable2FARequest represents 2FA enablement verification request
type VerifyEnable2FARequest struct {
	Code string `json:"code" validate:"required,len=6"`
}

// VerifyEnable2FAResponse represents 2FA enablement verification response
type VerifyEnable2FAResponse struct {
	BackupCodes []string `json:"backup_codes"`
	Message     string   `json:"message"`
	StatusCode  int      `json:"-"`
	Error       string   `json:"error,omitempty"`
}

// Disable2FARequest represents 2FA disablement request
type Disable2FARequest struct {
	Password string `json:"password" validate:"required"`
}

// Disable2FAResponse represents 2FA disablement response
type Disable2FAResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// VerifyLogin2FARequest represents 2FA login verification request
type VerifyLogin2FARequest struct {
	Code string `json:"code" validate:"required"`
}

// VerifyLogin2FAResponse represents 2FA login verification response
type VerifyLogin2FAResponse struct {
	Token      string `json:"token"`
	User       *User  `json:"user"`
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// GetBackupCodesRequest represents get backup codes request
type GetBackupCodesRequest struct {
	Password string `json:"password" validate:"required"`
}

// GetBackupCodesResponse represents get backup codes response
type GetBackupCodesResponse struct {
	Codes      []string `json:"codes"`
	StatusCode int      `json:"-"`
	Error      string   `json:"error,omitempty"`
}

// RegenerateBackupCodesRequest represents regenerate backup codes request
type RegenerateBackupCodesRequest struct {
	Password string `json:"password" validate:"required"`
}

// RegenerateBackupCodesResponse represents regenerate backup codes response
type RegenerateBackupCodesResponse struct {
	Codes      []string `json:"codes"`
	Message    string   `json:"message"`
	StatusCode int      `json:"-"`
	Error      string   `json:"error,omitempty"`
}

// Refresh Token Request and Response Types

// RefreshTokenRequest represents refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshTokenResponse represents refresh token response
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"`
	User        *User  `json:"user"`
	StatusCode  int    `json:"-"`
	Error       string `json:"error,omitempty"`
}

// Handler Functions

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

	if err := a.validator.Struct(req); err != nil {
		slog.Debug("Signup validation failed", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()

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
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Create user security record
	userSecurity := &UserSecurity{
		LoginAttempts:           0,
		TwoFactorEnabled:        false,
		ConcurrentSessions:      0,
		SecurityVersion:         1,
		RiskScore:               0,
		SuspiciousActivityCount: 0,
		CreatedAt:               time.Now(),
		UpdatedAt:               time.Now(),
	}

	// Create user and security record atomically in a transaction
	if err := a.storage.CreateUserWithSecurity(user, userSecurity); err != nil {
		slog.Error("Failed to create user with security", "error", err)
		// Check if it's a duplicate user error
		if strings.Contains(err.Error(), "user already exists") || strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return SignUpResponse{
				StatusCode: http.StatusConflict,
				Error:      "User already exists",
			}
		}
		return SignUpResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to create user",
		}
	}

	// Create session
	sessionToken, err := GenerateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err)
		return SignUpResponse{
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
		CreatedAt:         time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		slog.Error("Failed to create session", "error", err)
		return SignUpResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session creation failed",
		}
	}

	a.logSecurityEvent(&user.ID, "user_signup", "User successfully registered", ip, userAgent, true)
	slog.Info("User registered successfully", "user_id", user.ID, "email", user.Email)

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

	if err := a.validator.Struct(req); err != nil {
		slog.Debug("Signin validation failed", "error", err)
		return SignInResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()

	user, err := a.storage.GetUserByEmail(req.Email, "email")
	if err != nil {
		slog.Error("Failed to get user", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user",
		}
	}

	if user == nil {
		a.logSecurityEvent(nil, "login_failed", "Login attempt for non-existent user", ip, userAgent, false)
		return SignInResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid credentials",
		}
	}

	if !user.IsActive || user.IsSuspended {
		a.logSecurityEvent(&user.ID, "login_failed", "Login attempt on inactive/suspended account", ip, userAgent, false)
		return SignInResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is not active",
		}
	}

	security, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user security",
		}
	}

	// Check if account is locked
	if security != nil && security.LockedUntil != nil && time.Now().Before(*security.LockedUntil) {
		a.logSecurityEvent(&user.ID, "login_failed", "Login attempt on locked account", ip, userAgent, false)
		return SignInResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is temporarily locked",
		}
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
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

	// Check if 2FA is required
	requires2FA := false
	if security != nil {
		requires2FA = security.TwoFactorEnabled || a.securityConfig.RequireTwoFactor
	}

	// Send 2FA code if required
	if requires2FA {
		if err := a.SendLogin2FACode(user.ID); err != nil {
			slog.Error("Failed to send 2FA code", "error", err)
			return SignInResponse{
				StatusCode: http.StatusInternalServerError,
				Error:      "Failed to send 2FA code",
			}
		}

		return SignInResponse{
			StatusCode:  http.StatusOK,
			Requires2FA: true,
			User:        user,
		}
	}

	// Create session
	sessionToken, err := GenerateSecureToken(32)
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
		CreatedAt:         time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		slog.Error("Failed to create session", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session creation failed",
		}
	}

	// Log successful login
	a.logSecurityEvent(&user.ID, "login_success", "User successfully logged in", ip, userAgent, true)
	slog.Info("User logged in successfully", "user_id", user.ID, "email", user.Email)

	// Clear password hash from response
	user.PasswordHash = ""

	// Create refresh token
	refreshToken, err := GenerateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate refresh token", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Refresh token generation failed",
		}
	}

	refresh := &RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		SessionID: session.ID,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := a.storage.CreateRefreshToken(refresh); err != nil {
		slog.Error("Failed to create refresh token", "error", err)
		return SignInResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Refresh token creation failed",
		}
	}

	return SignInResponse{
		StatusCode:       http.StatusOK,
		Token:            sessionToken,
		User:             user,
		SessionID:        fmt.Sprintf("%d", session.ID),
		SessionExpiresAt: expiresAt,
		RefreshToken:     refreshToken,
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

	if time.Now().After(session.ExpiresAt) {
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
		slog.Error("Failed to update session last accessed time", "error", err)
	}

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

	if err := a.storage.DeleteSession(token); err != nil {
		slog.Error("Failed to delete session", "error", err)
		return LogoutResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while deleting session",
		}
	}

	a.logSecurityEvent(nil, "session_terminated", "User logged out", "", "", false)

	return LogoutResponse{
		StatusCode: http.StatusOK,
		Message:    "Successfully logged out",
	}
}

// GetSessionsHandler returns all active sessions for a user
func (a *AuthService) GetSessionsHandler(r *http.Request) GetSessionsResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return GetSessionsResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	sessions, err := a.storage.GetUserSessions(user.ID)
	if err != nil {
		slog.Error("Failed to get user sessions", "error", err)
		return GetSessionsResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user sessions",
		}
	}

	return GetSessionsResponse{
		StatusCode: http.StatusOK,
		Sessions:   sessions,
	}
}

// ForgotPasswordHandler processes password reset requests
func (a *AuthService) ForgotPasswordHandler(r *http.Request) ForgotPasswordResponse {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return ForgotPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return ForgotPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	if !a.securityConfig.AllowUserPasswordReset {
		return ForgotPasswordResponse{
			StatusCode: http.StatusForbidden,
			Error:      "Password reset is not enabled",
		}
	}

	user, err := a.storage.GetUserByEmailAnyProvider(req.Email)
	if err != nil {
		slog.Error("Failed to get user", "error", err)
		return ForgotPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while retrieving user",
		}
	}

	if user == nil {
		slog.Info("Password reset requested for unknown email", "email", req.Email)
		return ForgotPasswordResponse{
			StatusCode: http.StatusOK,
			Message:    "If an account with this email exists, a password reset link has been sent.",
		}
	}

	if user.Provider != "email" {
		slog.Info("Password reset attempted for OAuth user", "email", req.Email, "provider", user.Provider)
		return ForgotPasswordResponse{
			StatusCode: http.StatusOK,
			Message:    "If an account with this email exists, a password reset link has been sent.",
		}
	}

	token, err := GenerateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate password reset token", "error", err)
		return ForgotPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to generate reset token",
		}
	}

	resetToken := &PasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(a.securityConfig.PasswordResetExpiry),
		CreatedAt: time.Now(),
	}

	if err := a.storage.CreatePasswordResetToken(resetToken); err != nil {
		slog.Error("Failed to create password reset token", "error", err)
		return ForgotPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to create reset token",
		}
	}

	a.logSecurityEvent(&user.ID, "password_reset", "Password reset requested",
		extractIP(r), r.Header.Get("User-Agent"), true)

	response := ForgotPasswordResponse{
		StatusCode: http.StatusOK,
		Message:    "If an account with this email exists, a password reset link has been sent.",
		Token:      "",
	}

	if a.securityConfig.DebugMode {
		response.Token = token
		slog.Warn("Password reset token returned in response (debug mode)", "email", req.Email)
	}

	return response
}

// ResetPasswordHandler processes password reset confirmations
func (a *AuthService) ResetPasswordHandler(r *http.Request) ResetPasswordResponse {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return ResetPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

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
	if err != nil || resetToken == nil {
		slog.Warn("Invalid or expired password reset token")
		return ResetPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid or expired reset token",
		}
	}

	// Check if token is expired
	if time.Now().After(resetToken.ExpiresAt) {
		return ResetPasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Reset token expired",
		}
	}

	// Get user
	user, err := a.storage.GetUserByID(resetToken.UserID)
	if err != nil || user == nil {
		slog.Error("Failed to get user", "error", err)
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
			Error:      "Failed to update user password",
		}
	}

	// Update user security info
	security, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to update user security",
		}
	}

	now := time.Now()
	security.PasswordChangedAt = &now
	security.ForcePasswordChange = false
	if err := a.storage.UpdateUserSecurity(security); err != nil {
		slog.Error("Failed to update user security", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to update user security",
		}
	}

	// Mark token as used
	if err := a.storage.UsePasswordResetToken(req.Token); err != nil {
		slog.Error("Failed to mark password reset token as used", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to mark reset token as used",
		}
	}

	// Delete all user sessions
	if err := a.storage.DeleteUserSessions(user.ID); err != nil {
		slog.Error("Failed to delete user sessions", "error", err)
		return ResetPasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to delete user sessions",
		}
	}

	// Log security event
	a.logSecurityEvent(&user.ID, "password_changed", "Password reset completed",
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
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Verify current password
	if !checkPasswordHash(req.CurrentPassword, user.PasswordHash) {
		a.logSecurityEvent(&user.ID, EventPasswordChanged, "Password change failed - incorrect current password provided",
			extractIP(r), r.Header.Get("User-Agent"), false)
		return ChangePasswordResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Incorrect current password",
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
			Error:      "Failed to update user password",
		}
	}

	// Update user security info
	security, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		return ChangePasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to update user security",
		}
	}

	now := time.Now()
	security.PasswordChangedAt = &now
	security.ForcePasswordChange = false
	if err := a.storage.UpdateUserSecurity(security); err != nil {
		slog.Error("Failed to update user security", "error", err)
		return ChangePasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to update user security",
		}
	}

	// Delete all other user sessions (keep current session)
	currentToken := extractTokenFromRequest(r)
	sessions, err := a.storage.GetUserSessions(user.ID)
	if err != nil {
		slog.Error("Failed to get user sessions", "error", err)
		return ChangePasswordResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to get user sessions",
		}
	}

	for _, session := range sessions {
		if session.Token != currentToken {
			if err := a.storage.DeleteSession(session.Token); err != nil {
				slog.Error("Failed to delete other user sessions", "error", err)
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

// 2FA Handlers

// Enable2FAHandler initiates 2FA enablement
func (a *AuthService) Enable2FAHandler(r *http.Request) Enable2FAResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return Enable2FAResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	var req Enable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Enable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return Enable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		return Enable2FAResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid password",
		}
	}

	// Generate and send 2FA verification code
	if err := a.Enable2FA(user.ID); err != nil {
		return Enable2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to enable 2FA",
		}
	}

	return Enable2FAResponse{
		StatusCode: http.StatusOK,
		Message:    "2FA verification code sent to your email",
	}
}

// VerifyEnable2FAHandler verifies 2FA enablement code and enables 2FA
func (a *AuthService) VerifyEnable2FAHandler(r *http.Request) VerifyEnable2FAResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	var req VerifyEnable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	twoFactorCode, err := a.storage.Get2FACode(user.ID, req.Code)
	if err != nil || twoFactorCode == nil {
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid or expired code",
		}
	}

	if twoFactorCode.CodeType != "enable" {
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid code type",
		}
	}

	if time.Now().After(twoFactorCode.ExpiresAt) {
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Code expired",
		}
	}

	// Enable 2FA and generate backup codes
	security, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to get user security",
		}
	}

	security.TwoFactorEnabled = true
	now := time.Now()
	security.TwoFactorVerifiedAt = &now

	if err := a.storage.Use2FACode(user.ID, req.Code); err != nil {
		slog.Error("Failed to mark 2FA code as used", "error", err)
	}

	// Generate backup codes
	backupCodes, err := a.generateBackupCodes(user.ID)
	if err != nil {
		slog.Error("Failed to generate backup codes", "error", err)
		return VerifyEnable2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to generate backup codes",
		}
	}

	codeStrs := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		codeStrs[i] = code.Code
	}

	a.logSecurityEvent(&user.ID, "2fa_enabled", "2FA enabled successfully",
		extractIP(r), r.Header.Get("User-Agent"), true)

	return VerifyEnable2FAResponse{
		StatusCode:  http.StatusOK,
		BackupCodes: codeStrs,
		Message:     "2FA enabled successfully. Save these backup codes securely.",
	}
}

// Disable2FAHandler disables 2FA
func (a *AuthService) Disable2FAHandler(r *http.Request) Disable2FAResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return Disable2FAResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	var req Disable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Disable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return Disable2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		return Disable2FAResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid password",
		}
	}

	// Disable 2FA
	security, err := a.storage.GetUserSecurity(user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		return Disable2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to get user security",
		}
	}

	security.TwoFactorEnabled = false
	security.TwoFactorSecret = ""
	security.TwoFactorBackupCodes = ""
	security.TwoFactorVerifiedAt = nil

	if err := a.storage.UpdateUserSecurity(security); err != nil {
		slog.Error("Failed to update user security", "error", err)
		return Disable2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to update user security",
		}
	}

	a.logSecurityEvent(&user.ID, "2fa_disabled", "2FA disabled",
		extractIP(r), r.Header.Get("User-Agent"), true)

	return Disable2FAResponse{
		StatusCode: http.StatusOK,
		Message:    "2FA disabled successfully",
	}
}

// VerifyLogin2FAHandler verifies 2FA during login
func (a *AuthService) VerifyLogin2FAHandler(r *http.Request) VerifyLogin2FAResponse {
	var req VerifyLogin2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	code := req.Code
	ip := extractIP(r)
	userAgent := r.UserAgent()

	// Check if it's a backup code
	if len(code) > 10 {
		// For backup codes, we need the user ID from the code
		backupCode, err := a.storage.GetBackupCodeByCode(code)
		if err != nil || backupCode == nil {
			return VerifyLogin2FAResponse{
				StatusCode: http.StatusBadRequest,
				Error:      "Invalid backup code",
			}
		}

		if err := a.storage.Use2FABackupCode(backupCode.UserID, code); err != nil {
			return VerifyLogin2FAResponse{
				StatusCode: http.StatusBadRequest,
				Error:      "Invalid backup code",
			}
		}

		user, err := a.storage.GetUserByID(backupCode.UserID)
		if err != nil || user == nil {
			return VerifyLogin2FAResponse{
				StatusCode: http.StatusInternalServerError,
				Error:      "User not found",
			}
		}

		a.logSecurityEvent(&user.ID, "2fa_backup_code_used", "Backup code used for login", ip, userAgent, true)

		return a.createSessionAndResponse(user, ip, userAgent)
	}

	// For regular 2FA codes, we need to find the user
	// This requires either storing the user ID with the code or using a temporary session
	// For now, let's assume the code is stored with the user ID
	twoFactorCode, err := a.storage.GetLatestPending2FACode(code)
	if err != nil || twoFactorCode == nil {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid or expired 2FA code",
		}
	}

	if twoFactorCode.CodeType != "login" {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid code type",
		}
	}

	if time.Now().After(twoFactorCode.ExpiresAt) {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Code expired",
		}
	}

	// Mark code as used
	if err := a.storage.Use2FACode(twoFactorCode.UserID, code); err != nil {
		slog.Error("Failed to mark 2FA code as used", "error", err)
	}

	user, err := a.storage.GetUserByID(twoFactorCode.UserID)
	if err != nil || user == nil {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "User not found",
		}
	}

	if !user.IsActive || user.IsSuspended {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is not active",
		}
	}

	a.logSecurityEvent(&user.ID, "2fa_verified", "2FA verified successfully", ip, userAgent, true)

	return a.createSessionAndResponse(user, ip, userAgent)
}

// createSessionAndResponse is a helper to create a session and return response
func (a *AuthService) createSessionAndResponse(user *User, ip, userAgent string) VerifyLogin2FAResponse {
	sessionToken, err := GenerateSecureToken(32)
	if err != nil {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to create session",
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
		CreatedAt:         time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		return VerifyLogin2FAResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session creation failed",
		}
	}

	user.PasswordHash = ""

	return VerifyLogin2FAResponse{
		StatusCode: http.StatusOK,
		Token:      sessionToken,
		User:       user,
	}
}

// GetBackupCodesHandler returns all backup codes for a user
func (a *AuthService) GetBackupCodesHandler(r *http.Request) GetBackupCodesResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return GetBackupCodesResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	backupCodes, err := a.GetBackupCodes(user.ID)
	if err != nil {
		slog.Error("Failed to get backup codes", "error", err)
		return GetBackupCodesResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to get backup codes",
		}
	}

	codeStrs := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		codeStrs[i] = code.Code
	}

	return GetBackupCodesResponse{
		StatusCode: http.StatusOK,
		Codes:      codeStrs,
	}
}

// RegenerateBackupCodesHandler generates new backup codes and invalidates old ones
func (a *AuthService) RegenerateBackupCodesHandler(r *http.Request) RegenerateBackupCodesResponse {
	user := GetUserFromContext(r)
	if user == nil {
		return RegenerateBackupCodesResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not authenticated",
		}
	}

	// Verify password first
	var req RegenerateBackupCodesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return RegenerateBackupCodesResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return RegenerateBackupCodesResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		return RegenerateBackupCodesResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid password",
		}
	}

	// Regenerate backup codes
	backupCodes, err := a.RegenerateBackupCodes(user.ID)
	if err != nil {
		return RegenerateBackupCodesResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to regenerate backup codes",
		}
	}

	codeStrs := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		codeStrs[i] = code.Code
	}

	return RegenerateBackupCodesResponse{
		StatusCode: http.StatusOK,
		Codes:      codeStrs,
		Message:    "Backup codes regenerated. Save them securely.",
	}
}

// RefreshTokenHandler exchanges refresh token for new session token
func (a *AuthService) RefreshTokenHandler(r *http.Request) RefreshTokenResponse {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return RefreshTokenResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid request format",
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return RefreshTokenResponse{
			StatusCode: http.StatusBadRequest,
			Error:      formatValidationErrors(err),
		}
	}

	refreshToken, err := a.storage.GetRefreshToken(req.RefreshToken)
	if err != nil || refreshToken == nil {
		return RefreshTokenResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid refresh token",
		}
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		return RefreshTokenResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Refresh token expired",
		}
	}

	user, err := a.storage.GetUserByID(refreshToken.UserID)
	if err != nil || user == nil {
		return RefreshTokenResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "User not found",
		}
	}

	if !user.IsActive || user.IsSuspended {
		return RefreshTokenResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is not active",
		}
	}

	sessionToken, err := GenerateSecureToken(32)
	if err != nil {
		return RefreshTokenResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to generate session token",
		}
	}

	// Create new session
	sessionToken, err = GenerateSecureToken(32)
	if err != nil {
		return RefreshTokenResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to generate session token",
		}
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()
	deviceFingerprint := generateDeviceFingerprint(userAgent, ip)
	expiresAt := calculateSessionExpiry(a.securityConfig)

	session := &Session{
		Token:             sessionToken,
		UserID:            refreshToken.UserID,
		ExpiresAt:         expiresAt,
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
		IPAddress:         ip,
		IsActive:          true,
		LastAccessedAt:    time.Now(),
		CreatedAt:         time.Now(),
	}

	if err := a.storage.CreateSession(session); err != nil {
		return RefreshTokenResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session creation failed",
		}
	}

	// Update refresh token with new session ID
	refreshToken.SessionID = session.ID
	now := time.Now()
	refreshToken.LastUsedAt = &now
	if err := a.storage.UpdateRefreshToken(refreshToken); err != nil {
		slog.Error("Failed to update refresh token", "error", err)
	}

	user.PasswordHash = ""

	return RefreshTokenResponse{
		StatusCode:  http.StatusOK,
		AccessToken: sessionToken,
		User:        user,
	}
}
