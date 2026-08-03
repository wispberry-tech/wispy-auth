package core

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// writeJSON writes a JSON response with the given status code and body
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

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
	SessionID        uint      `json:"session_id"`
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
func (a *AuthService) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode signup request", "error", err)
		writeJSON(w, http.StatusBadRequest, SignUpResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		slog.Debug("Signup validation failed", "error", err)
		writeJSON(w, http.StatusBadRequest, SignUpResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()

	// Validate password strength
	if err := validatePasswordStrength(req.Password, a.securityConfig); err != nil {
		slog.Debug("Password validation failed", "error", err)
		writeJSON(w, http.StatusBadRequest, SignUpResponse{StatusCode: http.StatusBadRequest, Error: err.Error()})
		return
	}

	// Hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignUpResponse{StatusCode: http.StatusInternalServerError, Error: "Password hashing failed"})
		return
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
	if err := a.storage.CreateUserWithSecurity(r.Context(), user, userSecurity); err != nil {
		slog.Error("Failed to create user with security", "error", err)
		// Check if it's a duplicate user error
		if strings.Contains(err.Error(), "user already exists") || strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeJSON(w, http.StatusConflict, SignUpResponse{StatusCode: http.StatusConflict, Error: "User already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, SignUpResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to create user"})
		return
	}

	// Create session
	sessionToken, err := GenerateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignUpResponse{StatusCode: http.StatusInternalServerError, Error: "Session token generation failed"})
		return
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

	if err := a.storage.CreateSession(r.Context(), session); err != nil {
		slog.Error("Failed to create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignUpResponse{StatusCode: http.StatusInternalServerError, Error: "Session creation failed"})
		return
	}

	a.logSecurityEvent(&user.ID, "user_signup", "User successfully registered", ip, userAgent, true)
	slog.Info("User registered successfully", "user_id", user.ID, "email", user.Email)

	user.PasswordHash = ""

	writeJSON(w, http.StatusCreated, SignUpResponse{StatusCode: http.StatusCreated, Token: sessionToken,
		User: user})
	return
}

// SignInHandler processes user authentication requests
func (a *AuthService) SignInHandler(w http.ResponseWriter, r *http.Request) {
	var req SignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Debug("Failed to decode signin request", "error", err)
		writeJSON(w, http.StatusBadRequest, SignInResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		slog.Debug("Signin validation failed", "error", err)
		writeJSON(w, http.StatusBadRequest, SignInResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()

	user, err := a.storage.GetUserByEmail(r.Context(), req.Email, "email")
	if err != nil {
		slog.Error("Failed to get user", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignInResponse{StatusCode: http.StatusInternalServerError, Error: "Database error while retrieving user"})
		return
	}

	if user == nil {
		a.logSecurityEvent(nil, "login_failed", "Login attempt for non-existent user", ip, userAgent, false)
		writeJSON(w, http.StatusUnauthorized, SignInResponse{StatusCode: http.StatusUnauthorized, Error: "Invalid credentials"})
		return
	}

	if !user.IsActive || user.IsSuspended {
		a.logSecurityEvent(&user.ID, "login_failed", "Login attempt on inactive/suspended account", ip, userAgent, false)
		writeJSON(w, http.StatusUnauthorized, SignInResponse{StatusCode: http.StatusUnauthorized, Error: "Account is not active"})
		return
	}

	security, err := a.storage.GetUserSecurity(r.Context(), user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignInResponse{StatusCode: http.StatusInternalServerError, Error: "Database error while retrieving user security"})
		return
	}

	// Check if account is locked
	if security != nil && security.LockedUntil != nil && time.Now().Before(*security.LockedUntil) {
		a.logSecurityEvent(&user.ID, "login_failed", "Login attempt on locked account", ip, userAgent, false)
		writeJSON(w, http.StatusUnauthorized, SignInResponse{StatusCode: http.StatusUnauthorized, Error: "Account is temporarily locked"})
		return
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		// Handle failed login (increment attempts and potentially lock account atomically)
		wasLocked, err := a.storage.HandleFailedLogin(r.Context(), user.ID, a.securityConfig.MaxLoginAttempts, a.securityConfig.LockoutDuration)
		if err != nil {
			slog.Error("Failed to handle failed login", "error", err)
		} else if wasLocked {
			a.logSecurityEvent(&user.ID, "account_locked", "Account locked due to too many failed login attempts", ip, userAgent, true)
		}

		a.logSecurityEvent(&user.ID, "login_failed", "Invalid password provided", ip, userAgent, false)
		writeJSON(w, http.StatusUnauthorized, SignInResponse{StatusCode: http.StatusUnauthorized, Error: "Invalid credentials"})
		return
	}

	// Reset login attempts on successful authentication
	if err := a.storage.ResetLoginAttempts(r.Context(), user.ID); err != nil {
		slog.Error("Failed to reset login attempts", "error", err)
	}

	// Update last login
	if err := a.storage.UpdateLastLogin(r.Context(), user.ID, &ip); err != nil {
		slog.Error("Failed to update last login", "error", err)
	}

	// Check if 2FA is required
	requires2FA := false
	if security != nil {
		requires2FA = security.TwoFactorEnabled || *a.securityConfig.RequireTwoFactor
	}

	// Send 2FA code if required
	if requires2FA {
		if err := a.SendLogin2FACode(user.ID); err != nil {
			slog.Error("Failed to send 2FA code", "error", err)
			writeJSON(w, http.StatusInternalServerError, SignInResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to send 2FA code"})
			return
		}

		writeJSON(w, http.StatusOK, SignInResponse{StatusCode: http.StatusOK, Requires2FA: true,
			User: user})
		return
	}

	// Create session
	sessionToken, err := GenerateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignInResponse{StatusCode: http.StatusInternalServerError, Error: "Session token generation failed"})
		return
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

	if err := a.storage.CreateSession(r.Context(), session); err != nil {
		slog.Error("Failed to create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignInResponse{StatusCode: http.StatusInternalServerError, Error: "Session creation failed"})
		return
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
		writeJSON(w, http.StatusInternalServerError, SignInResponse{StatusCode: http.StatusInternalServerError, Error: "Refresh token generation failed"})
		return
	}

	refresh := &RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		SessionID: session.ID,
		ExpiresAt: time.Now().Add(a.securityConfig.RefreshTokenLifetime),
		CreatedAt: time.Now(),
	}

	if err := a.storage.CreateRefreshToken(r.Context(), refresh); err != nil {
		slog.Error("Failed to create refresh token", "error", err)
		writeJSON(w, http.StatusInternalServerError, SignInResponse{StatusCode: http.StatusInternalServerError, Error: "Refresh token creation failed"})
		return
	}

	writeJSON(w, http.StatusOK, SignInResponse{StatusCode: http.StatusOK, Token: sessionToken,
		User:             user,
		SessionID:        session.ID,
		SessionExpiresAt: expiresAt,
		RefreshToken:     refreshToken})
	return
}

// ValidateHandler validates a session token and returns user information
func (a *AuthService) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, ValidateResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid or expired session",
		})
		return
	}

	writeJSON(w, http.StatusOK, ValidateResponse{
		StatusCode: http.StatusOK,
		User:       user,
	})
}

// LogoutHandler processes user logout requests
func (a *AuthService) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, LogoutResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Invalid or expired session",
		})
		return
	}

	session := GetSessionFromContext(r)
	if err := a.storage.DeleteSession(r.Context(), session.Token); err != nil {
		slog.Error("Failed to delete session", "error", err)
		writeJSON(w, http.StatusInternalServerError, LogoutResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while deleting session",
		})
		return
	}

	a.logSecurityEvent(nil, "session_terminated", "User logged out", "", "", false)

	writeJSON(w, http.StatusOK, LogoutResponse{
		StatusCode: http.StatusOK,
		Message:    "Successfully logged out",
	})
}

// GetSessionsHandler returns all active sessions for a user
func (a *AuthService) GetSessionsHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, GetSessionsResponse{StatusCode: http.StatusUnauthorized, Error: "User not authenticated"})
		return
	}

	sessions, err := a.storage.GetUserSessions(r.Context(), user.ID)
	if err != nil {
		slog.Error("Failed to get user sessions", "error", err)
		writeJSON(w, http.StatusInternalServerError, GetSessionsResponse{StatusCode: http.StatusInternalServerError, Error: "Database error while retrieving user sessions"})
		return
	}

	writeJSON(w, http.StatusOK, GetSessionsResponse{StatusCode: http.StatusOK, Sessions: sessions})
	return
}

// ForgotPasswordHandler processes password reset requests
func (a *AuthService) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ForgotPasswordResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, ForgotPasswordResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	if !*a.securityConfig.AllowUserPasswordReset {
		writeJSON(w, http.StatusForbidden, ForgotPasswordResponse{StatusCode: http.StatusForbidden, Error: "Password reset is not enabled"})
		return
	}

	user, err := a.storage.GetUserByEmailAnyProvider(r.Context(), req.Email)
	if err != nil {
		slog.Error("Failed to get user", "error", err)
		writeJSON(w, http.StatusInternalServerError, ForgotPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Database error while retrieving user"})
		return
	}

	if user == nil {
		slog.Info("Password reset requested for unknown email", "email", req.Email)
		writeJSON(w, http.StatusOK, ForgotPasswordResponse{StatusCode: http.StatusOK, Message: "If an account with this email exists, a password reset link has been sent."})
		return
	}

	if user.Provider != "email" {
		slog.Info("Password reset attempted for OAuth user", "email", req.Email, "provider", user.Provider)
		writeJSON(w, http.StatusOK, ForgotPasswordResponse{StatusCode: http.StatusOK, Message: "If an account with this email exists, a password reset link has been sent."})
		return
	}

	token, err := GenerateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate password reset token", "error", err)
		writeJSON(w, http.StatusInternalServerError, ForgotPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to generate reset token"})
		return
	}

	resetToken := &PasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(a.securityConfig.PasswordResetExpiry),
		CreatedAt: time.Now(),
	}

	if err := a.storage.CreatePasswordResetToken(r.Context(), resetToken); err != nil {
		slog.Error("Failed to create password reset token", "error", err)
		writeJSON(w, http.StatusInternalServerError, ForgotPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to create reset token"})
		return
	}

	a.logSecurityEvent(&user.ID, "password_reset", "Password reset requested",
		extractIP(r), r.Header.Get("User-Agent"), true)

	response := ForgotPasswordResponse{
		StatusCode: http.StatusOK,
		Message:    "If an account with this email exists, a password reset link has been sent.",
		Token:      "",
	}

	if *a.securityConfig.DebugMode {
		response.Token = token
		slog.Warn("Password reset token returned in response (debug mode)", "email", req.Email)
	}

	writeJSON(w, response.StatusCode, response)
	return
}

// ResetPasswordHandler processes password reset confirmations
func (a *AuthService) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ResetPasswordResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, ResetPasswordResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	// Validate password strength
	if err := validatePasswordStrength(req.Password, a.securityConfig); err != nil {
		writeJSON(w, http.StatusBadRequest, ResetPasswordResponse{StatusCode: http.StatusBadRequest, Error: err.Error()})
		return
	}

	// Get and validate reset token
	resetToken, err := a.storage.GetPasswordResetToken(r.Context(), req.Token)
	if err != nil || resetToken == nil {
		slog.Warn("Invalid or expired password reset token")
		writeJSON(w, http.StatusBadRequest, ResetPasswordResponse{StatusCode: http.StatusBadRequest, Error: "Invalid or expired reset token"})
		return
	}

	// Check if token is expired
	if time.Now().After(resetToken.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, ResetPasswordResponse{StatusCode: http.StatusBadRequest, Error: "Reset token expired"})
		return
	}

	// Get user
	user, err := a.storage.GetUserByID(r.Context(), resetToken.UserID)
	if err != nil || user == nil {
		slog.Error("Failed to get user", "error", err)
		writeJSON(w, http.StatusInternalServerError, ResetPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to retrieve user"})
		return
	}

	// Hash new password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		slog.Error("Failed to hash new password", "error", err)
		writeJSON(w, http.StatusInternalServerError, ResetPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to process password"})
		return
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()
	if err := a.storage.UpdateUser(r.Context(), user); err != nil {
		slog.Error("Failed to update user password", "error", err)
		writeJSON(w, http.StatusInternalServerError, ResetPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user password"})
		return
	}

	// Update user security info
	security, err := a.storage.GetUserSecurity(r.Context(), user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, ResetPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user security"})
		return
	}

	now := time.Now()
	security.PasswordChangedAt = &now
	security.ForcePasswordChange = false
	if err := a.storage.UpdateUserSecurity(r.Context(), security); err != nil {
		slog.Error("Failed to update user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, ResetPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user security"})
		return
	}

	// Mark token as used
	if err := a.storage.UsePasswordResetToken(r.Context(), req.Token); err != nil {
		slog.Error("Failed to mark password reset token as used", "error", err)
		writeJSON(w, http.StatusInternalServerError, ResetPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to mark reset token as used"})
		return
	}

	// Delete all user sessions
	if err := a.storage.DeleteUserSessions(r.Context(), user.ID); err != nil {
		slog.Error("Failed to delete user sessions", "error", err)
		writeJSON(w, http.StatusInternalServerError, ResetPasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to delete user sessions"})
		return
	}

	// Log security event
	a.logSecurityEvent(&user.ID, "password_changed", "Password reset completed",
		extractIP(r), r.Header.Get("User-Agent"), true)

	writeJSON(w, http.StatusOK, ResetPasswordResponse{StatusCode: http.StatusOK, Message: "Password has been successfully reset"})
	return
}

// ChangePasswordHandler processes password change requests for authenticated users
func (a *AuthService) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, ChangePasswordResponse{StatusCode: http.StatusUnauthorized, Error: "User not authenticated"})
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ChangePasswordResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, ChangePasswordResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	// Verify current password
	if !checkPasswordHash(req.CurrentPassword, user.PasswordHash) {
		a.logSecurityEvent(&user.ID, EventPasswordChanged, "Password change failed - incorrect current password provided",
			extractIP(r), r.Header.Get("User-Agent"), false)
		writeJSON(w, http.StatusBadRequest, ChangePasswordResponse{StatusCode: http.StatusBadRequest, Error: "Incorrect current password"})
		return
	}

	// Hash new password
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		slog.Error("Failed to hash new password", "error", err)
		writeJSON(w, http.StatusInternalServerError, ChangePasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to process password"})
		return
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()
	if err := a.storage.UpdateUser(r.Context(), user); err != nil {
		slog.Error("Failed to update user password", "error", err)
		writeJSON(w, http.StatusInternalServerError, ChangePasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user password"})
		return
	}

	// Update user security info
	security, err := a.storage.GetUserSecurity(r.Context(), user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, ChangePasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user security"})
		return
	}

	now := time.Now()
	security.PasswordChangedAt = &now
	security.ForcePasswordChange = false
	if err := a.storage.UpdateUserSecurity(r.Context(), security); err != nil {
		slog.Error("Failed to update user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, ChangePasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user security"})
		return
	}

	// Delete all other user sessions (keep current session)
	currentSession := GetSessionFromContext(r)
	sessions, err := a.storage.GetUserSessions(r.Context(), user.ID)
	if err != nil {
		slog.Error("Failed to get user sessions", "error", err)
		writeJSON(w, http.StatusInternalServerError, ChangePasswordResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to get user sessions"})
		return
	}

	for _, session := range sessions {
		if session.Token != currentSession.Token {
			if err := a.storage.DeleteSession(r.Context(), session.Token); err != nil {
				slog.Error("Failed to delete other user sessions", "error", err)
			}
		}
	}

	// Log security event
	a.logSecurityEvent(&user.ID, EventPasswordChanged, "Password changed successfully",
		extractIP(r), r.Header.Get("User-Agent"), true)

	writeJSON(w, http.StatusOK, ChangePasswordResponse{StatusCode: http.StatusOK, Message: "Password has been successfully changed"})
	return
}

// 2FA Handlers

// Enable2FAHandler initiates 2FA enablement
func (a *AuthService) Enable2FAHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, Enable2FAResponse{StatusCode: http.StatusUnauthorized, Error: "User not authenticated"})
		return
	}

	var req Enable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Enable2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, Enable2FAResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	if a.emailService == nil {
		writeJSON(w, http.StatusInternalServerError, Enable2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Email service not configured"})
		return
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, Enable2FAResponse{StatusCode: http.StatusUnauthorized, Error: "Invalid password"})
		return
	}

	// Generate and send 2FA verification code
	if err := a.Enable2FA(user.ID, extractIP(r)); err != nil {
		writeJSON(w, http.StatusInternalServerError, Enable2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to enable 2FA"})
		return
	}

	writeJSON(w, http.StatusOK, Enable2FAResponse{StatusCode: http.StatusOK, Message: "2FA verification code sent to your email"})
	return
}

// VerifyEnable2FAHandler verifies 2FA enablement code and enables 2FA
func (a *AuthService) VerifyEnable2FAHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, VerifyEnable2FAResponse{StatusCode: http.StatusUnauthorized, Error: "User not authenticated"})
		return
	}

	var req VerifyEnable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, VerifyEnable2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, VerifyEnable2FAResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	twoFactorCode, err := a.storage.Get2FACode(r.Context(), user.ID, req.Code, "enable")
	if err != nil || twoFactorCode == nil {
		writeJSON(w, http.StatusBadRequest, VerifyEnable2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid or expired code"})
		return
	}

	if twoFactorCode.CodeType != "enable" {
		writeJSON(w, http.StatusBadRequest, VerifyEnable2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid code type"})
		return
	}

	if time.Now().After(twoFactorCode.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, VerifyEnable2FAResponse{StatusCode: http.StatusBadRequest, Error: "Code expired"})
		return
	}

	// Enable 2FA and generate backup codes
	security, err := a.storage.GetUserSecurity(r.Context(), user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, VerifyEnable2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to get user security"})
		return
	}

	security.TwoFactorEnabled = true
	now := time.Now()
	security.TwoFactorVerifiedAt = &now

	if err := a.storage.UpdateUserSecurity(r.Context(), security); err != nil {
		slog.Error("Failed to update user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, VerifyEnable2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user security"})
		return
	}

	if err := a.storage.Use2FACode(r.Context(), user.ID, req.Code); err != nil {
		slog.Error("Failed to mark 2FA code as used", "error", err)
	}

	// Generate backup codes
	backupCodes, err := a.generateBackupCodes(user.ID)
	if err != nil {
		slog.Error("Failed to generate backup codes", "error", err)
		writeJSON(w, http.StatusInternalServerError, VerifyEnable2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to generate backup codes"})
		return
	}

	codeStrs := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		codeStrs[i] = code.Code
	}

	a.logSecurityEvent(&user.ID, "2fa_enabled", "2FA enabled successfully",
		extractIP(r), r.Header.Get("User-Agent"), true)

	writeJSON(w, http.StatusOK, VerifyEnable2FAResponse{StatusCode: http.StatusOK, BackupCodes: codeStrs,
		Message: "2FA enabled successfully. Save these backup codes securely."})
	return
}

// Disable2FAHandler disables 2FA
func (a *AuthService) Disable2FAHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, Disable2FAResponse{StatusCode: http.StatusUnauthorized, Error: "User not authenticated"})
		return
	}

	var req Disable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Disable2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, Disable2FAResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, Disable2FAResponse{StatusCode: http.StatusUnauthorized, Error: "Invalid password"})
		return
	}

	// Disable 2FA
	security, err := a.storage.GetUserSecurity(r.Context(), user.ID)
	if err != nil {
		slog.Error("Failed to get user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, Disable2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to get user security"})
		return
	}

	security.TwoFactorEnabled = false
	security.TwoFactorSecret = ""
	security.TwoFactorBackupCodes = ""
	security.TwoFactorVerifiedAt = nil

	if err := a.storage.UpdateUserSecurity(r.Context(), security); err != nil {
		slog.Error("Failed to update user security", "error", err)
		writeJSON(w, http.StatusInternalServerError, Disable2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to update user security"})
		return
	}

	a.logSecurityEvent(&user.ID, "2fa_disabled", "2FA disabled",
		extractIP(r), r.Header.Get("User-Agent"), true)

	writeJSON(w, http.StatusOK, Disable2FAResponse{StatusCode: http.StatusOK, Message: "2FA disabled successfully"})
	return
}

// VerifyLogin2FAHandler verifies 2FA during login
func (a *AuthService) VerifyLogin2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyLogin2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, VerifyLogin2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, VerifyLogin2FAResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	if a.emailService == nil {
		writeJSON(w, http.StatusInternalServerError, VerifyLogin2FAResponse{StatusCode: http.StatusInternalServerError, Error: "Email service not configured"})
		return
	}

	code := req.Code
	ip := extractIP(r)
	userAgent := r.UserAgent()

	// Check if it's a backup code
	if len(code) > 10 {
		// For backup codes, we need the user ID from the code
		backupCode, err := a.storage.GetBackupCodeByCode(r.Context(), code)
		if err != nil || backupCode == nil {
			writeJSON(w, http.StatusBadRequest, VerifyLogin2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid backup code"})
			return
		}

		if err := a.storage.Use2FABackupCode(r.Context(), backupCode.UserID, code); err != nil {
			writeJSON(w, http.StatusBadRequest, VerifyLogin2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid backup code"})
			return
		}

		user, err := a.storage.GetUserByID(r.Context(), backupCode.UserID)
		if err != nil || user == nil {
			writeJSON(w, http.StatusInternalServerError, VerifyLogin2FAResponse{StatusCode: http.StatusInternalServerError, Error: "User not found"})
			return
		}

		a.logSecurityEvent(&user.ID, "2fa_backup_code_used", "Backup code used for login", ip, userAgent, true)

		resp := a.createSessionAndResponse(r.Context(), user, ip, userAgent)
		writeJSON(w, resp.StatusCode, resp)
		return
	}

	// For regular 2FA codes, we need to find the user
	// This requires either storing the user ID with the code or using a temporary session
	// For now, let's assume the code is stored with the user ID
	twoFactorCode, err := a.storage.GetLatestPending2FACode(r.Context(), code, "login")
	if err != nil || twoFactorCode == nil {
		writeJSON(w, http.StatusBadRequest, VerifyLogin2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid or expired 2FA code"})
		return
	}

	if twoFactorCode.CodeType != "login" {
		writeJSON(w, http.StatusBadRequest, VerifyLogin2FAResponse{StatusCode: http.StatusBadRequest, Error: "Invalid code type"})
		return
	}

	if time.Now().After(twoFactorCode.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, VerifyLogin2FAResponse{StatusCode: http.StatusBadRequest, Error: "Code expired"})
		return
	}

	// Mark code as used
	if err := a.storage.Use2FACode(r.Context(), twoFactorCode.UserID, code); err != nil {
		slog.Error("Failed to mark 2FA code as used", "error", err)
	}

	user, err := a.storage.GetUserByID(r.Context(), twoFactorCode.UserID)
	if err != nil || user == nil {
		writeJSON(w, http.StatusInternalServerError, VerifyLogin2FAResponse{StatusCode: http.StatusInternalServerError, Error: "User not found"})
		return
	}

	if !user.IsActive || user.IsSuspended {
		writeJSON(w, http.StatusUnauthorized, VerifyLogin2FAResponse{StatusCode: http.StatusUnauthorized, Error: "Account is not active"})
		return
	}

	a.logSecurityEvent(&user.ID, "2fa_verified", "2FA verified successfully", ip, userAgent, true)

	resp := a.createSessionAndResponse(r.Context(), user, ip, userAgent)
	writeJSON(w, resp.StatusCode, resp)
	return
}

// createSessionAndResponse is a helper to create a session and return response
func (a *AuthService) createSessionAndResponse(ctx context.Context, user *User, ip, userAgent string) VerifyLogin2FAResponse {
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

	if err := a.storage.CreateSession(ctx, session); err != nil {
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
func (a *AuthService) GetBackupCodesHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, GetBackupCodesResponse{StatusCode: http.StatusUnauthorized, Error: "User not authenticated"})
		return
	}

	backupCodes, err := a.GetBackupCodes(user.ID)
	if err != nil {
		slog.Error("Failed to get backup codes", "error", err)
		writeJSON(w, http.StatusInternalServerError, GetBackupCodesResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to get backup codes"})
		return
	}

	codeStrs := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		codeStrs[i] = code.Code
	}

	writeJSON(w, http.StatusOK, GetBackupCodesResponse{StatusCode: http.StatusOK, Codes: codeStrs})
	return
}

// RegenerateBackupCodesHandler generates new backup codes and invalidates old ones
func (a *AuthService) RegenerateBackupCodesHandler(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, RegenerateBackupCodesResponse{StatusCode: http.StatusUnauthorized, Error: "User not authenticated"})
		return
	}

	// Verify password first
	var req RegenerateBackupCodesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, RegenerateBackupCodesResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, RegenerateBackupCodesResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	// Verify password
	if !checkPasswordHash(req.Password, user.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, RegenerateBackupCodesResponse{StatusCode: http.StatusUnauthorized, Error: "Invalid password"})
		return
	}

	// Regenerate backup codes
	backupCodes, err := a.RegenerateBackupCodes(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, RegenerateBackupCodesResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to regenerate backup codes"})
		return
	}

	codeStrs := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		codeStrs[i] = code.Code
	}

	writeJSON(w, http.StatusOK, RegenerateBackupCodesResponse{StatusCode: http.StatusOK, Codes: codeStrs,
		Message: "Backup codes regenerated. Save them securely."})
	return
}

// RefreshTokenHandler exchanges refresh token for new session token
func (a *AuthService) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, RefreshTokenResponse{StatusCode: http.StatusBadRequest, Error: "Invalid request format"})
		return
	}

	if err := a.validator.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, RefreshTokenResponse{StatusCode: http.StatusBadRequest, Error: formatValidationErrors(err)})
		return
	}

	refreshToken, err := a.storage.GetRefreshToken(r.Context(), req.RefreshToken)
	if err != nil || refreshToken == nil {
		writeJSON(w, http.StatusUnauthorized, RefreshTokenResponse{StatusCode: http.StatusUnauthorized, Error: "Invalid refresh token"})
		return
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		writeJSON(w, http.StatusUnauthorized, RefreshTokenResponse{StatusCode: http.StatusUnauthorized, Error: "Refresh token expired"})
		return
	}

	user, err := a.storage.GetUserByID(r.Context(), refreshToken.UserID)
	if err != nil || user == nil {
		writeJSON(w, http.StatusUnauthorized, RefreshTokenResponse{StatusCode: http.StatusUnauthorized, Error: "User not found"})
		return
	}

	if !user.IsActive || user.IsSuspended {
		writeJSON(w, http.StatusUnauthorized, RefreshTokenResponse{StatusCode: http.StatusUnauthorized, Error: "Account is not active"})
		return
	}

	sessionToken, err := GenerateSecureToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, RefreshTokenResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to generate session token"})
		return
	}

	// Create new session
	sessionToken, err = GenerateSecureToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, RefreshTokenResponse{StatusCode: http.StatusInternalServerError, Error: "Failed to generate session token"})
		return
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

	if err := a.storage.CreateSession(r.Context(), session); err != nil {
		writeJSON(w, http.StatusInternalServerError, RefreshTokenResponse{StatusCode: http.StatusInternalServerError, Error: "Session creation failed"})
		return
	}

	// Update refresh token with new session ID
	refreshToken.SessionID = session.ID
	now := time.Now()
	refreshToken.LastUsedAt = &now
	if err := a.storage.UpdateRefreshToken(r.Context(), refreshToken); err != nil {
		slog.Error("Failed to update refresh token", "error", err)
	}

	user.PasswordHash = ""

	writeJSON(w, http.StatusOK, RefreshTokenResponse{StatusCode: http.StatusOK, AccessToken: sessionToken,
		User: user})
	return
}
