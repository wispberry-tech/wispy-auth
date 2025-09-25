package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Request and Response Types

// SignUpResponse represents the response for user registration
type SignUpResponse struct {
	Token                     string `json:"token"`                       // Session token for authentication
	User                      *User  `json:"user"`                        // Created user information
	RequiresEmailVerification bool   `json:"requires_email_verification"` // Whether email verification is required
	StatusCode                int    `json:"-"`                           // HTTP status code (not serialized)
	Error                     string `json:"error,omitempty"`             // Error message if any
}

// SignInRequest represents a user login request
type SignInRequest struct {
	Email    string `json:"email"`    // User's email address
	Password string `json:"password"` // User's password (plaintext)
}

// SignInResponse represents the response for user authentication
type SignInResponse struct {
	Token                     string    `json:"token"`                       // Session token for authentication
	User                      *User     `json:"user"`                        // Authenticated user information
	SessionID                 string    `json:"session_id"`                  // Session identifier
	Requires2FA               bool      `json:"requires_2fa"`                // Whether two-factor authentication is required
	RequiresEmailVerification bool      `json:"requires_email_verification"` // Whether email verification is required
	SessionExpiresAt          time.Time `json:"session_expires_at"`          // When the session expires
	StatusCode                int       `json:"-"`                           // HTTP status code (not serialized)
	Error                     string    `json:"error,omitempty"`             // Error message if any
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

// ForgotPasswordRequest represents a password reset request
type ForgotPasswordRequest struct {
	Email string `json:"email"` // User's email address
}

// ForgotPasswordResponse represents the response for password reset initiation
type ForgotPasswordResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// ResetPasswordRequest represents a password reset confirmation request
type ResetPasswordRequest struct {
	Token       string `json:"token"`        // Password reset token
	NewPassword string `json:"new_password"` // New password (plaintext)
}

// ResetPasswordResponse represents the response for password reset completion
type ResetPasswordResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// EmailVerificationResponse represents the response for email verification operations
type EmailVerificationResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// VerifyEmailRequest represents an email verification request
type VerifyEmailRequest struct {
	Token string `json:"token"` // Email verification token
}

// SessionsResponse represents the response for user session listing
type SessionsResponse struct {
	Sessions   []*Session `json:"sessions"`        // List of user sessions
	StatusCode int        `json:"-"`               // HTTP status code (not serialized)
	Error      string     `json:"error,omitempty"` // Error message if any
}

// RevokeSessionResponse represents the response for session revocation operations
type RevokeSessionResponse struct {
	Message    string `json:"message"`         // Success message
	StatusCode int    `json:"-"`               // HTTP status code (not serialized)
	Error      string `json:"error,omitempty"` // Error message if any
}

// HTTP request types with validation
type SignUpRequestHTTP struct {
	Email        string `json:"email" validate:"required,email,max=255"`
	Password     string `json:"password" validate:"required,min=8,max=128"`
	Username     string `json:"username" validate:"omitempty,min=2,max=100"`
	FirstName    string `json:"first_name" validate:"omitempty,max=100"`
	LastName     string `json:"last_name" validate:"omitempty,max=100"`
	ReferralCode string `json:"referral_code" validate:"omitempty,max=50"`
}

type SignInRequestHTTP struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type ForgotPasswordRequestHTTP struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequestHTTP struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

type VerifyEmailRequestHTTP struct {
	Token string `json:"token" validate:"required"`
}

// SignUp processes user registration from HTTP request and returns a structured response.
// It parses and validates the request body, creates the user account, establishes a session,
// sends verification/welcome emails if configured, and returns the result.
//
// Usage:
//
//	r.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.SignUp(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Request body should contain: {"email": "...", "password": "...", "name": "..."}
// Returns SignUpResponse with token, user data, verification status, and any errors
func (a *AuthService) SignUpHandler(r *http.Request) SignUpResponse {
	var req SignUpRequestHTTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Invalid request body in signup", "error", err, "remote_addr", r.RemoteAddr)
		return SignUpResponse{
			Error:      fmt.Sprintf("Invalid request body: %v", err),
			StatusCode: http.StatusBadRequest,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		slog.Warn("Validation failed in signup", "error", err, "email", req.Email, "remote_addr", r.RemoteAddr)
		return SignUpResponse{
			Error:      fmt.Sprintf("Validation failed: %s", formatValidationErrors(err)),
			StatusCode: http.StatusBadRequest,
		}
	}

	// Extract client information
	ip := extractIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Create user account
	username := req.Username
	if username == "" {
		// Auto-generate username from email if not provided
		username = req.Email[:strings.Index(req.Email, "@")]
	}

	signUpReq := SignUpRequest{
		Email:        req.Email,
		Password:     req.Password,
		Username:     username,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		ReferralCode: req.ReferralCode,
	}
	user, err := a.SignUpWithTenant(signUpReq, 0)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			slog.Warn("User already exists during signup", "email", req.Email, "remote_addr", r.RemoteAddr)
			return SignUpResponse{
				StatusCode: 409,
				Error:      "User with this email already exists",
			}
		} else if strings.Contains(err.Error(), "password must") || strings.Contains(err.Error(), "invalid email") {
			slog.Warn("Password/email validation failed", "error", err, "email", req.Email)
			return SignUpResponse{
				StatusCode: 400,
				Error:      fmt.Sprintf("Validation error: %s", err.Error()),
			}
		} else {
			slog.Error("Failed to create user during signup", "error", err, "email", req.Email, "remote_addr", r.RemoteAddr)
			return SignUpResponse{
				StatusCode: 500,
				Error:      "An internal error occurred during account creation. Please try again later.",
			}
		}
	}

	// Build response - only create session if email verification is not required or already verified
	response := SignUpResponse{
		User:                      user,
		RequiresEmailVerification: a.securityConfig.RequireEmailVerification && !user.EmailVerified,
		StatusCode:                200,
	}

	// Only create session if email verification is not required or email is already verified
	if !response.RequiresEmailVerification {
		session, err := a.CreateSession(user.ID, ip, userAgent, "")
		if err != nil {
			slog.Error("Failed to create session after signup", "error", err, "user_id", user.ID, "email", user.Email, "remote_addr", r.RemoteAddr)
			return SignUpResponse{
				StatusCode: 500,
				Error:      "An internal error occurred during session creation. Please try again later.",
			}
		}
		response.Token = session.Token
	}

	// Send verification email if needed
	if response.RequiresEmailVerification && a.emailService != nil {
		if userSecurity, err := a.storage.GetUserSecurity(response.User.ID); err == nil && userSecurity.VerificationToken != "" {
			go func() {
				if err := a.emailService.SendVerificationEmail(response.User.Email, userSecurity.VerificationToken); err != nil {
					slog.Error("Failed to send verification email", "error", err, "user_id", response.User.ID, "email", response.User.Email)
				}
			}()
		}
	}

	// Send welcome email
	if a.emailService != nil {
		displayName := ""
		if response.User.FirstName != "" {
			if response.User.LastName != "" {
				displayName = response.User.FirstName + " " + response.User.LastName
			} else {
				displayName = response.User.FirstName
			}
		} else if response.User.Username != "" {
			displayName = response.User.Username
		} else {
			displayName = response.User.Email
		}
		go func() {
			if err := a.emailService.SendWelcomeEmail(response.User.Email, displayName); err != nil {
				slog.Error("Failed to send welcome email", "error", err, "user_id", response.User.ID, "email", response.User.Email)
			}
		}()
	}

	return response
}

// SignInHandler processes user authentication from HTTP request and returns a structured response.
// It parses the request body, validates credentials, checks account status (locked, suspended),
// creates a new session, and returns authentication tokens with session details.
//
// Usage:
//
//	r.Post("/signin", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.SignInHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Request body should contain: {"email": "...", "password": "..."}
// Returns SignInResponse with token, user data, session info, 2FA status, and any errors
func (a *AuthService) SignInHandler(r *http.Request) SignInResponse {
	var req SignInRequestHTTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Invalid request body in signin", "error", err, "remote_addr", r.RemoteAddr)
		return SignInResponse{
			Error:      fmt.Sprintf("Invalid request body: %v", err),
			StatusCode: http.StatusBadRequest,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		slog.Warn("Validation failed in signin", "error", err, "email", req.Email, "remote_addr", r.RemoteAddr)
		return SignInResponse{
			Error:      fmt.Sprintf("Validation failed: %s", formatValidationErrors(err)),
			StatusCode: http.StatusBadRequest,
		}
	}

	// Extract client information
	ip := extractIP(r)
	userAgent := r.Header.Get("User-Agent")

	user, err := a.SignInWithContext(req.Email, req.Password, ip, userAgent, "")
	if err != nil {
		if errors.Is(err, ErrEmailNotVerified) {
			// For unverified email, we return user info but no token
			// Use 403 Forbidden as credentials are valid but access is restricted due to unverified email
			user, getUserErr := a.storage.GetUserByEmailAnyProvider(req.Email)
			if getUserErr == nil {
				slog.Info("Login attempt with unverified email", "email", req.Email, "user_id", user.ID)
				return SignInResponse{
					User:                      user,
					RequiresEmailVerification: true,
					StatusCode:                403,
					Error:                     "Email verification required. Please check your email and click the verification link.",
				}
			} else {
				slog.Info("Login attempt with unverified email", "email", req.Email)
				return SignInResponse{
					RequiresEmailVerification: true,
					StatusCode:                403,
					Error:                     "Email verification required. Please check your email and click the verification link.",
				}
			}
		} else if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrInvalidCredentials) {
			slog.Warn("Invalid credentials attempt", "email", req.Email, "remote_addr", r.RemoteAddr)
			return SignInResponse{
				StatusCode: 401,
				Error:      "Invalid email or password",
			}
		} else if strings.Contains(err.Error(), "account is locked") {
			slog.Warn("Login attempt on locked account", "email", req.Email, "error", err)
			return SignInResponse{
				StatusCode: 423,
				Error:      fmt.Sprintf("Account locked: %s", err.Error()),
			}
		} else if strings.Contains(err.Error(), "account is suspended") ||
			strings.Contains(err.Error(), "account is inactive") {
			slog.Warn("Login attempt on suspended/inactive account", "email", req.Email, "error", err)
			return SignInResponse{
				StatusCode: 403,
				Error:      fmt.Sprintf("Account access denied: %s", err.Error()),
			}
		} else {
			slog.Error("Internal error during signin", "error", err, "email", req.Email, "remote_addr", r.RemoteAddr)
			return SignInResponse{
				StatusCode: 500,
				Error:      "An internal authentication error occurred. Please try again later.",
			}
		}
	}

	// Create session for the authenticated user
	session, err := a.CreateSession(user.ID, ip, userAgent, "")
	if err != nil {
		slog.Error("Failed to create session after signin", "error", err, "user_id", user.ID, "email", user.Email, "remote_addr", r.RemoteAddr)
		return SignInResponse{
			StatusCode: 500,
			Error:      "An internal error occurred during session creation. Please try again later.",
		}
	}

	return SignInResponse{
		Token:            session.Token,
		User:             user,
		SessionID:        session.ID,
		Requires2FA:      session.RequiresTwoFactor && !session.TwoFactorVerified,
		SessionExpiresAt: session.ExpiresAt,
		StatusCode:       200,
	}
}

// ValidateHandler validates a session token from HTTP request and returns user information.
// It extracts the token from Authorization header, removes Bearer prefix if present,
// and validates the user session to ensure the token is still valid.
//
// Usage:
//
//	r.Get("/validate", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.ValidateHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Returns ValidateResponse with user data and any validation errors
func (a *AuthService) ValidateHandler(r *http.Request) ValidateResponse {
	token := extractTokenFromRequest(r)
	if token == "" {
		slog.Error("Missing authorization header - authentication failed",
			"remote_addr", r.RemoteAddr,
			"method", r.Method,
			"url", r.URL.String(),
			"user_agent", r.UserAgent(),
			"referer", r.Referer())
		return ValidateResponse{
			StatusCode: 401,
			Error:      "Authorization header required. Please provide a Bearer token.",
		}
	}

	// Debug: Log the full token being validated
	slog.Debug("Validating session token", "token_prefix", token[:min(8, len(token))], "token_length", len(token), "remote_addr", r.RemoteAddr)

	// Get session from token
	session, err := a.storage.GetSession(token)
	if err != nil {
		slog.Warn("Session validation failed", "error", err, "token_prefix", token[:min(8, len(token))], "token_length", len(token), "remote_addr", r.RemoteAddr)
		return ValidateResponse{
			StatusCode: 401,
			Error:      "Invalid or expired session",
		}
	}

	// Check if session is valid and active
	if !session.IsActive || session.ExpiresAt.Before(time.Now()) {
		slog.Warn("Session expired or inactive", "session_id", session.ID, "remote_addr", r.RemoteAddr)
		return ValidateResponse{
			StatusCode: 401,
			Error:      "Session expired or inactive",
		}
	}

	// Get user from session
	user, err := a.storage.GetUserByID(session.UserID)
	if err != nil {
		slog.Error("User not found for valid session - data inconsistency", "error", err, "user_id", session.UserID, "session_id", session.ID, "remote_addr", r.RemoteAddr)
		return ValidateResponse{
			StatusCode: 401,
			Error:      "Session validation failed",
		}
	}

	// Update session activity
	session.LastActivity = time.Now()
	if updateErr := a.storage.UpdateSession(session); updateErr != nil {
		slog.Error("Failed to update session activity", "error", updateErr, "session_id", session.ID, "user_id", session.UserID)
	}

	return ValidateResponse{
		User:       user,
		StatusCode: 200,
	}
}

// ForgotPasswordHandler initiates password reset process from HTTP request with email enumeration protection.
// It always returns success regardless of whether the email exists to prevent
// information disclosure attacks while still processing valid reset requests.
//
// Usage:
//
//	r.Post("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.ForgotPasswordHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Request body should contain: {"email": "..."}
// Returns ForgotPasswordResponse with success message (always success for security)
func (a *AuthService) ForgotPasswordHandler(r *http.Request) ForgotPasswordResponse {
	var req ForgotPasswordRequestHTTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Invalid request body in forgot password", "error", err, "remote_addr", r.RemoteAddr)
		return ForgotPasswordResponse{
			Error:      fmt.Sprintf("Invalid request body: %v", err),
			StatusCode: http.StatusBadRequest,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		slog.Warn("Validation failed in forgot password", "error", err, "email", req.Email, "remote_addr", r.RemoteAddr)
		return ForgotPasswordResponse{
			Error:      fmt.Sprintf("Validation failed: %s", formatValidationErrors(err)),
			StatusCode: http.StatusBadRequest,
		}
	}

	// Process request and send email if configured
	err := a.InitiatePasswordReset(req.Email)

	// Send reset email if successful and user exists
	if err == nil && a.emailService != nil {
		user, getUserErr := a.storage.GetUserByEmailAnyProvider(req.Email)
		if getUserErr == nil && user != nil {
			if userSecurity, secErr := a.storage.GetUserSecurity(user.ID); secErr == nil && userSecurity.PasswordResetToken != "" {
				go func() {
					if err := a.emailService.SendPasswordResetEmail(user.Email, userSecurity.PasswordResetToken); err != nil {
						slog.Error("Failed to send password reset email", "error", err, "user_id", user.ID, "email", user.Email)
					}
				}()
			}
		}
	}

	// Always return success to prevent email enumeration
	return ForgotPasswordResponse{
		Message:    "If your email is registered, you will receive a password reset link.",
		StatusCode: http.StatusOK,
	}
}

// ResetPasswordHandler completes password reset from HTTP request using a valid token.
// It validates the reset token, checks password strength requirements,
// and updates the user's password if all validations pass.
//
// Usage:
//
//	r.Post("/reset-password", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.ResetPasswordHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Request body should contain: {"token": "...", "new_password": "..."}
// Returns ResetPasswordResponse with success message and any validation errors
func (a *AuthService) ResetPasswordHandler(r *http.Request) ResetPasswordResponse {
	var req ResetPasswordRequestHTTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Invalid request body in reset password", "error", err, "remote_addr", r.RemoteAddr)
		return ResetPasswordResponse{
			Error:      fmt.Sprintf("Invalid request body: %v", err),
			StatusCode: http.StatusBadRequest,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		slog.Warn("Validation failed in reset password", "error", err, "remote_addr", r.RemoteAddr)
		return ResetPasswordResponse{
			Error:      fmt.Sprintf("Validation failed: %s", formatValidationErrors(err)),
			StatusCode: http.StatusBadRequest,
		}
	}

	if err := a.ResetPassword(req.Token, req.NewPassword); err != nil {
		if strings.Contains(err.Error(), "invalid reset token") || strings.Contains(err.Error(), "expired") {
			slog.Warn("Invalid or expired reset token used", "error", err, "remote_addr", r.RemoteAddr)
			return ResetPasswordResponse{
				StatusCode: 400,
				Error:      fmt.Sprintf("Reset token error: %s", err.Error()),
			}
		} else if strings.Contains(err.Error(), "password must") {
			slog.Info("Password validation failed during reset", "error", err)
			return ResetPasswordResponse{
				StatusCode: 400,
				Error:      fmt.Sprintf("Password requirements not met: %s", err.Error()),
			}
		} else {
			slog.Error("Failed to reset password", "error", err, "remote_addr", r.RemoteAddr)
			return ResetPasswordResponse{
				StatusCode: 500,
				Error:      "An internal error occurred during password reset. Please try again later.",
			}
		}
	}

	return ResetPasswordResponse{
		Message:    "Password reset successfully",
		StatusCode: 200,
	}
}

// VerifyEmailHandler processes email verification from HTTP request using a verification token.
// It validates the verification token and marks the user's email as verified
// if the token is valid and not expired.
//
// Usage:
//
//	r.Post("/verify-email", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.VerifyEmailHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Request body should contain: {"token": "..."}
// Returns EmailVerificationResponse with success message and any validation errors
func (a *AuthService) VerifyEmailHandler(r *http.Request) EmailVerificationResponse {
	var req VerifyEmailRequestHTTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("Invalid request body in verify email", "error", err, "remote_addr", r.RemoteAddr)
		return EmailVerificationResponse{
			Error:      fmt.Sprintf("Invalid request body: %v", err),
			StatusCode: http.StatusBadRequest,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		slog.Warn("Validation failed in verify email", "error", err, "remote_addr", r.RemoteAddr)
		return EmailVerificationResponse{
			Error:      fmt.Sprintf("Validation failed: %s", formatValidationErrors(err)),
			StatusCode: http.StatusBadRequest,
		}
	}

	if err := a.VerifyEmail(req.Token); err != nil {
		slog.Warn("Email verification failed", "error", err, "remote_addr", r.RemoteAddr)
		return EmailVerificationResponse{
			StatusCode: 400,
			Error:      fmt.Sprintf("Email verification failed: %s", err.Error()),
		}
	}

	return EmailVerificationResponse{
		Message:    "Email verified successfully",
		StatusCode: 200,
	}
}

// ResendVerificationHandler resends email verification for authenticated users from HTTP request.
// It validates the user's session token, checks if email is already verified,
// and triggers a new verification email if needed.
//
// Usage:
//
//	r.Post("/resend-verification", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.ResendVerificationHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Returns EmailVerificationResponse with success message and any errors
func (a *AuthService) ResendVerificationHandler(r *http.Request) EmailVerificationResponse {
	token := extractTokenFromRequest(r)
	if token == "" {
		return EmailVerificationResponse{
			StatusCode: 401,
			Error:      "Authorization header required",
		}
	}

	// Get session from token
	session, err := a.storage.GetSession(token)
	if err != nil {
		return EmailVerificationResponse{
			StatusCode: 401,
			Error:      "Invalid token",
		}
	}

	if err := a.SendEmailVerification(session.UserID); err != nil {
		if strings.Contains(err.Error(), "already verified") {
			return EmailVerificationResponse{
				StatusCode: 400,
				Error:      err.Error(),
			}
		} else {
			return EmailVerificationResponse{
				StatusCode: 500,
				Error:      "Failed to send verification email",
			}
		}
	}

	// Send verification email if configured
	if a.emailService != nil {
		user, ok := GetUserFromContext(r)
		if !ok {
			// Get user from session if not in context
			if user, err := a.storage.GetUserByID(session.UserID); err == nil {
				if userSecurity, secErr := a.storage.GetUserSecurity(user.ID); secErr == nil && userSecurity.VerificationToken != "" {
					go func() {
						if err := a.emailService.SendVerificationEmail(user.Email, userSecurity.VerificationToken); err != nil {
							slog.Error("Failed to send verification email", "error", err, "user_id", user.ID, "email", user.Email)
						}
					}()
				}
			}
		} else {
			if userSecurity, secErr := a.storage.GetUserSecurity(user.ID); secErr == nil && userSecurity.VerificationToken != "" {
				go func() {
					if err := a.emailService.SendVerificationEmail(user.Email, userSecurity.VerificationToken); err != nil {
						slog.Error("Failed to send verification email", "error", err, "user_id", user.ID, "email", user.Email)
					}
				}()
			}
		}
	}

	return EmailVerificationResponse{
		Message:    "Verification email sent",
		StatusCode: 200,
	}
}

// GetSessionsHandler retrieves all active sessions for the authenticated user from HTTP request.
// It validates the user's token, extracts the user ID from the session,
// and returns a list of all active sessions with device and location information.
//
// Usage:
//
//	r.Get("/sessions", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.GetSessionsHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Returns SessionsResponse with list of sessions and any errors
func (a *AuthService) GetSessionsHandler(r *http.Request) SessionsResponse {
	token := extractTokenFromRequest(r)
	if token == "" {
		return SessionsResponse{
			StatusCode: 401,
			Error:      "Authorization header required",
		}
	}

	// Get session from token
	session, err := a.storage.GetSession(token)
	if err != nil {
		return SessionsResponse{
			StatusCode: 401,
			Error:      "Invalid token",
		}
	}

	sessions, err := a.GetUserSessions(session.UserID)
	if err != nil {
		slog.Error("Failed to fetch user sessions", "error", err, "user_id", session.UserID, "session_id", session.ID)
		return SessionsResponse{
			StatusCode: 500,
			Error:      "Failed to fetch sessions",
		}
	}

	return SessionsResponse{
		Sessions:   sessions,
		StatusCode: 200,
	}
}

// RevokeSessionHandler revokes a specific user session by ID from HTTP request.
// It terminates the specified session, making the associated token invalid.
// This is useful for logging out from specific devices or browsers.
//
// Usage:
//
//	r.Delete("/sessions/{sessionID}", func(w http.ResponseWriter, r *http.Request) {
//	    sessionID := chi.URLParam(r, "sessionID")
//	    result := authService.RevokeSessionHandler(r, sessionID)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Returns RevokeSessionResponse with success message and any errors
func (a *AuthService) RevokeSessionHandler(r *http.Request, sessionID string) RevokeSessionResponse {
	if sessionID == "" {
		return RevokeSessionResponse{
			StatusCode: 400,
			Error:      "Session ID is required",
		}
	}

	if err := a.RevokeSession(sessionID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return RevokeSessionResponse{
				StatusCode: 404,
				Error:      "Session not found",
			}
		} else {
			slog.Error("Failed to revoke session", "error", err, "session_id", sessionID, "remote_addr", r.RemoteAddr)
			return RevokeSessionResponse{
				StatusCode: 500,
				Error:      "Failed to revoke session",
			}
		}
	}

	return RevokeSessionResponse{
		Message:    "Session revoked successfully",
		StatusCode: 200,
	}
}

// RevokeAllSessionsHandler revokes all sessions for the authenticated user from HTTP request.
// It validates the user's token, extracts the user ID, and terminates all
// active sessions for that user. This is useful for "log out everywhere" functionality.
//
// Usage:
//
//	r.Delete("/sessions", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.RevokeAllSessionsHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Returns RevokeSessionResponse with success message and any errors
func (a *AuthService) RevokeAllSessionsHandler(r *http.Request) RevokeSessionResponse {
	token := extractTokenFromRequest(r)
	if token == "" {
		return RevokeSessionResponse{
			StatusCode: 401,
			Error:      "Authorization header required",
		}
	}

	// Get session from token
	session, err := a.storage.GetSession(token)
	if err != nil {
		return RevokeSessionResponse{
			StatusCode: 401,
			Error:      "Invalid token",
		}
	}

	if err := a.RevokeAllUserSessions(session.UserID); err != nil {
		slog.Error("Failed to revoke all user sessions", "error", err, "user_id", session.UserID, "remote_addr", r.RemoteAddr)
		return RevokeSessionResponse{
			StatusCode: 500,
			Error:      "Failed to revoke sessions",
		}
	}

	return RevokeSessionResponse{
		Message:    "All sessions revoked successfully",
		StatusCode: 200,
	}
}

// OAuthHandler initiates OAuth flow by generating authorization URL from HTTP request.
// It creates a state parameter for security and returns the OAuth provider's
// authorization URL for redirecting the user to complete authentication.
//
// Usage:
//
//	r.Get("/oauth/{provider}", func(w http.ResponseWriter, r *http.Request) {
//	    provider := chi.URLParam(r, "provider")
//	    result := authService.OAuthHandler(r, provider)
//	    if result.URL != "" {
//	        http.Redirect(w, r, result.URL, http.StatusTemporaryRedirect)
//	    } else {
//	        w.WriteHeader(result.StatusCode)
//	        json.NewEncoder(w).Encode(result)
//	    }
//	})
//
// Returns OAuthResponse with authorization URL and redirect status
func (a *AuthService) OAuthHandler(w http.ResponseWriter, r *http.Request, provider string) OAuthResponse {
	if provider == "" {
		slog.Warn("Missing provider parameter in OAuth", "remote_addr", r.RemoteAddr)
		return OAuthResponse{
			StatusCode: 400,
			Error:      "OAuth provider parameter is required",
		}
	}

	url, csrfToken, err := a.GetOAuthURL(provider, r)
	if err != nil {
		slog.Warn("Invalid OAuth provider requested", "provider", provider, "error", err, "remote_addr", r.RemoteAddr)
		return OAuthResponse{
			StatusCode: 400,
			Error:      fmt.Sprintf("Invalid OAuth provider '%s': %s", provider, err.Error()),
		}
	}

	// Set CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "_csrf",
		Value:    csrfToken,
		HttpOnly: true,
		Secure:   !a.developmentMode, // Only secure in production
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   900, // 15 minutes
	})

	return OAuthResponse{
		URL:        url,
		StatusCode: 307, // Temporary Redirect
	}
}

// OAuthCallbackHandler processes OAuth callback from HTTP request with authorization code.
// It exchanges the authorization code for user information, creates or updates
// the user account, generates authentication tokens, and determines if the user is new.
//
// Usage:
//
//	r.Get("/oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
//	    provider := chi.URLParam(r, "provider")
//	    code := r.URL.Query().Get("code")
//	    result := authService.OAuthCallbackHandler(r, provider, code)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Returns OAuthResponse with token, user data, new user status, and any errors
func (a *AuthService) OAuthCallbackHandler(r *http.Request, provider, code, state string) OAuthResponse {
	if provider == "" || code == "" || state == "" {
		slog.Warn("Missing OAuth callback parameters", "provider", provider, "has_code", code != "", "has_state", state != "", "remote_addr", r.RemoteAddr)
		return OAuthResponse{
			StatusCode: 400,
			Error:      "OAuth callback missing required parameters: provider, code, and state are all required",
		}
	}

	// Get CSRF token from cookie
	csrfCookie, err := r.Cookie("_csrf")
	if err != nil {
		slog.Warn("CSRF cookie missing in OAuth callback", "error", err, "provider", provider, "remote_addr", r.RemoteAddr)
		return OAuthResponse{
			StatusCode: 400,
			Error:      fmt.Sprintf("CSRF cookie not found: %s. Please restart the OAuth flow.", err.Error()),
		}
	}

	// Validate state and CSRF token
	if err := a.ValidateOAuthState(state, csrfCookie.Value); err != nil {
		slog.Warn("OAuth state validation failed", "error", err, "provider", provider, "remote_addr", r.RemoteAddr)
		return OAuthResponse{
			StatusCode: 400,
			Error:      fmt.Sprintf("OAuth state validation failed: %s. Please restart the OAuth flow.", err.Error()),
		}
	}

	user, err := a.HandleOAuthCallback(provider, code)
	if err != nil {
		slog.Error("OAuth callback processing failed", "error", err, "provider", provider, "remote_addr", r.RemoteAddr)
		return OAuthResponse{
			StatusCode: 500,
			Error:      "OAuth authentication failed. Please try again later.",
		}
	}

	// Check if user already exists to determine if they're new
	// We'll consider a user new if they haven't logged in before or recently created
	isNewUser := true
	if userSecurity, err := a.storage.GetUserSecurity(user.ID); err == nil && userSecurity.LastLoginAt != nil {
		isNewUser = user.CreatedAt.After(userSecurity.LastLoginAt.Add(-time.Minute))
	}

	// Create session for the OAuth user
	ip := extractIP(r)
	userAgent := r.Header.Get("User-Agent")
	session, err := a.CreateSession(user.ID, ip, userAgent, "")
	if err != nil {
		slog.Error("Failed to create session after OAuth", "error", err, "user_id", user.ID, "provider", provider, "remote_addr", r.RemoteAddr)
		return OAuthResponse{
			StatusCode: 500,
			Error:      "Failed to create session. Please try again later.",
		}
	}

	// Send welcome email for new users
	if isNewUser && a.emailService != nil {
		displayName := ""
		if user.FirstName != "" {
			if user.LastName != "" {
				displayName = user.FirstName + " " + user.LastName
			} else {
				displayName = user.FirstName
			}
		} else if user.Username != "" {
			displayName = user.Username
		} else {
			displayName = user.Email
		}
		go func() {
			if err := a.emailService.SendWelcomeEmail(user.Email, displayName); err != nil {
				slog.Error("Failed to send welcome email", "error", err, "user_id", user.ID, "email", user.Email)
			}
		}()
	}

	return OAuthResponse{
		Token:      session.Token,
		User:       user,
		IsNewUser:  isNewUser,
		StatusCode: 200,
	}
}

// GetProvidersHandler returns the list of configured OAuth providers from HTTP request.
//
// Usage:
//
//	r.Get("/providers", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.GetProvidersHandler(r)
//	    w.WriteHeader(200)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Returns map with available providers list
func (a *AuthService) GetProvidersHandler(r *http.Request) map[string][]string {
	providers := a.GetAvailableProviders()
	return map[string][]string{"providers": providers}
}

// Referral Management Handlers

// GenerateReferralCodeRequestHTTP represents HTTP request for generating a referral code
type GenerateReferralCodeRequestHTTP struct {
	TenantID uint `json:"tenant_id" validate:"required"`
	MaxUses  int  `json:"max_uses" validate:"omitempty,min=1,max=1000"`
}

// MyReferralCodesResponse represents the response for user's referral codes
type MyReferralCodesResponse struct {
	ReferralCodes []*ReferralCode `json:"referral_codes"`
	StatusCode    int             `json:"-"`
	Error         string          `json:"error,omitempty"`
}

// MyReferralsResponse represents the response for user's referrals
type MyReferralsResponse struct {
	Referrals  []*UserReferral `json:"referrals"`
	StatusCode int             `json:"-"`
	Error      string          `json:"error,omitempty"`
}

// ReferralStatsResponse represents the response for referral statistics
type ReferralStatsResponse struct {
	TotalReferred   int    `json:"total_referred"`
	ActiveReferrals int    `json:"active_referrals"`
	StatusCode      int    `json:"-"`
	Error           string `json:"error,omitempty"`
}

// GenerateReferralCodeHandler generates a new referral code for the authenticated user.
//
// Usage:
//
//	r.Post("/referrals/generate", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.GenerateReferralCodeHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Request body: {"tenant_id": 1, "max_uses": 5}
// Returns GenerateReferralCodeResponse with the generated code
func (a *AuthService) GenerateReferralCodeHandler(r *http.Request) GenerateReferralCodeResponse {
	// Authenticate user
	token := extractTokenFromRequest(r)
	if token == "" {
		return GenerateReferralCodeResponse{
			StatusCode: 401,
			Error:      "Authorization header required",
		}
	}

	session, err := a.storage.GetSession(token)
	if err != nil {
		return GenerateReferralCodeResponse{
			StatusCode: 401,
			Error:      "Invalid session token",
		}
	}

	// Parse request
	var req GenerateReferralCodeRequestHTTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return GenerateReferralCodeResponse{
			StatusCode: 400,
			Error:      fmt.Sprintf("Invalid request body: %v", err),
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return GenerateReferralCodeResponse{
			StatusCode: 400,
			Error:      fmt.Sprintf("Validation failed: %s", formatValidationErrors(err)),
		}
	}

	// Generate referral code
	maxUses := req.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}

	generateReq := GenerateReferralCodeRequest{
		UserID:   session.UserID,
		TenantID: req.TenantID,
		MaxUses:  maxUses,
	}

	return a.GenerateReferralCode(generateReq)
}

// GetMyReferralCodesHandler returns all referral codes generated by the authenticated user.
//
// Usage:
//
//	r.Get("/referrals/my-codes", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.GetMyReferralCodesHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Returns MyReferralCodesResponse with list of referral codes
func (a *AuthService) GetMyReferralCodesHandler(r *http.Request) MyReferralCodesResponse {
	// Authenticate user
	token := extractTokenFromRequest(r)
	if token == "" {
		return MyReferralCodesResponse{
			StatusCode: 401,
			Error:      "Authorization header required",
		}
	}

	session, err := a.storage.GetSession(token)
	if err != nil {
		return MyReferralCodesResponse{
			StatusCode: 401,
			Error:      "Invalid session token",
		}
	}

	// Get user's referral codes
	codes, err := a.GetMyReferralCodes(session.UserID)
	if err != nil {
		slog.Error("Failed to get user referral codes", "user_id", session.UserID, "error", err)
		return MyReferralCodesResponse{
			StatusCode: 500,
			Error:      "Failed to retrieve referral codes",
		}
	}

	return MyReferralCodesResponse{
		ReferralCodes: codes,
		StatusCode:    200,
	}
}

// GetMyReferralsHandler returns all users referred by the authenticated user.
//
// Usage:
//
//	r.Get("/referrals/my-referrals", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.GetMyReferralsHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Returns MyReferralsResponse with list of referrals
func (a *AuthService) GetMyReferralsHandler(r *http.Request) MyReferralsResponse {
	// Authenticate user
	token := extractTokenFromRequest(r)
	if token == "" {
		return MyReferralsResponse{
			StatusCode: 401,
			Error:      "Authorization header required",
		}
	}

	session, err := a.storage.GetSession(token)
	if err != nil {
		return MyReferralsResponse{
			StatusCode: 401,
			Error:      "Invalid session token",
		}
	}

	// Get user's referrals
	referrals, err := a.GetMyReferrals(session.UserID)
	if err != nil {
		slog.Error("Failed to get user referrals", "user_id", session.UserID, "error", err)
		return MyReferralsResponse{
			StatusCode: 500,
			Error:      "Failed to retrieve referrals",
		}
	}

	return MyReferralsResponse{
		Referrals:  referrals,
		StatusCode: 200,
	}
}

// GetReferralStatsHandler returns referral statistics for the authenticated user.
//
// Usage:
//
//	r.Get("/referrals/stats", func(w http.ResponseWriter, r *http.Request) {
//	    result := authService.GetReferralStatsHandler(r)
//	    w.WriteHeader(result.StatusCode)
//	    json.NewEncoder(w).Encode(result)
//	})
//
// Expects Authorization header: "Bearer <session-token>"
// Returns ReferralStatsResponse with referral statistics
func (a *AuthService) GetReferralStatsHandler(r *http.Request) ReferralStatsResponse {
	// Authenticate user
	token := extractTokenFromRequest(r)
	if token == "" {
		return ReferralStatsResponse{
			StatusCode: 401,
			Error:      "Authorization header required",
		}
	}

	session, err := a.storage.GetSession(token)
	if err != nil {
		return ReferralStatsResponse{
			StatusCode: 401,
			Error:      "Invalid session token",
		}
	}

	// Get referral statistics
	totalReferred, activeReferrals, err := a.GetReferralStats(session.UserID)
	if err != nil {
		slog.Error("Failed to get referral stats", "user_id", session.UserID, "error", err)
		return ReferralStatsResponse{
			StatusCode: 500,
			Error:      "Failed to retrieve referral statistics",
		}
	}

	return ReferralStatsResponse{
		TotalReferred:   totalReferred,
		ActiveReferrals: activeReferrals,
		StatusCode:      200,
	}
}

// ===== 2FA HANDLERS =====

// Enable2FARequest represents the request to enable 2FA
type Enable2FARequest struct {
	UserID uint `json:"user_id" validate:"required"`
}

// Enable2FAResponse represents the response from enabling 2FA
type Enable2FAResponse struct {
	BackupCodes []string `json:"backup_codes,omitempty"`
	Message     string   `json:"message"`
	Error       string   `json:"error,omitempty"`
	StatusCode  int      `json:"-"`
}

// Send2FACodeRequest represents the request to send a 2FA code
type Send2FACodeRequest struct {
	UserID uint `json:"user_id" validate:"required"`
}

// Send2FACodeResponse represents the response from sending 2FA code
type Send2FACodeResponse struct {
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
	StatusCode int    `json:"-"`
}

// Verify2FACodeRequest represents the request to verify a 2FA code
type Verify2FACodeRequest struct {
	UserID uint   `json:"user_id" validate:"required"`
	Code   string `json:"code" validate:"required"`
}

// Verify2FACodeResponse represents the response from verifying 2FA code
type Verify2FACodeResponse struct {
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
	StatusCode int    `json:"-"`
}

// Generate2FABackupCodesRequest represents the request to generate backup codes
type Generate2FABackupCodesRequest struct {
	UserID uint `json:"user_id" validate:"required"`
}

// Generate2FABackupCodesResponse represents the response with backup codes
type Generate2FABackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes,omitempty"`
	Message     string   `json:"message"`
	Error       string   `json:"error,omitempty"`
	StatusCode  int      `json:"-"`
}

// Disable2FARequest represents the request to disable 2FA
type Disable2FARequest struct {
	UserID uint `json:"user_id" validate:"required"`
}

// Disable2FAResponse represents the response from disabling 2FA
type Disable2FAResponse struct {
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
	StatusCode int    `json:"-"`
}

// Enable2FAHandler handles enabling 2FA for a user
func (a *AuthService) Enable2FAHandler(r *http.Request) Enable2FAResponse {
	var req Enable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Enable2FAResponse{
			Error:      "Invalid request format",
			StatusCode: 400,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return Enable2FAResponse{
			Error:      "Validation failed: " + err.Error(),
			StatusCode: 400,
		}
	}

	setup, err := a.Enable2FAForUser(req.UserID)
	if err != nil {
		slog.Error("Failed to enable 2FA", "error", err, "user_id", req.UserID)
		return Enable2FAResponse{
			Error:      err.Error(),
			StatusCode: 400,
		}
	}

	return Enable2FAResponse{
		BackupCodes: setup.BackupCodes,
		Message:     setup.Message,
		StatusCode:  200,
	}
}

// Send2FACodeHandler handles sending a 2FA code to a user
func (a *AuthService) Send2FACodeHandler(r *http.Request) Send2FACodeResponse {
	var req Send2FACodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Send2FACodeResponse{
			Error:      "Invalid request format",
			StatusCode: 400,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return Send2FACodeResponse{
			Error:      "Validation failed: " + err.Error(),
			StatusCode: 400,
		}
	}

	err := a.Send2FACode(req.UserID)
	if err != nil {
		slog.Error("Failed to send 2FA code", "error", err, "user_id", req.UserID)
		return Send2FACodeResponse{
			Error:      err.Error(),
			StatusCode: 400,
		}
	}

	return Send2FACodeResponse{
		Message:    "2FA verification code sent to your email",
		StatusCode: 200,
	}
}

// Verify2FACodeHandler handles verifying a 2FA code
func (a *AuthService) Verify2FACodeHandler(r *http.Request) Verify2FACodeResponse {
	var req Verify2FACodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Verify2FACodeResponse{
			Error:      "Invalid request format",
			StatusCode: 400,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return Verify2FACodeResponse{
			Error:      "Validation failed: " + err.Error(),
			StatusCode: 400,
		}
	}

	err := a.Verify2FACode(req.UserID, req.Code)
	if err != nil {
		slog.Error("Failed to verify 2FA code", "error", err, "user_id", req.UserID)
		return Verify2FACodeResponse{
			Error:      err.Error(),
			StatusCode: 400,
		}
	}

	return Verify2FACodeResponse{
		Message:    "2FA code verified successfully",
		StatusCode: 200,
	}
}

// Generate2FABackupCodesHandler handles generating new backup codes
func (a *AuthService) Generate2FABackupCodesHandler(r *http.Request) Generate2FABackupCodesResponse {
	var req Generate2FABackupCodesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Generate2FABackupCodesResponse{
			Error:      "Invalid request format",
			StatusCode: 400,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return Generate2FABackupCodesResponse{
			Error:      "Validation failed: " + err.Error(),
			StatusCode: 400,
		}
	}

	backupCodes, err := a.Generate2FABackupCodes(req.UserID)
	if err != nil {
		slog.Error("Failed to generate backup codes", "error", err, "user_id", req.UserID)
		return Generate2FABackupCodesResponse{
			Error:      err.Error(),
			StatusCode: 400,
		}
	}

	return Generate2FABackupCodesResponse{
		BackupCodes: backupCodes,
		Message:     "New backup codes generated successfully",
		StatusCode:  200,
	}
}

// Disable2FAHandler handles disabling 2FA for a user
func (a *AuthService) Disable2FAHandler(r *http.Request) Disable2FAResponse {
	var req Disable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return Disable2FAResponse{
			Error:      "Invalid request format",
			StatusCode: 400,
		}
	}

	if err := a.validator.Struct(req); err != nil {
		return Disable2FAResponse{
			Error:      "Validation failed: " + err.Error(),
			StatusCode: 400,
		}
	}

	err := a.Disable2FAForUser(req.UserID)
	if err != nil {
		slog.Error("Failed to disable 2FA", "error", err, "user_id", req.UserID)
		return Disable2FAResponse{
			Error:      err.Error(),
			StatusCode: 400,
		}
	}

	return Disable2FAResponse{
		Message:    "2FA has been disabled successfully",
		StatusCode: 200,
	}
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
