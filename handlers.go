package auth

import (
	"errors"
	"strings"
	"time"
)

// Request and Response Types
type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type SignUpResponse struct {
	Token                      string `json:"token"`
	User                       *User  `json:"user"`
	RequiresEmailVerification bool   `json:"requires_email_verification"`
	StatusCode                int    `json:"-"`
	Error                     string `json:"error,omitempty"`
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInResponse struct {
	Token            string     `json:"token"`
	User             *User      `json:"user"`
	SessionID        string     `json:"session_id"`
	Requires2FA      bool       `json:"requires_2fa"`
	SessionExpiresAt time.Time  `json:"session_expires_at"`
	StatusCode       int        `json:"-"`
	Error            string     `json:"error,omitempty"`
}

type ValidateResponse struct {
	User       *User  `json:"user"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

type OAuthResponse struct {
	URL        string `json:"url,omitempty"`
	Token      string `json:"token,omitempty"`
	User       *User  `json:"user,omitempty"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ForgotPasswordResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type ResetPasswordResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

type EmailVerificationResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

type SessionsResponse struct {
	Sessions   []*Session `json:"sessions"`
	StatusCode int        `json:"-"`
	Error      string     `json:"error,omitempty"`
}

type RevokeSessionResponse struct {
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Error      string `json:"error,omitempty"`
}

// Handler Methods that return response types
func (a *AuthService) HandleSignUp(request SignUpRequest, ip, userAgent string) SignUpResponse {
	// Validate required fields
	if request.Email == "" || request.Password == "" || request.Name == "" {
		return SignUpResponse{
			StatusCode: 400,
			Error:      "Email, password, and name are required",
		}
	}

	user, err := a.SignUpWithTenant(request.Email, request.Password, request.Name, 0)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			return SignUpResponse{
				StatusCode: 409,
				Error:      "User already exists",
			}
		} else if strings.Contains(err.Error(), "password must") || strings.Contains(err.Error(), "invalid email") {
			return SignUpResponse{
				StatusCode: 400,
				Error:      err.Error(),
			}
		} else {
			return SignUpResponse{
				StatusCode: 500,
				Error:      "Failed to create user",
			}
		}
	}

	// Create session for the new user
	session, err := a.CreateSession(user.ID, ip, userAgent, "")
	if err != nil {
		return SignUpResponse{
			StatusCode: 500,
			Error:      "Failed to create session",
		}
	}

	return SignUpResponse{
		Token:                     session.Token,
		User:                      user,
		RequiresEmailVerification: a.securityConfig.RequireEmailVerification && !user.EmailVerified,
		StatusCode:                200,
	}
}

func (a *AuthService) HandleSignIn(request SignInRequest, ip, userAgent string) SignInResponse {
	// Validate required fields
	if request.Email == "" || request.Password == "" {
		return SignInResponse{
			StatusCode: 400,
			Error:      "Email and password are required",
		}
	}

	user, err := a.SignInWithContext(request.Email, request.Password, ip, userAgent, "")
	if err != nil {
		if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrInvalidCredentials) {
			return SignInResponse{
				StatusCode: 401,
				Error:      "Invalid credentials",
			}
		} else if strings.Contains(err.Error(), "account is locked") {
			return SignInResponse{
				StatusCode: 423,
				Error:      err.Error(),
			}
		} else if strings.Contains(err.Error(), "account is suspended") || 
			     strings.Contains(err.Error(), "account is inactive") {
			return SignInResponse{
				StatusCode: 403,
				Error:      err.Error(),
			}
		} else if strings.Contains(err.Error(), "email not verified") {
			return SignInResponse{
				StatusCode: 403,
				Error:      "Email verification required",
			}
		} else {
			return SignInResponse{
				StatusCode: 500,
				Error:      "Internal server error",
			}
		}
	}

	// Create session for the authenticated user
	session, err := a.CreateSession(user.ID, ip, userAgent, "")
	if err != nil {
		return SignInResponse{
			StatusCode: 500,
			Error:      "Failed to create session",
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

func (a *AuthService) HandleValidate(token string) ValidateResponse {
	if token == "" {
		return ValidateResponse{
			StatusCode: 401,
			Error:      "Authorization token required",
		}
	}

	// Remove "Bearer " prefix if present
	if after, ok := strings.CutPrefix(token, "Bearer "); ok {
		token = after
	}

	user, err := a.ValidateUser(token)
	if err != nil {
		return ValidateResponse{
			StatusCode: 401,
			Error:      "Invalid token",
		}
	}

	return ValidateResponse{
		User:       user,
		StatusCode: 200,
	}
}

func (a *AuthService) HandleGetOAuth(provider string) OAuthResponse {
	if provider == "" {
		return OAuthResponse{
			StatusCode: 400,
			Error:      "Provider parameter required",
		}
	}

	state := generateRandomPassword()
	url, err := a.GetOAuthURL(provider, state)
	if err != nil {
		return OAuthResponse{
			StatusCode: 400,
			Error:      "Invalid OAuth provider",
		}
	}

	return OAuthResponse{
		URL:        url,
		StatusCode: 307, // Temporary Redirect
	}
}

func (a *AuthService) HandleOAuthCallbackRequest(provider, code string) OAuthResponse {
	if provider == "" {
		return OAuthResponse{
			StatusCode: 400,
			Error:      "Provider parameter required",
		}
	}

	if code == "" {
		return OAuthResponse{
			StatusCode: 400,
			Error:      "Code not provided",
		}
	}

	user, err := a.processOAuthCallback(provider, code)
	if err != nil {
		return OAuthResponse{
			StatusCode: 500,
			Error:      "OAuth failed: " + err.Error(),
		}
	}

	token, err := a.GenerateToken(user)
	if err != nil {
		return OAuthResponse{
			StatusCode: 500,
			Error:      "Failed to generate token",
		}
	}

	return OAuthResponse{
		Token:      token,
		User:       user,
		StatusCode: 200,
	}
}

// processOAuthCallback is the internal method to handle OAuth callback
func (a *AuthService) processOAuthCallback(provider, code string) (*User, error) {
	// This would contain the actual OAuth processing logic
	// For now, returning an error as this needs to be implemented
	return nil, errors.New("OAuth callback processing not implemented")
}

// Password Reset Handlers
func (a *AuthService) HandleForgotPassword(request ForgotPasswordRequest) ForgotPasswordResponse {
	if request.Email == "" {
		return ForgotPasswordResponse{
			StatusCode: 400,
			Error:      "Email is required",
		}
	}

	// Always return success to prevent email enumeration
	if err := a.InitiatePasswordReset(request.Email); err != nil {
		// Log error but don't expose it to prevent information leakage
	}

	return ForgotPasswordResponse{
		Message:    "If the email exists, a password reset link has been sent",
		StatusCode: 200,
	}
}

func (a *AuthService) HandleResetPassword(request ResetPasswordRequest) ResetPasswordResponse {
	if request.Token == "" || request.NewPassword == "" {
		return ResetPasswordResponse{
			StatusCode: 400,
			Error:      "Token and new password are required",
		}
	}

	if err := a.ResetPassword(request.Token, request.NewPassword); err != nil {
		if strings.Contains(err.Error(), "invalid reset token") || strings.Contains(err.Error(), "expired") {
			return ResetPasswordResponse{
				StatusCode: 400,
				Error:      err.Error(),
			}
		} else if strings.Contains(err.Error(), "password must") {
			return ResetPasswordResponse{
				StatusCode: 400,
				Error:      err.Error(),
			}
		} else {
			return ResetPasswordResponse{
				StatusCode: 500,
				Error:      "Failed to reset password",
			}
		}
	}

	return ResetPasswordResponse{
		Message:    "Password reset successfully",
		StatusCode: 200,
	}
}

// Email Verification Handlers
func (a *AuthService) HandleResendVerification(token string) EmailVerificationResponse {
	if token == "" {
		return EmailVerificationResponse{
			StatusCode: 401,
			Error:      "Authorization token required",
		}
	}

	// Remove "Bearer " prefix if present
	if after, ok := strings.CutPrefix(token, "Bearer "); ok {
		token = after
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

	return EmailVerificationResponse{
		Message:    "Verification email sent",
		StatusCode: 200,
	}
}

func (a *AuthService) HandleVerifyEmail(request VerifyEmailRequest) EmailVerificationResponse {
	if request.Token == "" {
		return EmailVerificationResponse{
			StatusCode: 400,
			Error:      "Verification token is required",
		}
	}

	if err := a.VerifyEmail(request.Token); err != nil {
		return EmailVerificationResponse{
			StatusCode: 400,
			Error:      "Invalid verification token",
		}
	}

	return EmailVerificationResponse{
		Message:    "Email verified successfully",
		StatusCode: 200,
	}
}

// Session Management Handlers
func (a *AuthService) HandleGetSessions(token string) SessionsResponse {
	if token == "" {
		return SessionsResponse{
			StatusCode: 401,
			Error:      "Authorization token required",
		}
	}

	// Remove "Bearer " prefix if present
	if after, ok := strings.CutPrefix(token, "Bearer "); ok {
		token = after
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

func (a *AuthService) HandleRevokeSession(sessionID string) RevokeSessionResponse {
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

func (a *AuthService) HandleRevokeAllSessions(token string) RevokeSessionResponse {
	if token == "" {
		return RevokeSessionResponse{
			StatusCode: 401,
			Error:      "Authorization token required",
		}
	}

	// Remove "Bearer " prefix if present
	if after, ok := strings.CutPrefix(token, "Bearer "); ok {
		token = after
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
