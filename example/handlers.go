package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	auth "github.com/wispberry-tech/wispy-auth"
)

// handleSignUp handles user registration with validation
func handleSignUp(authService *auth.AuthService, emailService EmailService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SignUpRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		// Validate request
		if errors := validateRequest(req); errors != nil {
			sendValidationErrors(w, errors)
			return
		}

		// Extract security context
		ip := extractIP(r)
		userAgent := r.Header.Get("User-Agent")

		// Convert to auth request
		authReq := convertToAuthSignUpRequest(req)

		// Call auth service
		response := authService.HandleSignUp(authReq, ip, userAgent)

		// Handle response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		// Send verification email if needed
		if response.RequiresEmailVerification && response.User.VerificationToken != "" {
			go func() {
				if err := emailService.SendVerificationEmail(response.User.Email, response.User.VerificationToken); err != nil {
					// Log error but don't fail the request
					// In production, you might want to retry or queue this
					// log.Printf("Failed to send verification email: %v", err)
				}
			}()
		} else {
			// Send welcome email for verified users
			go func() {
				if err := emailService.SendWelcomeEmail(response.User.Email, response.User.Name); err != nil {
					// Log error but don't fail the request
					// log.Printf("Failed to send welcome email: %v", err)
				}
			}()
		}

		json.NewEncoder(w).Encode(response)
	}
}

// handleSignIn handles user authentication with validation
func handleSignIn(authService *auth.AuthService, emailService EmailService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SignInRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		// Validate request
		if errors := validateRequest(req); errors != nil {
			sendValidationErrors(w, errors)
			return
		}

		// Extract security context
		ip := extractIP(r)
		userAgent := r.Header.Get("User-Agent")

		// Convert to auth request
		authReq := convertToAuthSignInRequest(req)

		// Call auth service
		response := authService.HandleSignIn(authReq, ip, userAgent)

		// Handle response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(response)
	}
}

// handleValidate validates a JWT token
func handleValidate(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		response := authService.HandleValidate(token)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(response.User)
	}
}

// handleForgotPassword initiates password reset with validation
func handleForgotPassword(authService *auth.AuthService, emailService EmailService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ForgotPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		// Validate request
		if errors := validateRequest(req); errors != nil {
			sendValidationErrors(w, errors)
			return
		}

		// Convert to auth request
		authReq := convertToAuthForgotPasswordRequest(req)

		// Call auth service
		response := authService.HandleForgotPassword(authReq)

		// Send password reset email asynchronously
		// Note: We always send the email attempt to prevent email enumeration
		go func() {
			// In a real implementation, you would need to get the actual reset token
			// from the auth service. For now, this is a mock token.
			if err := emailService.SendPasswordResetEmail(req.Email, "mock-reset-token"); err != nil {
				// Log error but don't fail the request
				// log.Printf("Failed to send password reset email: %v", err)
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": response.Message})
	}
}

// handleResetPassword resets user password with validation
func handleResetPassword(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		// Validate request
		if errors := validateRequest(req); errors != nil {
			sendValidationErrors(w, errors)
			return
		}

		// Convert to auth request
		authReq := convertToAuthResetPasswordRequest(req)

		// Call auth service
		response := authService.HandleResetPassword(authReq)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": response.Message})
	}
}

// handleVerifyEmail verifies user email with validation
func handleVerifyEmail(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		// Validate request
		if errors := validateRequest(req); errors != nil {
			sendValidationErrors(w, errors)
			return
		}

		// Convert to auth request
		authReq := convertToAuthVerifyEmailRequest(req)

		// Call auth service
		response := authService.HandleVerifyEmail(authReq)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": response.Message})
	}
}

// handleResendVerification resends verification email
func handleResendVerification(authService *auth.AuthService, emailService EmailService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		response := authService.HandleResendVerification(token)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		// In a real implementation, you would need to get the user and verification token
		// from the auth service to send the actual email with the token
		// For now, this is a mock implementation

		json.NewEncoder(w).Encode(map[string]string{"message": response.Message})
	}
}

// handleGetSessions gets all user sessions
func handleGetSessions(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		response := authService.HandleGetSessions(token)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(response)
	}
}

// handleRevokeSession revokes a specific session
func handleRevokeSession(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := chi.URLParam(r, "sessionID")
		if sessionID == "" {
			http.Error(w, "Session ID is required", http.StatusBadRequest)
			return
		}

		response := authService.HandleRevokeSession(sessionID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": response.Message})
	}
}

// handleRevokeAllSessions revokes all user sessions
func handleRevokeAllSessions(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		response := authService.HandleRevokeAllSessions(token)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"message": response.Message})
	}
}

// handleOAuth initiates OAuth flow
func handleOAuth(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		if provider == "" {
			http.Error(w, "Provider parameter required", http.StatusBadRequest)
			return
		}

		response := authService.HandleGetOAuth(provider)

		if response.Error != "" {
			http.Error(w, response.Error, response.StatusCode)
			return
		}

		// Redirect to OAuth provider
		http.Redirect(w, r, response.URL, http.StatusTemporaryRedirect)
	}
}

// handleOAuthCallback handles OAuth callback
func handleOAuthCallback(authService *auth.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		code := r.URL.Query().Get("code")

		if provider == "" {
			http.Error(w, "Provider parameter required", http.StatusBadRequest)
			return
		}

		if code == "" {
			http.Error(w, "Authorization code required", http.StatusBadRequest)
			return
		}

		response := authService.HandleOAuthCallbackRequest(provider, code)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)

		if response.Error != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": response.Error})
			return
		}

		json.NewEncoder(w).Encode(response)
	}
}

// handleGetProviders returns available OAuth providers
func handleGetProviders() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providers := []string{"google", "github", "discord"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"providers": providers,
		})
	}
}