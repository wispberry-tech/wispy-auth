package core

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// AuthMiddleware provides authentication middleware for HTTP handlers
func (a *AuthService) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractTokenFromRequest(r)
		if token == "" {
			slog.Debug("No token provided in request")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate session
		session, err := a.storage.GetSession(token)
		if err != nil {
			slog.Error("Failed to get session", "error", err)
			http.Error(w, "Session validation failed", http.StatusInternalServerError)
			return
		}

		if session == nil {
			slog.Debug("Invalid session token", "token_prefix", token[:min(8, len(token))])
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if session is expired
		if time.Now().After(session.ExpiresAt) {
			slog.Debug("Session expired", "session_id", session.ID)
			// Clean up expired session
			if err := a.storage.DeleteSession(token); err != nil {
				slog.Error("Failed to delete expired session", "error", err)
			}
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		// Get user
		user, err := a.storage.GetUserByID(session.UserID)
		if err != nil {
			slog.Error("Failed to get user", "error", err)
			http.Error(w, "User retrieval failed", http.StatusInternalServerError)
			return
		}

		if user == nil {
			slog.Debug("User not found for session", "user_id", session.UserID)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check if user is active
		if !user.IsActive || user.IsSuspended {
			slog.Debug("User account is inactive", "user_id", user.ID)
			http.Error(w, "Account is not active", http.StatusUnauthorized)
			return
		}

		// Update session last accessed time
		session.LastAccessedAt = time.Now()
		if err := a.storage.UpdateSession(session); err != nil {
			slog.Error("Failed to update session last accessed time", "error", err)
			// Don't fail the request for this error
		}

		// Clear password hash before adding to context
		user.PasswordHash = ""

		// Add user to request context
		ctx := context.WithValue(r.Context(), "user", user)
		ctx = context.WithValue(ctx, "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuthMiddleware provides optional authentication middleware
// If a token is provided and valid, the user is added to context
// If no token or invalid token, the request continues without user context
func (a *AuthService) OptionalAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractTokenFromRequest(r)
		if token == "" {
			// No token provided, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Try to validate session
		session, err := a.storage.GetSession(token)
		if err != nil {
			slog.Error("Failed to get session in optional auth", "error", err)
			// Continue without authentication on error
			next.ServeHTTP(w, r)
			return
		}

		if session == nil || time.Now().After(session.ExpiresAt) {
			// Invalid or expired session, continue without authentication
			if session != nil && time.Now().After(session.ExpiresAt) {
				// Clean up expired session
				if err := a.storage.DeleteSession(token); err != nil {
					slog.Error("Failed to delete expired session in optional auth", "error", err)
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		// Get user
		user, err := a.storage.GetUserByID(session.UserID)
		if err != nil {
			slog.Error("Failed to get user in optional auth", "error", err)
			next.ServeHTTP(w, r)
			return
		}

		if user == nil || !user.IsActive || user.IsSuspended {
			// User not found or inactive, continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Update session last accessed time
		session.LastAccessedAt = time.Now()
		if err := a.storage.UpdateSession(session); err != nil {
			slog.Error("Failed to update session last accessed time in optional auth", "error", err)
		}

		// Clear password hash before adding to context
		user.PasswordHash = ""

		// Add user to request context
		ctx := context.WithValue(r.Context(), "user", user)
		ctx = context.WithValue(ctx, "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSessionFromContext retrieves the current session from the request context
func GetSessionFromContext(r *http.Request) *Session {
	if session, ok := r.Context().Value("session").(*Session); ok {
		return session
	}
	return nil
}
