package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Context keys for storing user data in request context
type contextKey string

const (
	UserContextKey   contextKey = "auth_user"
	TenantContextKey contextKey = "auth_tenant"
)

// MiddlewareConfig holds configuration for middleware behavior and customization.
// It allows fine-tuning of authentication, error handling, and tenant resolution.
type MiddlewareConfig struct {
	// TokenExtractor defines how to extract token from request
	TokenExtractor func(r *http.Request) string
	
	// TenantExtractor defines how to extract tenant context from request
	TenantExtractor func(r *http.Request) uint
	
	// ErrorHandler defines how to handle middleware errors
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error, statusCode int)
	
	// SkipAuth allows certain paths to skip authentication
	SkipAuth func(r *http.Request) bool
}

// DefaultMiddlewareConfig returns sensible defaults for middleware configuration.
// It sets up standard token extraction from Authorization header, tenant extraction
// from headers/URL parameters, JSON error responses, and no auth skipping.
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		TokenExtractor:  defaultTokenExtractor,
		TenantExtractor: defaultTenantExtractor,
		ErrorHandler:    defaultErrorHandler,
		SkipAuth:        func(r *http.Request) bool { return false },
	}
}

// defaultTokenExtractor extracts session token from Authorization header.
// It removes the "Bearer " prefix if present and returns the clean token.
func defaultTokenExtractor(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if token == "" {
		return ""
	}
	
	// Remove "Bearer " prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		return token[7:]
	}
	
	return token
}

// defaultTenantExtractor extracts tenant ID from various sources.
// It checks X-Tenant-ID header, URL query parameter, and Chi URL parameter
// in that order, returning the first valid tenant ID found or 0 if none.
func defaultTenantExtractor(r *http.Request) uint {
	// Try header first
	if tenantHeader := r.Header.Get("X-Tenant-ID"); tenantHeader != "" {
		if tenantID, err := strconv.ParseUint(tenantHeader, 10, 32); err == nil {
			return uint(tenantID)
		}
	}
	
	// Try URL parameter
	if tenantParam := r.URL.Query().Get("tenant_id"); tenantParam != "" {
		if tenantID, err := strconv.ParseUint(tenantParam, 10, 32); err == nil {
			return uint(tenantID)
		}
	}
	
	// Try Chi URL parameter
	if tenantParam := chi.URLParam(r, "tenantID"); tenantParam != "" {
		if tenantID, err := strconv.ParseUint(tenantParam, 10, 32); err == nil {
			return uint(tenantID)
		}
	}
	
	return 0 // Default/no tenant
}

// defaultErrorHandler provides standard JSON error responses.
// It sets appropriate headers and returns error messages in JSON format.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}

// RequireAuth middleware ensures user is authenticated before accessing protected routes.
// It validates session tokens, extracts user information, and adds the user to request context.
// Optionally accepts custom MiddlewareConfig for customized behavior.
//
// Usage:
//   r.Use(authService.RequireAuth())
//   r.With(authService.RequireAuth()).Get("/protected", handler)
func (a *AuthService) RequireAuth(config ...MiddlewareConfig) func(http.Handler) http.Handler {
	cfg := DefaultMiddlewareConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this request should skip auth
			if cfg.SkipAuth(r) {
				next.ServeHTTP(w, r)
				return
			}
			
			// Extract token
			token := cfg.TokenExtractor(r)
			if token == "" {
				cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusUnauthorized)
				return
			}
			
			// Get session from token
			session, err := a.storage.GetSession(token)
			if err != nil {
				cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusUnauthorized)
				return
			}
			
			// Check if session is valid and active
			if !session.IsActive || session.ExpiresAt.Before(time.Now()) {
				cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusUnauthorized)
				return
			}
			
			// Get user from session
			user, err := a.storage.GetUserByID(session.UserID)
			if err != nil {
				cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusUnauthorized)
				return
			}
			
			// Update session activity
			session.LastActivity = time.Now()
			if updateErr := a.storage.UpdateSession(session); updateErr != nil {
				// Log the error but don't fail the request
				slog.Warn("Failed to update session activity", "error", updateErr, "session_id", session.ID)
			}
			
			// Add user to context
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole middleware ensures user has specific role(s) in the current or default tenant.
// This middleware should be used after RequireAuth. It extracts tenant context from
// the request and verifies the user has one of the required roles.
//
// Parameters:
//   - roles: One or more role names that the user must have
//
// Usage:
//   r.With(authService.RequireRole("admin", "moderator")).Get("/admin", handler)
func (a *AuthService) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return a.RequireRoleInTenant(0, roles...) // Use default tenant
}

// RequireRoleInTenant middleware ensures user has specific role(s) in a specified tenant.
// This provides more control than RequireRole by explicitly specifying the tenant ID.
// Use this when you need to verify roles in a specific tenant rather than the current context.
//
// Parameters:
//   - tenantID: Specific tenant ID to check roles in (0 = extract from request)
//   - roles: One or more role names that the user must have
//
// Usage:
//   r.With(authService.RequireRoleInTenant(1, "admin")).Get("/tenant/1/admin", handler)
func (a *AuthService) RequireRoleInTenant(tenantID uint, roles ...string) func(http.Handler) http.Handler {
	cfg := DefaultMiddlewareConfig()
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user from context (should be set by RequireAuth)
			user, ok := r.Context().Value(UserContextKey).(*User)
			if !ok {
				cfg.ErrorHandler(w, r, ErrUserNotFound, http.StatusUnauthorized)
				return
			}
			
			// Determine tenant ID
			targetTenantID := tenantID
			if targetTenantID == 0 {
				targetTenantID = cfg.TenantExtractor(r)
			}
			
			// If still no tenant ID, use default tenant
			if targetTenantID == 0 {
				targetTenantID = a.storageConfig.MultiTenant.DefaultTenantID
			}
			
			// Get user's tenants and roles
			userTenants, err := a.GetUserTenants(user.ID)
			if err != nil {
				cfg.ErrorHandler(w, r, err, http.StatusInternalServerError)
				return
			}
			
			// Check if user has required role in the tenant
			hasRole := false
			for _, ut := range userTenants {
				if ut.TenantID == targetTenantID && ut.Role != nil {
					for _, requiredRole := range roles {
						if ut.Role.Name == requiredRole {
							hasRole = true
							// Add tenant to context
							ctx := context.WithValue(r.Context(), TenantContextKey, ut.Tenant)
							r = r.WithContext(ctx)
							break
						}
					}
				}
				if hasRole {
					break
				}
			}
			
			if !hasRole {
				cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusForbidden)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission middleware ensures user has specific permission(s) in the current tenant.
// This provides fine-grained access control by checking individual permissions rather
// than broad roles. Should be used after RequireAuth middleware.
//
// Parameters:
//   - permissions: One or more permission names that the user must have
//
// Usage:
//   r.With(authService.RequirePermission("users.read", "users.write")).Get("/users", handler)
func (a *AuthService) RequirePermission(permissions ...string) func(http.Handler) http.Handler {
	return a.RequirePermissionInTenant(0, permissions...)
}

// RequirePermissionInTenant middleware ensures user has specific permission(s) in a specified tenant.
// This provides the most granular control by checking specific permissions in a specific tenant.
// Use this for multi-tenant applications with complex permission requirements.
//
// Parameters:
//   - tenantID: Specific tenant ID to check permissions in (0 = extract from request)
//   - permissions: One or more permission names that the user must have
//
// Usage:
//   r.With(authService.RequirePermissionInTenant(1, "billing.read")).Get("/tenant/1/billing", handler)
func (a *AuthService) RequirePermissionInTenant(tenantID uint, permissions ...string) func(http.Handler) http.Handler {
	cfg := DefaultMiddlewareConfig()
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user from context (should be set by RequireAuth)
			user, ok := r.Context().Value(UserContextKey).(*User)
			if !ok {
				cfg.ErrorHandler(w, r, ErrUserNotFound, http.StatusUnauthorized)
				return
			}
			
			// Determine tenant ID
			targetTenantID := tenantID
			if targetTenantID == 0 {
				targetTenantID = cfg.TenantExtractor(r)
			}
			
			// If still no tenant ID, use default tenant
			if targetTenantID == 0 {
				targetTenantID = a.storageConfig.MultiTenant.DefaultTenantID
			}
			
			// Check each required permission
			for _, permission := range permissions {
				hasPermission, err := a.UserHasPermission(user.ID, targetTenantID, permission)
				if err != nil {
					cfg.ErrorHandler(w, r, err, http.StatusInternalServerError)
					return
				}
				
				if !hasPermission {
					cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusForbidden)
					return
				}
			}
			
			// Add tenant ID to context for convenience
			if targetTenantID > 0 {
				ctx := context.WithValue(r.Context(), TenantContextKey, targetTenantID)
				r = r.WithContext(ctx)
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenant middleware ensures request is in the context of a specific tenant.
// It verifies that the authenticated user belongs to the specified tenant and is active.
// The tenant information is added to the request context for use in handlers.
//
// Parameters:
//   - tenantID: Optional specific tenant ID (if not provided, extracted from request)
//
// Usage:
//   r.With(authService.RequireTenant(1)).Get("/tenant/1/data", handler)
//   r.With(authService.RequireTenant()).Get("/tenant/{tenantID}/data", handler)
func (a *AuthService) RequireTenant(tenantID ...uint) func(http.Handler) http.Handler {
	cfg := DefaultMiddlewareConfig()
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user from context (should be set by RequireAuth)
			user, ok := r.Context().Value(UserContextKey).(*User)
			if !ok {
				cfg.ErrorHandler(w, r, ErrUserNotFound, http.StatusUnauthorized)
				return
			}
			
			// Determine required tenant ID
			var requiredTenantID uint
			if len(tenantID) > 0 {
				requiredTenantID = tenantID[0]
			} else {
				requiredTenantID = cfg.TenantExtractor(r)
			}
			
			if requiredTenantID == 0 {
				cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusBadRequest)
				return
			}
			
			// Check if user belongs to this tenant
			userTenants, err := a.GetUserTenants(user.ID)
			if err != nil {
				cfg.ErrorHandler(w, r, err, http.StatusInternalServerError)
				return
			}
			
			belongsToTenant := false
			var userTenant *UserTenant
			for _, ut := range userTenants {
				if ut.TenantID == requiredTenantID && ut.IsActive {
					belongsToTenant = true
					userTenant = ut
					break
				}
			}
			
			if !belongsToTenant {
				cfg.ErrorHandler(w, r, ErrInvalidCredentials, http.StatusForbidden)
				return
			}
			
			// Add tenant to context
			ctx := context.WithValue(r.Context(), TenantContextKey, userTenant.Tenant)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Chain middleware allows chaining multiple middleware together in a specific order.
// Middleware are applied in reverse order (last to first), so the first middleware
// in the list will be the outermost wrapper.
//
// Parameters:
//   - middlewares: One or more middleware functions to chain together
//
// Usage:
//   combined := authService.Chain(RequireAuth(), RequireRole("admin"), RequireTenant())
//   r.With(combined).Get("/admin", handler)
func (a *AuthService) Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// Context helper functions for extracting data from request context

// GetUserFromContext extracts the authenticated user from request context.
// Returns the user and a boolean indicating if the user was found.
// The user is set by RequireAuth middleware and related auth middleware.
//
// Returns:
//   - *User: The authenticated user, or nil if not found
//   - bool: true if user was found in context, false otherwise
func GetUserFromContext(r *http.Request) (*User, bool) {
	user, ok := r.Context().Value(UserContextKey).(*User)
	return user, ok
}

// GetTenantFromContext extracts the tenant information from request context.
// Returns the tenant and a boolean indicating if the tenant was found.
// The tenant is set by tenant-related middleware.
//
// Returns:
//   - *Tenant: The tenant object, or nil if not found
//   - bool: true if tenant was found in context, false otherwise
func GetTenantFromContext(r *http.Request) (*Tenant, bool) {
	tenant, ok := r.Context().Value(TenantContextKey).(*Tenant)
	return tenant, ok
}

// GetTenantIDFromContext extracts the tenant ID from request context.
// It tries to get the ID from a Tenant object first, then falls back to
// a direct tenant ID value. Returns 0 and false if no tenant context is found.
//
// Returns:
//   - uint: The tenant ID, or 0 if not found
//   - bool: true if tenant ID was found in context, false otherwise
func GetTenantIDFromContext(r *http.Request) (uint, bool) {
	if tenant, ok := GetTenantFromContext(r); ok && tenant != nil {
		return tenant.ID, true
	}
	
	if tenantID, ok := r.Context().Value(TenantContextKey).(uint); ok {
		return tenantID, true
	}
	
	return 0, false
}

// MustGetUserFromContext extracts user from context or panics if not found.
// This is a convenience function for handlers that require authentication.
// Use this only when you're certain the RequireAuth middleware is in place.
//
// Panics if user is not found in context.
//
// Returns:
//   - *User: The authenticated user from context
func MustGetUserFromContext(r *http.Request) *User {
	user, ok := GetUserFromContext(r)
	if !ok {
		panic("user not found in request context - make sure RequireAuth middleware is used")
	}
	return user
}

// MustGetTenantFromContext extracts tenant from context or panics if not found.
// This is a convenience function for handlers that require tenant context.
// Use this only when you're certain tenant middleware is in place.
//
// Panics if tenant is not found in context.
//
// Returns:
//   - *Tenant: The tenant from context
func MustGetTenantFromContext(r *http.Request) *Tenant {
	tenant, ok := GetTenantFromContext(r)
	if !ok {
		panic("tenant not found in request context - make sure tenant middleware is used")
	}
	return tenant
}

// Convenience middleware combinations

// RequireAuthAndRole combines authentication and role checking in a single middleware.
// This is equivalent to chaining RequireAuth() and RequireRole() but more convenient.
//
// Parameters:
//   - roles: One or more role names that the user must have
//
// Usage:
//   r.With(authService.RequireAuthAndRole("admin")).Get("/admin", handler)
func (a *AuthService) RequireAuthAndRole(roles ...string) func(http.Handler) http.Handler {
	return a.Chain(
		a.RequireAuth(),
		a.RequireRole(roles...),
	)
}

// RequireAuthAndPermission combines authentication and permission checking in a single middleware.
// This is equivalent to chaining RequireAuth() and RequirePermission() but more convenient.
//
// Parameters:
//   - permissions: One or more permission names that the user must have
//
// Usage:
//   r.With(authService.RequireAuthAndPermission("users.read")).Get("/users", handler)
func (a *AuthService) RequireAuthAndPermission(permissions ...string) func(http.Handler) http.Handler {
	return a.Chain(
		a.RequireAuth(),
		a.RequirePermission(permissions...),
	)
}

// RequireAuthAndTenant combines authentication and tenant checking in a single middleware.
// This is equivalent to chaining RequireAuth() and RequireTenant() but more convenient.
//
// Parameters:
//   - tenantID: Optional specific tenant ID (if not provided, extracted from request)
//
// Usage:
//   r.With(authService.RequireAuthAndTenant(1)).Get("/tenant/1/data", handler)
func (a *AuthService) RequireAuthAndTenant(tenantID ...uint) func(http.Handler) http.Handler {
	return a.Chain(
		a.RequireAuth(),
		a.RequireTenant(tenantID...),
	)
}

// RequireAuthRoleAndTenant combines authentication, role checking, and tenant verification.
// This provides comprehensive access control for multi-tenant applications with role-based access.
//
// Parameters:
//   - tenantID: Specific tenant ID to check roles in
//   - roles: One or more role names that the user must have in the tenant
//
// Usage:
//   r.With(authService.RequireAuthRoleAndTenant(1, "admin")).Get("/tenant/1/admin", handler)
func (a *AuthService) RequireAuthRoleAndTenant(tenantID uint, roles ...string) func(http.Handler) http.Handler {
	return a.Chain(
		a.RequireAuth(),
		a.RequireRoleInTenant(tenantID, roles...),
	)
}

// RequireAuthPermissionAndTenant combines authentication, permission checking, and tenant verification.
// This provides the most granular access control for multi-tenant applications with fine-grained permissions.
//
// Parameters:
//   - tenantID: Specific tenant ID to check permissions in
//   - permissions: One or more permission names that the user must have in the tenant
//
// Usage:
//   r.With(authService.RequireAuthPermissionAndTenant(1, "billing.read")).Get("/tenant/1/billing", handler)
func (a *AuthService) RequireAuthPermissionAndTenant(tenantID uint, permissions ...string) func(http.Handler) http.Handler {
	return a.Chain(
		a.RequireAuth(),
		a.RequirePermissionInTenant(tenantID, permissions...),
	)
}