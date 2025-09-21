# 📚 API Reference

Complete API documentation for Wispy Auth library components, handlers, and configuration options.

## 🏗️ Core Service

### AuthService

The main authentication service that orchestrates all operations.

```go
type AuthService struct {
    storage         storage.Interface
    oauthConfigs    map[string]*oauth2.Config
    storageConfig   StorageConfig
    securityConfig  SecurityConfig
    emailService    EmailService
    validator       *validator.Validate
    developmentMode bool
}
```

#### Constructor

```go
func NewAuthService(cfg Config) (*AuthService, error)
```

**Parameters:**
- `cfg Config` - Service configuration

**Returns:**
- `*AuthService` - Configured service instance
- `error` - Configuration or initialization error

**Example:**
```go
authService, err := auth.NewAuthService(auth.Config{
    DatabaseDSN: "postgresql://user:pass@localhost/db",
    EmailService: &YourEmailService{},
    SecurityConfig: auth.SecurityConfig{
        RequireEmailVerification: true,
        PasswordMinLength: 8,
    },
})
```

## 🔧 Configuration

### Config

Main configuration structure for the authentication service.

```go
type Config struct {
    DatabaseDSN     string                              `json:"database_dsn"`
    Storage         storage.Interface                   `json:"-"`
    EmailService    EmailService                        `json:"-"`
    SecurityConfig  SecurityConfig                      `json:"security_config"`
    StorageConfig   StorageConfig                       `json:"storage_config"`
    OAuthProviders  map[string]OAuthProviderConfig      `json:"oauth_providers"`
    AutoMigrate     bool                                `json:"auto_migrate"`
}
```

**Fields:**
- `DatabaseDSN` - Database connection string (PostgreSQL/SQLite)
- `Storage` - Custom storage implementation (optional)
- `EmailService` - Email service implementation (required)
- `SecurityConfig` - Security policies and settings
- `StorageConfig` - Database table/column mapping
- `OAuthProviders` - OAuth provider configurations
- `AutoMigrate` - Enable automatic database migrations

### SecurityConfig

Comprehensive security configuration options.

```go
type SecurityConfig struct {
    // Email verification
    RequireEmailVerification bool          `json:"require_email_verification"`
    VerificationTokenExpiry  time.Duration `json:"verification_token_expiry"`

    // Password security
    PasswordMinLength      int           `json:"password_min_length"`
    PasswordRequireUpper   bool          `json:"password_require_upper"`
    PasswordRequireLower   bool          `json:"password_require_lower"`
    PasswordRequireNumber  bool          `json:"password_require_number"`
    PasswordRequireSpecial bool          `json:"password_require_special"`
    PasswordResetExpiry    time.Duration `json:"password_reset_expiry"`

    // Login security
    MaxLoginAttempts int           `json:"max_login_attempts"`
    LockoutDuration  time.Duration `json:"lockout_duration"`
    SessionLifetime  time.Duration `json:"session_lifetime"`
    RequireTwoFactor bool          `json:"require_two_factor"`

    // Referral System
    RequireReferralCode  bool              `json:"require_referral_code"`
    DefaultUserRoleName  string            `json:"default_user_role_name"`
    MaxInviteesPerRole   map[string]int    `json:"max_invitees_per_role"`
    ReferralCodeLength   int               `json:"referral_code_length"`
    ReferralCodePrefix   string            `json:"referral_code_prefix"`
    ReferralCodeExpiry   time.Duration     `json:"referral_code_expiry"`
}
```

**Default Values:**
```go
SecurityConfig{
    RequireEmailVerification: false,
    VerificationTokenExpiry:  24 * time.Hour,
    PasswordMinLength:        8,
    PasswordRequireUpper:     false,
    PasswordRequireLower:     false,
    PasswordRequireNumber:    false,
    PasswordRequireSpecial:   false,
    PasswordResetExpiry:      1 * time.Hour,
    MaxLoginAttempts:         5,
    LockoutDuration:          15 * time.Minute,
    SessionLifetime:          7 * 24 * time.Hour,
    RequireTwoFactor:         false,
    RequireReferralCode:      false,
    DefaultUserRoleName:      "default-user",
    MaxInviteesPerRole:       map[string]int{},
    ReferralCodeLength:       8,
    ReferralCodePrefix:       "",
    ReferralCodeExpiry:       0, // No expiry
}
```

## 🌐 HTTP Handlers

All handlers return structured response objects with status codes for maximum developer control.

### Authentication Handlers

#### SignUpHandler

User registration with email/password.

```go
func (a *AuthService) SignUpHandler(r *http.Request) SignUpResponse
```

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "password123",
    "username": "testuser",
    "first_name": "John",
    "last_name": "Doe",
    "referral_code": "REF12345678"
}
```

**Response:**
```go
type SignUpResponse struct {
    Token                     string `json:"token"`
    User                      *User  `json:"user"`
    RequiresEmailVerification bool   `json:"requires_email_verification"`
    StatusCode                int    `json:"-"`
    Error                     string `json:"error,omitempty"`
}
```

**Status Codes:**
- `201` - User created successfully
- `400` - Validation error or invalid referral code
- `409` - User already exists
- `500` - Internal server error

#### SignInHandler

User authentication with email/password.

```go
func (a *AuthService) SignInHandler(r *http.Request) SignInResponse
```

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```

**Response:**
```go
type SignInResponse struct {
    Token                     string    `json:"token"`
    User                      *User     `json:"user"`
    SessionID                 string    `json:"session_id"`
    Requires2FA               bool      `json:"requires_2fa"`
    RequiresEmailVerification bool      `json:"requires_email_verification"`
    SessionExpiresAt          time.Time `json:"session_expires_at"`
    StatusCode                int       `json:"-"`
    Error                     string    `json:"error,omitempty"`
}
```

**Status Codes:**
- `200` - Authentication successful
- `400` - Invalid request format
- `401` - Invalid credentials or account locked
- `403` - Account suspended or requires verification
- `500` - Internal server error

#### ValidateHandler

Token validation and user info retrieval.

```go
func (a *AuthService) ValidateHandler(r *http.Request) ValidateResponse
```

**Headers:**
```
Authorization: Bearer <session-token>
```

**Response:**
```go
type ValidateResponse struct {
    User       *User  `json:"user"`
    StatusCode int    `json:"-"`
    Error      string `json:"error,omitempty"`
}
```

### Password Management

#### ForgotPasswordHandler

Initiate password reset flow.

```go
func (a *AuthService) ForgotPasswordHandler(r *http.Request) ForgotPasswordResponse
```

**Request Body:**
```json
{
    "email": "user@example.com"
}
```

**Response:**
```go
type ForgotPasswordResponse struct {
    Message    string `json:"message"`
    StatusCode int    `json:"-"`
    Error      string `json:"error,omitempty"`
}
```

#### ResetPasswordHandler

Complete password reset with token.

```go
func (a *AuthService) ResetPasswordHandler(r *http.Request) ResetPasswordResponse
```

**Request Body:**
```json
{
    "token": "reset-token-here",
    "new_password": "newpassword123"
}
```

### Email Verification

#### VerifyEmailHandler

Verify email address with token.

```go
func (a *AuthService) VerifyEmailHandler(r *http.Request) EmailVerificationResponse
```

**Request Body:**
```json
{
    "token": "verification-token-here"
}
```

#### ResendVerificationHandler

Resend email verification.

```go
func (a *AuthService) ResendVerificationHandler(r *http.Request) EmailVerificationResponse
```

**Headers:**
```
Authorization: Bearer <session-token>
```

### Session Management

#### GetSessionsHandler

Get all user sessions.

```go
func (a *AuthService) GetSessionsHandler(r *http.Request) SessionsResponse
```

**Headers:**
```
Authorization: Bearer <session-token>
```

**Response:**
```go
type SessionsResponse struct {
    Sessions   []*Session `json:"sessions"`
    StatusCode int        `json:"-"`
    Error      string     `json:"error,omitempty"`
}
```

#### RevokeSessionHandler

Revoke specific session.

```go
func (a *AuthService) RevokeSessionHandler(r *http.Request, sessionID string) RevokeSessionResponse
```

#### RevokeAllSessionsHandler

Revoke all user sessions.

```go
func (a *AuthService) RevokeAllSessionsHandler(r *http.Request) RevokeSessionResponse
```

### OAuth Integration

#### OAuthHandler

Initiate OAuth flow.

```go
func (a *AuthService) OAuthHandler(w http.ResponseWriter, r *http.Request, provider string) OAuthResponse
```

**Parameters:**
- `provider` - OAuth provider name (google, github, discord, etc.)

#### OAuthCallbackHandler

Handle OAuth callback.

```go
func (a *AuthService) OAuthCallbackHandler(r *http.Request, provider, code, state string) OAuthResponse
```

**Response:**
```go
type OAuthResponse struct {
    Token      string `json:"token"`
    User       *User  `json:"user"`
    IsNewUser  bool   `json:"is_new_user"`
    StatusCode int    `json:"-"`
    Error      string `json:"error,omitempty"`
}
```

#### GetProvidersHandler

Get available OAuth providers.

```go
func (a *AuthService) GetProvidersHandler(r *http.Request) map[string][]string
```

**Response:**
```json
{
    "providers": ["google", "github", "discord"]
}
```

## 🎯 Referral System

### GenerateReferralCodeHandler

Generate new referral code.

```go
func (a *AuthService) GenerateReferralCodeHandler(r *http.Request) GenerateReferralCodeResponse
```

**Headers:**
```
Authorization: Bearer <session-token>
```

**Request Body:**
```json
{
    "tenant_id": 1,
    "max_uses": 5
}
```

**Response:**
```go
type GenerateReferralCodeResponse struct {
    Code        string     `json:"code"`
    MaxUses     int        `json:"max_uses"`
    ExpiresAt   *time.Time `json:"expires_at,omitempty"`
    StatusCode  int        `json:"-"`
    Error       string     `json:"error,omitempty"`
}
```

**Status Codes:**
- `201` - Code generated successfully
- `401` - Unauthorized
- `403` - Referral limit reached
- `500` - Internal server error

### GetMyReferralCodesHandler

Get user's generated referral codes.

```go
func (a *AuthService) GetMyReferralCodesHandler(r *http.Request) MyReferralCodesResponse
```

**Response:**
```go
type MyReferralCodesResponse struct {
    ReferralCodes []*ReferralCode `json:"referral_codes"`
    StatusCode    int             `json:"-"`
    Error         string          `json:"error,omitempty"`
}
```

### GetMyReferralsHandler

Get users referred by current user.

```go
func (a *AuthService) GetMyReferralsHandler(r *http.Request) MyReferralsResponse
```

### GetReferralStatsHandler

Get referral statistics.

```go
func (a *AuthService) GetReferralStatsHandler(r *http.Request) ReferralStatsResponse
```

**Response:**
```go
type ReferralStatsResponse struct {
    TotalReferred   int    `json:"total_referred"`
    ActiveReferrals int    `json:"active_referrals"`
    StatusCode      int    `json:"-"`
    Error           string `json:"error,omitempty"`
}
```

## 🛡️ Middleware

### RequireAuth

Authentication middleware for protected routes.

```go
func (a *AuthService) RequireAuth(config ...MiddlewareConfig) func(http.Handler) http.Handler
```

**Configuration:**
```go
type MiddlewareConfig struct {
    SkipPaths     []string `json:"skip_paths"`
    ErrorResponse func(w http.ResponseWriter, error string, statusCode int)
}
```

**Usage:**
```go
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuth())
    r.Get("/protected", protectedHandler)
})
```

**Context Values:**
- `auth.GetUserFromContext(ctx)` - Current user
- `auth.GetTenantFromContext(ctx)` - Current tenant
- `auth.MustGetUserFromContext(ctx)` - Current user (panics if not found)

### RequirePermission

Permission-based authorization middleware.

```go
func (a *AuthService) RequirePermission(resource, action string) func(http.Handler) http.Handler
```

**Usage:**
```go
r.Group(func(r chi.Router) {
    r.Use(authService.RequireAuth())
    r.Use(authService.RequirePermission("documents", "read"))
    r.Get("/documents", getDocumentsHandler)
})
```

## 📊 Data Types

### User

```go
type User struct {
    ID        uint   `json:"id"`
    Email     string `json:"email"`
    Username  string `json:"username"`
    FirstName string `json:"first_name"`
    LastName  string `json:"last_name"`

    PasswordHash string `json:"-"`
    AvatarURL    string `json:"avatar_url,omitempty"`
    Provider     string `json:"provider"`
    ProviderID   string `json:"provider_id"`

    // Email Security
    EmailVerified     bool       `json:"email_verified"`
    EmailVerifiedAt   *time.Time `json:"email_verified_at,omitempty"`
    VerificationToken string     `json:"-"`

    // Password Security
    PasswordResetToken     string     `json:"-"`
    PasswordResetExpiresAt *time.Time `json:"password_reset_expires_at,omitempty"`
    PasswordChangedAt      *time.Time `json:"password_changed_at,omitempty"`

    // Login Security
    LoginAttempts     int        `json:"login_attempts"`
    LastFailedLoginAt *time.Time `json:"last_failed_login_at,omitempty"`
    LockedUntil       *time.Time `json:"locked_until,omitempty"`
    LastLoginAt       *time.Time `json:"last_login_at,omitempty"`

    // Location & Device Tracking
    LastKnownIP       string `json:"last_known_ip,omitempty"`
    LastLoginLocation string `json:"last_login_location,omitempty"`

    // Two-Factor Authentication
    TwoFactorEnabled bool   `json:"two_factor_enabled"`
    TwoFactorSecret  string `json:"-"`
    BackupCodes      string `json:"-"`

    // Account Security
    IsActive      bool       `json:"is_active"`
    IsSuspended   bool       `json:"is_suspended"`
    SuspendedAt   *time.Time `json:"suspended_at,omitempty"`
    SuspendReason string     `json:"suspend_reason,omitempty"`

    // Referral System
    ReferredByCode string `json:"referred_by_code,omitempty"`
    DefaultRoleID  *uint  `json:"default_role_id,omitempty"`

    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

### Session

```go
type Session struct {
    ID        string    `json:"id"`
    UserID    uint      `json:"user_id"`
    Token     string    `json:"token"`
    ExpiresAt time.Time `json:"expires_at"`
    CSRF      string    `json:"csrf_token"`

    // Device & Location Tracking
    DeviceFingerprint string `json:"device_fingerprint"`
    UserAgent         string `json:"user_agent"`
    IPAddress         string `json:"ip_address"`
    Location          string `json:"location"`

    // Status
    IsActive          bool      `json:"is_active"`
    LastActivity      time.Time `json:"last_activity"`
    RequiresTwoFactor bool      `json:"requires_two_factor"`
    TwoFactorVerified bool      `json:"two_factor_verified"`

    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

### ReferralCode

```go
type ReferralCode struct {
    ID                  uint       `json:"id"`
    Code                string     `json:"code"`
    GeneratedByUserID   uint       `json:"generated_by_user_id"`
    GeneratedByRoleID   uint       `json:"generated_by_role_id"`
    TenantID            uint       `json:"tenant_id"`
    MaxUses             int        `json:"max_uses"`
    CurrentUses         int        `json:"current_uses"`
    ExpiresAt           *time.Time `json:"expires_at,omitempty"`
    IsActive            bool       `json:"is_active"`
    CreatedAt           time.Time  `json:"created_at"`
    UpdatedAt           time.Time  `json:"updated_at"`

    // Populated by joins
    GeneratedByUser *User   `json:"generated_by_user,omitempty"`
    GeneratedByRole *Role   `json:"generated_by_role,omitempty"`
    Tenant          *Tenant `json:"tenant,omitempty"`
}
```

## 🔧 OAuth Provider Configuration

### OAuthProviderConfig

```go
type OAuthProviderConfig struct {
    ClientID     string   `json:"client_id"`
    ClientSecret string   `json:"client_secret"`
    RedirectURL  string   `json:"redirect_url"`
    AuthURL      string   `json:"auth_url"`
    TokenURL     string   `json:"token_url"`
    Scopes       []string `json:"scopes"`
}
```

### Helper Functions

#### Built-in Providers

```go
// Google OAuth
func NewGoogleOAuthProvider(clientID, clientSecret, redirectURL string) OAuthProviderConfig

// GitHub OAuth
func NewGitHubOAuthProvider(clientID, clientSecret, redirectURL string) OAuthProviderConfig

// Discord OAuth
func NewDiscordOAuthProvider(clientID, clientSecret, redirectURL string) OAuthProviderConfig
```

#### Custom Providers

```go
func NewCustomOAuthProvider(
    clientID, clientSecret, redirectURL, authURL, tokenURL string,
    scopes []string
) OAuthProviderConfig
```

**Example:**
```go
OAuthProviders: map[string]auth.OAuthProviderConfig{
    "google": auth.NewGoogleOAuthProvider(
        "google-client-id",
        "google-client-secret",
        "http://localhost:8080/oauth/callback",
    ),
    "microsoft": auth.NewCustomOAuthProvider(
        "ms-client-id",
        "ms-client-secret",
        "http://localhost:8080/oauth/callback",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        []string{"openid", "profile", "email", "User.Read"},
    ),
}
```

## ✉️ Email Service Interface

```go
type EmailService interface {
    SendVerificationEmail(email, token string) error
    SendPasswordResetEmail(email, token string) error
    SendWelcomeEmail(email, name string) error
}
```

**Implementation Example:**
```go
type YourEmailService struct {
    smtpHost     string
    smtpPort     int
    smtpUsername string
    smtpPassword string
}

func (e *YourEmailService) SendVerificationEmail(email, token string) error {
    // Implement email sending logic
    return nil
}
```

## 🚨 Error Handling

### Common Errors

```go
var (
    ErrUserNotFound       = errors.New("user not found")
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrUserExists         = errors.New("user already exists")
    ErrInvalidProvider    = errors.New("invalid OAuth provider")
)
```

### Status Codes

| Code | Description | Common Causes |
|------|-------------|---------------|
| `200` | Success | Operation completed successfully |
| `201` | Created | User/resource created successfully |
| `400` | Bad Request | Invalid input, validation errors |
| `401` | Unauthorized | Invalid credentials, missing token |
| `403` | Forbidden | Insufficient permissions, account locked |
| `404` | Not Found | User/resource not found |
| `409` | Conflict | User already exists, duplicate data |
| `500` | Internal Error | Database error, service unavailable |

### Error Response Format

All handlers return errors in a consistent format:

```json
{
    "error": "Descriptive error message",
    "status_code": 400
}
```

This API reference provides comprehensive documentation for integrating and using the Wispy Auth library effectively.