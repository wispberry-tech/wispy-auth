# Email Verification Module - Independent Integration

The email verification module is a standalone module that provides email verification functionality that can be integrated manually into your authentication flow. Like the referrals module, it does NOT extend or modify the core auth service - instead, it provides utilities that you can use in your route handlers.

## Key Features

- **🔗 Independent Module**: No coupling with core auth service
- **📧 Multiple Providers**: Support for Resend, SendGrid, Mailgun, Postmark, and custom providers (all via REST APIs)
- **📋 Template System**: Built-in templates with customization support using `text/template`
- **🛠️ Manual Integration**: You control when and how verification emails are sent
- **⚡ Flexible Usage**: Use utilities directly in your handlers
- **🔐 Secure Tokens**: Cryptographically secure verification tokens

## Installation

```go
import (
    "github.com/wispberry-tech/wispy-auth/core"
    "github.com/wispberry-tech/wispy-auth/verifyemail"
)
```

## Quick Setup

```go
// Initialize storage (must implement both core.Storage and verifyemail.Storage)
storage := yourstorage.NewStorage("connection_string")

// Initialize core auth service
coreConfig := core.Config{
    Storage:        storage,
    SecurityConfig: core.DefaultSecurityConfig(),
}
authService, err := core.NewAuthService(coreConfig)

// Initialize email verification module
verifyConfig := verifyemail.Config{
    BaseURL:      "https://yourapp.com",
    AppName:      "Your App",
    SupportEmail: "support@yourapp.com",
    Provider:     "resend",
    ProviderConfig: map[string]interface{}{
        "api_key": "your-resend-api-key",
    },
}

verifyModule, err := verifyemail.NewVerifyEmailModule(storage, verifyConfig)
verifyUtils := verifyModule.GetUtilities()
```

## Manual Integration Pattern (Recommended)

This is the primary way to integrate email verification into your signup flow:

```go
func signupWithEmailVerificationHandler(authService *core.AuthService, verifyUtils *verifyemail.Utilities) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req SignupRequest
        json.NewDecoder(r.Body).Decode(&req)
        
        // Step 1: Call core signup first
        result := authService.SignUpHandler(r)
        if result.StatusCode != http.StatusCreated {
            w.WriteHeader(result.StatusCode)
            json.NewEncoder(w).Encode(result)
            return
        }
        
        // Step 2: Send verification email after successful signup
        sendOptions := verifyemail.SendOptions{
            CustomData: map[string]interface{}{
                "welcome_message": "Welcome to our platform!",
            },
        }
        
        _, err := verifyUtils.SendVerificationEmail(result.User, sendOptions)
        if err != nil {
            // Log error but don't fail signup since user was created successfully
            log.Printf("Failed to send verification email: %v", err)
        }
        
        // Step 3: Return success with verification info
        response := SignupResponse{
            Token:            result.Token,
            User:             result.User,
            VerificationSent: err == nil,
        }
        
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(response)
    }
}
```

## Email Verification Handler

```go
func verifyEmailHandler(verifyUtils *verifyemail.Utilities) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := r.URL.Query().Get("token") // Or from JSON body
        
        verifyOptions := verifyemail.VerifyOptions{
            UpdateEmailStatus:   true, // Update user's email verification status
            DeleteTokenAfterUse: true, // Clean up token after use
        }
        
        verifiedToken, err := verifyUtils.VerifyEmail(token, verifyOptions)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        
        // Email verified successfully
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Email verified successfully!",
            "user_id": verifiedToken.UserID,
        })
    }
}
```

## Available Utilities

```go
// Core email verification operations
func (u *Utilities) SendVerificationEmail(user *core.User, options SendOptions) (*EmailVerificationToken, error)
func (u *Utilities) VerifyEmail(token string, options VerifyOptions) (*EmailVerificationToken, error)
func (u *Utilities) ValidateVerificationToken(token string) (*EmailVerificationToken, error)

// Management operations
func (u *Utilities) ResendVerificationEmail(user *core.User, options SendOptions) (*EmailVerificationToken, error)
func (u *Utilities) GetUserVerificationTokens(userID uint) ([]*EmailVerificationToken, error)
func (u *Utilities) CleanupExpiredTokens() error

// Token generation (for advanced use cases)
func (u *Utilities) GenerateVerificationToken(userID uint, email string, options SendOptions) (*EmailVerificationToken, error)
```

## Email Providers

### Resend (Default)
```go
config := verifyemail.Config{
    Provider: "resend",
    ProviderConfig: map[string]interface{}{
        "api_key": "re_xxx",
    },
}
```

### SendGrid
```go
config := verifyemail.Config{
    Provider: "sendgrid",
    ProviderConfig: map[string]interface{}{
        "api_key": "SG.xxx",
    },
}
```

### Mailgun
```go
config := verifyemail.Config{
    Provider: "mailgun",
    ProviderConfig: map[string]interface{}{
        "api_key": "key-xxx",
        "domain":  "mg.yourdomain.com",
    },
}
```

### Postmark
```go
config := verifyemail.Config{
    Provider: "postmark",
    ProviderConfig: map[string]interface{}{
        "api_key": "your-postmark-server-token",
    },
}
```

## Custom Email Templates

### Using Custom Template
```go
customTemplate := &verifyemail.EmailTemplate{
    Subject:   "Welcome! Verify your email for {{.AppName}}",
    FromEmail: "welcome@yourapp.com",
    FromName:  "{{.AppName}} Team",
    TextBody: `Hi {{.User.FirstName}},
    
Welcome to {{.AppName}}! Please verify your email:
{{.VerificationURL}}

{{.CustomData.welcome_message}}`,
    HTMLBody: `<h1>Welcome {{.User.FirstName}}!</h1>
<p>Please <a href="{{.VerificationURL}}">verify your email</a></p>
<p>{{.CustomData.welcome_message}}</p>`,
}

sendOptions := verifyemail.SendOptions{
    CustomTemplate: customTemplate,
    CustomData: map[string]interface{}{
        "welcome_message": "Thanks for joining our community!",
    },
}
```

### Available Template Variables
- `{{.User}}` - User object (ID, Email, FirstName, LastName, etc.)
- `{{.Token}}` - Verification token
- `{{.VerificationURL}}` - Complete verification URL
- `{{.ExpiresAt}}` - Token expiration time
- `{{.AppName}}` - Application name
- `{{.SupportEmail}}` - Support email address
- `{{.CustomData.key}}` - Any custom data passed

## Configuration Options

```go
type Config struct {
    // Token settings
    TokenLength      int           // Length of verification tokens (default: 32)
    TokenExpiry      time.Duration // How long tokens are valid (default: 24h)
    MaxTokensPerUser int           // Max active tokens per user (default: 3)

    // Email settings  
    BaseURL      string // Base URL for verification links
    VerifyPath   string // Path for verification endpoint (default: "/verify-email")
    AppName      string // Application name for emails
    SupportEmail string // Support email address

    // Template settings
    DefaultTemplate  EmailTemplate // Default email template
    UseHTMLTemplate  bool          // Whether to use HTML templates

    // Provider settings
    Provider       string                 // Email provider (resend, sendgrid, mailgun, postmark)
    ProviderConfig map[string]interface{} // Provider-specific config
}
```

## Benefits

1. **🔗 Complete Independence**: No coupling with core auth service
2. **🎛️ Full Control**: Developer controls exactly when verification emails are sent
3. **📧 Multi-Provider**: Easy switching between email providers
4. **📋 Flexible Templates**: Custom templates with rich data binding
5. **🧪 Testable**: Easy to unit test email verification logic separately
6. **🔐 Secure**: Cryptographically secure tokens with expiration

## Storage Requirements

Your storage implementation must implement both `core.Storage` and `verifyemail.Storage` interfaces:

```go
type Storage interface {
    core.Storage // Embed all core storage methods
    
    // Email verification methods
    CreateEmailVerificationToken(token *EmailVerificationToken) error
    GetEmailVerificationTokenByToken(token string) (*EmailVerificationToken, error)
    ValidateEmailVerificationToken(token string) (*EmailVerificationToken, error)
    // ... other verification methods
}
```

## Example Usage Flow

1. **Signup**: User signs up → Core creates user → Send verification email
2. **Email Sent**: User receives email with verification link
3. **Verification**: User clicks link → Verify token → Update user status
4. **Cleanup**: Optional token cleanup after verification

The module handles all the complexity of token generation, email templating, provider management, and verification logic while giving you complete control over the integration points.