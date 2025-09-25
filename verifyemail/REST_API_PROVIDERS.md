# Email Verification Module - REST API Providers

## Overview

The Email Verification module has been updated to focus exclusively on REST API providers, removing SMTP support in favor of modern, reliable email service APIs.

## Supported Providers (All REST API)

### 1. **Resend** (Recommended)
- Modern email API with excellent deliverability
- Simple integration
- Good pricing for startups

```go
config := verifyemail.Config{
    Provider: "resend",
    ProviderConfig: map[string]interface{}{
        "api_key": "re_your_api_key_here",
    },
}
```

### 2. **SendGrid** 
- Enterprise-grade email service
- Advanced analytics and tracking
- Proven scalability

```go
config := verifyemail.Config{
    Provider: "sendgrid",
    ProviderConfig: map[string]interface{}{
        "api_key": "SG.your_api_key_here",
    },
}
```

### 3. **Mailgun**
- Developer-focused email API
- Powerful routing and validation
- EU and US regions available

```go
config := verifyemail.Config{
    Provider: "mailgun",
    ProviderConfig: map[string]interface{}{
        "api_key": "key-your_api_key_here",
        "domain":  "mg.yourdomain.com",
    },
}
```

### 4. **Postmark**
- Focus on transactional emails
- Excellent deliverability rates
- Simple, clean API

```go
config := verifyemail.Config{
    Provider: "postmark",
    ProviderConfig: map[string]interface{}{
        "api_key": "your-postmark-server-token",
    },
}
```

## Why REST APIs Over SMTP?

1. **Reliability**: REST APIs handle retries, queue management, and failover automatically
2. **Features**: Rich features like analytics, templates, A/B testing, bounce handling
3. **Performance**: Faster delivery with optimized infrastructure
4. **Security**: No need to handle SMTP authentication or TLS complexities
5. **Monitoring**: Built-in delivery tracking, open rates, click tracking
6. **Compliance**: Providers handle spam compliance, DKIM, SPF automatically

## Adding New Providers

To add a new REST API email provider:

1. **Create Provider Implementation**:
```go
type YourProvider struct {
    apiKey string
    client *http.Client
}

func NewYourProvider(config map[string]interface{}) (EmailProvider, error) {
    // Implementation
}

func (p *YourProvider) SendEmail(ctx context.Context, message *EmailMessage) error {
    // REST API call to your provider
}
```

2. **Register Provider**:
```go
func init() {
    RegisterEmailProvider("yourprovider", NewYourProvider)
}
```

3. **Update Documentation**: Add configuration example and usage notes

## Module Architecture

The module maintains the same independent architecture:
- **No Core Coupling**: Works independently from the auth core
- **Manual Integration**: Developers call utilities directly in route handlers
- **Storage Interface**: Extends core.Storage with email verification methods
- **Provider Pattern**: Pluggable email providers with factory registration
- **Template Engine**: text/template for email rendering with custom data

## Example Usage

```go
// Initialize module with any REST API provider
verifyModule, err := verifyemail.NewVerifyEmailModule(storage, verifyemail.Config{
    Provider: "resend", // or "sendgrid", "mailgun", "postmark"
    ProviderConfig: map[string]interface{}{
        "api_key": "your_api_key",
    },
    BaseURL:      "https://yourapp.com",
    VerifyPath:   "/verify-email", 
    AppName:      "Your App",
    SupportEmail: "support@yourapp.com",
})

// Use in signup handler
utils := verifyModule.GetUtilities()
_, err := utils.SendVerificationEmail(user, verifyemail.SendOptions{
    CustomData: map[string]interface{}{
        "welcome_message": "Welcome to our platform!",
    },
})
```

## Benefits of This Design

1. **Developer Choice**: Pick the email provider that fits your needs and budget
2. **Easy Migration**: Switch providers by changing configuration
3. **Reliability**: Leverage provider infrastructure for delivery guarantees
4. **Features**: Access to provider-specific features (analytics, templates, etc.)
5. **Maintenance**: No complex SMTP connection management
6. **Scaling**: Providers handle volume scaling automatically

## Future Enhancements

Potential additions for REST API providers:
- Amazon SES
- Mailjet 
- ConvertKit
- Customer.io
- Loops
- Brevo (formerly Sendinblue)

The provider pattern makes it easy to add any REST API-based email service.