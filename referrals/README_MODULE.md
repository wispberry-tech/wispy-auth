# Referrals Module - Independent Integration

The referrals module is a standalone module that provides referral functionality that can be integrated manually into your authentication flow. It does NOT extend or modify the core auth service - instead, it provides utilities and middleware that you can use in your route handlers.

## Key Features

- **Independent Module**: No coupling with core auth service
- **Manual Integration**: You control when and how referrals are processed
- **Flexible Usage**: Use utilities directly in your handlers
- **Optional Middleware**: Convenience middleware for common patterns

## Installation

```go
import (
    "github.com/wispberry-tech/wispy-auth/core"
    "github.com/wispberry-tech/wispy-auth/referrals"
    referralstorage "github.com/wispberry-tech/wispy-auth/referrals/storage"
)
```

## Quick Setup

```go
// Initialize storage (must implement both core.Storage and referrals.Storage)
storage, err := referralstorage.NewSQLiteStorage("app.db")
if err != nil {
    log.Fatal("Failed to create storage:", err)
}

// Initialize core auth service
coreConfig := core.Config{
    Storage:        storage,
    SecurityConfig: core.DefaultSecurityConfig(),
}
authService, err := core.NewAuthService(coreConfig)

// Initialize referrals module
referralsConfig := referrals.DefaultConfig()
referralsModule, err := referrals.NewReferralsModule(storage, referralsConfig)
referralsUtils := referralsModule.GetUtilities()
```

## Manual Integration Pattern (Recommended)

This is the primary way to integrate referrals into your signup flow:

```go
func signupWithReferralHandler(authService *core.AuthService, referralsUtils *referrals.Utilities) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req SignupRequest
        json.NewDecoder(r.Body).Decode(&req)
        
        var validReferral *referrals.ReferralCode
        var err error
        
        // Step 1: Check referral if provided
        if req.ReferralCode != "" {
            validReferral, err = referralsUtils.ValidateReferralCode(req.ReferralCode, 0)
            if err != nil {
                http.Error(w, "Invalid referral code: " + err.Error(), 400)
                return
            }
        } else if referralsUtils.IsReferralRequired() {
            http.Error(w, "Referral code is required", 400)
            return
        }
        
        // Step 2: Call core signup
        result := authService.SignUpHandler(r)
        if result.StatusCode != http.StatusCreated {
            w.WriteHeader(result.StatusCode)
            json.NewEncoder(w).Encode(result)
            return
        }
        
        // Step 3: Process referral after successful signup
        usedReferral := false
        if validReferral != nil {
            err = referralsUtils.ProcessReferralSignup(validReferral, result.User.ID)
            if err != nil {
                log.Printf("Failed to process referral: %v", err)
            } else {
                usedReferral = true
            }
        }
        
        // Step 4: Return success with referral info
        response := SignupResponse{
            Token:        result.Token,
            User:         result.User,
            UsedReferral: usedReferral,
            ReferralCode: validReferral,
        }
        
        w.WriteHeader(http.StatusCreated)
        json.NewEncoder(w).Encode(response)
    }
}
```

## Available Utilities

```go
// Core referral operations
func (u *Utilities) ValidateReferralCode(code string, userID uint) (*ReferralCode, error)
func (u *Utilities) ProcessReferralSignup(referralCode *ReferralCode, newUserID uint) error
func (u *Utilities) GenerateReferralCode(userID uint, options GenerateOptions) (*ReferralCode, error)

// Management operations
func (u *Utilities) GetUserReferralCodes(userID uint) ([]*ReferralCode, error)
func (u *Utilities) GetReferralStats(userID uint) (*ReferralStats, error)
func (u *Utilities) GetReferralRelationships(userID uint) ([]*ReferralRelationship, error)
func (u *Utilities) DeactivateReferralCode(userID, codeID uint) error

// Helper functions
func (u *Utilities) IsReferralRequired() bool
func (u *Utilities) ExtractReferralFromRequest(r *http.Request) string
```

## Configuration

```go
type Config struct {
    CodeLength          int           // Length of generated codes (default: 8)
    CodePrefix          string        // Optional prefix (e.g., "REF")
    AllowCustomCodes    bool          // Whether users can create custom codes
    MaxCodesPerUser     int           // Max codes per user (0 = unlimited)
    DefaultMaxUses      int           // Default max uses per code (0 = unlimited)
    RequireReferralCode bool          // Make referral codes mandatory
}

// Use default configuration
config := referrals.DefaultConfig()

// Or customize
config := referrals.Config{
    CodeLength:          6,
    CodePrefix:          "INVITE",
    RequireReferralCode: true,
    MaxCodesPerUser:     3,
}
```

## Benefits

1. **Complete Control**: You decide exactly when referrals are validated and processed
2. **No Magic**: Clear, explicit integration points in your code
3. **Error Handling**: You control how referral errors are handled
4. **Testable**: Easy to unit test your referral integration logic
5. **Flexible**: Works with any HTTP router or framework

## Storage Requirements

Your storage implementation must implement both `core.Storage` and `referrals.Storage` interfaces:

```go
type Storage interface {
    core.Storage // Embed all core storage methods
    
    // Referral-specific methods
    CreateReferralCode(code *ReferralCode) error
    GetReferralCodeByCode(code string) (*ReferralCode, error)
    ValidateReferralCode(code string) (*ReferralCode, error)
    // ... other referral methods
}
```

## Example Handlers

See `examples/referrals/main.go` for a complete working example showing:
- Signup with referral validation
- Referral code generation
- Statistics retrieval
- Error handling patterns