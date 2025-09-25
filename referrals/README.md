# Referrals Extension for Wispy Auth

A powerful referral system extension that builds on top of the Wispy Auth core library using clean composition patterns.

## Features

- 🎯 **Generate Referral Codes** - Create custom or auto-generated referral codes
- 📊 **Track Usage** - Monitor referral code usage and success rates
- 👥 **Referral Relationships** - Track who referred whom
- 🏆 **Leaderboards** - View top referrers with statistics
- ⚙️ **Flexible Configuration** - Customizable code formats, limits, and expiration
- 🔒 **Security First** - Prevent self-referrals and duplicate referrals
- 🚀 **Performance Optimized** - Efficient database queries with proper indexing

## Installation

```bash
go get github.com/wispberry-tech/wispy-auth/extensions/referrals
```

## Quick Start

```go
package main

import (
    "github.com/wispberry-tech/wispy-auth/core"
    "github.com/wispberry-tech/wispy-auth/core/storage"
    "github.com/wispberry-tech/wispy-auth/extensions/referrals"
    referralstorage "github.com/wispberry-tech/wispy-auth/extensions/referrals/storage"
)

func main() {
    // Create storage with referral support
    storage, _ := referralstorage.NewInMemorySQLiteStorage()
    defer storage.Close()

    // Create core auth service
    coreConfig := core.Config{
        Storage:        storage,
        SecurityConfig: core.DefaultSecurityConfig(),
    }
    coreAuth, _ := core.NewAuthService(coreConfig)

    // Configure referrals extension
    referralConfig := referrals.Config{
        CodeLength:          8,
        CodePrefix:          "REF",
        AllowCustomCodes:    true,
        MaxCodesPerUser:     5,
        RequireReferralCode: false,
    }

    // Create enhanced auth service
    authService := referrals.NewAuthService(coreAuth, storage, referralConfig)

    // Set up HTTP handlers
    mux := http.NewServeMux()

    // Enhanced signup with referral support
    mux.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
        result := authService.SignUpWithReferralHandler(r)
        w.WriteHeader(result.StatusCode)
        json.NewEncoder(w).Encode(result)
    })

    // Referral code generation (protected)
    mux.Handle("POST /referrals/generate",
        authService.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            result := authService.GenerateReferralCodeHandler(r)
            w.WriteHeader(result.StatusCode)
            json.NewEncoder(w).Encode(result)
        })))

    http.ListenAndServe(":8080", mux)
}
```

## API Endpoints

### Registration with Referrals
**POST `/signup`** - Enhanced registration with referral code support

```json
{
  "email": "user@example.com",
  "password": "SecurePass123",
  "first_name": "John",
  "last_name": "Doe",
  "referral_code": "REF12345678"
}
```

### Referral Management (Protected)
- **POST `/referrals/generate`** - Generate new referral code
- **GET `/referrals/codes`** - Get user's referral codes
- **GET `/referrals/stats`** - Get referral statistics
- **GET `/referrals/relationships`** - Get referral relationships
- **POST `/referrals/codes/{id}/deactivate`** - Deactivate referral code

### Public Endpoints
- **GET `/referrals/top`** - Get top referrers leaderboard

## Configuration Options

```go
type Config struct {
    // Code generation settings
    CodeLength        int           // Length of generated codes (default: 8)
    CodePrefix        string        // Optional prefix (e.g., "REF")
    AllowCustomCodes  bool          // Whether users can create custom codes

    // Usage limits
    MaxCodesPerUser   int           // Max referral codes per user (0 = unlimited)
    DefaultMaxUses    int           // Default max uses per code (0 = unlimited)
    DefaultExpiry     time.Duration // Default expiry duration (0 = never expires)

    // Requirements
    RequireReferralCode bool        // Make referral codes mandatory for signup
}
```

### Default Configuration
```go
config := referrals.DefaultConfig()
// CodeLength: 8, CodePrefix: "", AllowCustomCodes: false
// MaxCodesPerUser: 5, DefaultMaxUses: 0, DefaultExpiry: 0
// RequireReferralCode: false
```

## Storage Backends

The extension supports the same storage backends as the core library:

### SQLite (Development & Testing)
```go
// In-memory with referral support
storage, err := referralstorage.NewInMemorySQLiteStorage()

// File-based with referral support
storage, err := referralstorage.NewSQLiteStorage("./auth.db")
```

### PostgreSQL (Production)
```go
storage, err := referralstorage.NewPostgresStorage("postgresql://user:pass@localhost/db")
```

## Database Schema

The extension adds these tables to the core schema:

```sql
-- Referral codes with usage tracking
CREATE TABLE referral_codes (
    id SERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    generated_by INTEGER NOT NULL,
    max_uses INTEGER DEFAULT 0,
    current_uses INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (generated_by) REFERENCES users(id)
);

-- Referral relationships between users
CREATE TABLE referral_relationships (
    id SERIAL PRIMARY KEY,
    referrer_user_id INTEGER NOT NULL,
    referred_user_id INTEGER UNIQUE NOT NULL, -- One referrer per user
    referral_code_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (referrer_user_id) REFERENCES users(id),
    FOREIGN KEY (referred_user_id) REFERENCES users(id),
    FOREIGN KEY (referral_code_id) REFERENCES referral_codes(id)
);

-- Statistics view for performance
CREATE VIEW referral_stats AS
SELECT
    user_id,
    COUNT(referrals) as total_referred,
    COUNT(active_codes) as active_codes,
    SUM(code_uses) as total_codes_used
FROM users
LEFT JOIN referral_relationships ON users.id = referrals.referrer_user_id
LEFT JOIN referral_codes ON users.id = codes.generated_by
GROUP BY user_id;
```

## Example Usage Scenarios

### 1. Basic Referral Program
```go
// User generates a referral code
options := referrals.GenerateCodeOptions{
    MaxUses: 10, // Limited to 10 uses
}
code, err := authService.GenerateReferralCode(userID, options)

// New user signs up with referral code
// POST /signup with referral_code in body
// Automatically creates referral relationship
```

### 2. Custom Branded Codes
```go
// Allow custom codes with branding
config := referrals.Config{
    CodePrefix:       "MYAPP",
    AllowCustomCodes: true,
    CodeLength:       10,
}

// User creates custom code: "MYAPPSPECIAL2024"
options := referrals.GenerateCodeOptions{
    CustomCode: "SPECIAL2024", // Will become "MYAPPSPECIAL2024"
}
```

### 3. Time-Limited Campaigns
```go
// Create codes that expire in 30 days
expiry := time.Now().Add(30 * 24 * time.Hour)
options := referrals.GenerateCodeOptions{
    ExpiresAt: &expiry,
    MaxUses:   100,
}
code, err := authService.GenerateReferralCode(userID, options)
```

### 4. Mandatory Referrals
```go
// Require referral codes for all signups
config := referrals.Config{
    RequireReferralCode: true,
    DefaultMaxUses:      1, // Single-use codes
}

// Signup will fail without valid referral code
```

## Advanced Features

### Referral Statistics
```go
// Get detailed stats for a user
stats, err := authService.GetUserReferralStats(userID)
fmt.Printf("Total referred: %d\n", stats.TotalReferred)
fmt.Printf("Active codes: %d\n", stats.ActiveCodes)
fmt.Printf("Total uses: %d\n", stats.TotalCodesUsed)

// Get leaderboard
topReferrers, err := authService.GetTopReferrers(10)
```

### Referral Relationships
```go
// Get all users referred by a user
relationships, err := authService.GetReferralRelationships(userID)

for _, rel := range relationships {
    fmt.Printf("Referred user %d via code %s\n",
        rel.ReferredUserID, rel.ReferralCode.Code)
}
```

### Code Management
```go
// Get all codes for a user
codes, err := authService.GetUserReferralCodes(userID)

// Deactivate a code
err = authService.DeactivateReferralCode(userID, codeID)
```

## Architecture Pattern

This extension demonstrates the **composition + interface extension** pattern:

1. **Core Unchanged** - No modifications to the core library
2. **Interface Extension** - `referrals.Storage` extends `core.Storage`
3. **Service Composition** - `referrals.AuthService` wraps `core.AuthService`
4. **Clean Separation** - Referral logic is completely separate
5. **Type Safety** - Interfaces ensure compatibility

## Running the Example

```bash
cd extensions/referrals/example
go run main.go
```

Visit http://localhost:8080 for API documentation and example requests.

## Migration from Core

To add referrals to an existing core implementation:

1. **Replace storage** - Use referral-enabled storage
2. **Wrap auth service** - Compose with referrals extension
3. **Update signup** - Use enhanced signup handler
4. **Add endpoints** - Mount referral-specific routes

The core functionality remains unchanged, and existing users are unaffected.

## Best Practices

### Security
- ✅ Prevent self-referrals automatically
- ✅ Enforce one referrer per user
- ✅ Validate referral codes before use
- ✅ Track suspicious referral patterns

### Performance
- ✅ Use database views for statistics
- ✅ Index referral code lookups
- ✅ Batch referral relationship queries
- ✅ Cache top referrers if needed

### User Experience
- ✅ Clear error messages for invalid codes
- ✅ Show referral progress to users
- ✅ Provide referral analytics dashboard
- ✅ Make referrals optional by default

## License

MIT License - same as core library.