# Referral System Example

This example demonstrates the comprehensive referral system with role-based invitation limits and automatic user role assignment.

## Features Demonstrated

- ✅ Role-based referral code generation
- ✅ Configurable invitation limits per role
- ✅ Automatic default role assignment
- ✅ Referral code validation and tracking
- ✅ Referral statistics and analytics
- ✅ Admin role management
- ✅ Complete referral audit trail

## Running the Example

```bash
cd examples/referrals
go mod tidy
go run main.go
```

## Referral System Configuration

The example uses these role-based limits:
- **user**: 5 invitations maximum
- **premium**: 20 invitations maximum
- **admin**: 100 invitations maximum

Referral codes:
- **Format**: REF + 8 random characters
- **Expiry**: 30 days
- **Usage**: Configurable per code

## Testing the Referral Flow

### 1. Create First User (Alice)
```bash
curl -X POST http://localhost:8080/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123"}'
```

### 2. Sign In and Get Token
```bash
curl -X POST http://localhost:8080/signin \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Password123"}'
```

### 3. Generate Referral Code
```bash
curl -X POST http://localhost:8080/referrals/generate \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"max_uses":5}'
```

### 4. Sign Up with Referral Code (Bob)
```bash
curl -X POST http://localhost:8080/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"bob@example.com","password":"Password123","referral_code":"REF12345678"}'
```

### 5. Check Referral Statistics
```bash
curl -X GET http://localhost:8080/referrals/stats \
  -H 'Authorization: Bearer ALICE_TOKEN'
```

### 6. View All Referral Codes
```bash
curl -X GET http://localhost:8080/referrals/codes \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

### 7. View Referred Users
```bash
curl -X GET http://localhost:8080/referrals/users \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

## Admin Features

### Upgrade User Role (Increases Invitation Limit)
```bash
curl -X POST http://localhost:8080/admin/upgrade-user \
  -H 'Authorization: Bearer ADMIN_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"user_id":1,"role":"premium"}'
```

## Key Configuration Options

```go
SecurityConfig: auth.SecurityConfig{
    // Referral system settings
    RequireReferralCode: false,        // Set to true to require codes
    DefaultUserRoleName: "user",       // Default role for new users

    // Role-based invitation limits
    MaxInviteesPerRole: map[string]int{
        "user":     5,
        "premium":  20,
        "admin":    100,
    },

    // Code generation settings
    ReferralCodeLength: 8,
    ReferralCodePrefix: "REF",
    ReferralCodeExpiry: 30 * 24 * time.Hour,
}
```

## Referral Code Validation

The system automatically validates:
- ✅ Code exists and is active
- ✅ Code hasn't expired
- ✅ Code hasn't exceeded usage limit
- ✅ User hasn't already used this code
- ✅ Referrer has invitation capacity for their role

## Analytics Available

- Total users referred by each user
- Active vs used referral codes
- Referral success rates
- Role-based referral performance
- Complete referral relationship tree

## Security Features

- Referral codes are cryptographically secure
- Usage limits prevent abuse
- Role-based controls prevent unauthorized mass invitations
- Complete audit trail of all referral activities
- Automatic cleanup of expired codes