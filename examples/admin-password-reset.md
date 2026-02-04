# Admin Password Reset Example

This example demonstrates how to implement administrative password reset functionality using the wispy-auth library. This allows administrators to reset user passwords programmatically, which is useful for user management systems, support tools, and administrative interfaces.

## Overview

The `AdminResetPassword` method allows administrators to reset any user's password. Key features:

- Generates a secure temporary password
- Forces the user to change their password on next login
- Invalidates all existing user sessions for security
- Logs comprehensive security events
- Returns a temporary password for secure communication to the user

## Configuration

By default, user self-service password reset is **disabled** (`AllowUserPasswordReset: false`). This means users cannot reset their own passwords through the `/forgot-password` endpoint - only administrators can reset passwords.

### Enabling User Self-Service Password Reset

If you want to allow users to reset their own passwords, enable it in the configuration:

```go
config := core.Config{
    Storage: storage,
    SecurityConfig: core.SecurityConfig{
        AllowUserPasswordReset: true, // Allow users to reset their own passwords
        // ... other security settings
    },
}
```

When enabled, users can use the `/forgot-password` and `/reset-password` endpoints. When disabled, these endpoints return a 403 Forbidden error.

### Admin-Only Password Reset

For high-security applications where only administrators should manage passwords, keep `AllowUserPasswordReset: false` (the default).

## Implementation

### Basic Admin Password Reset

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/wispberry-tech/wispy-auth/core"
    "github.com/wispberry-tech/wispy-auth/core/storage"
)

func main() {
    // Initialize auth service (same as before)
    storage, err := storage.NewInMemorySQLiteStorage()
    if err != nil {
        log.Fatal("Failed to create storage:", err)
    }
    defer storage.Close()

    config := core.Config{
        Storage:        storage,
        SecurityConfig: core.DefaultSecurityConfig(),
        // Note: AllowUserPasswordReset is false by default, so users cannot
        // reset their own passwords. Only admins can reset passwords.
    }

    authService, err := core.NewAuthService(config)
    if err != nil {
        log.Fatal("Failed to create auth service:", err)
    }
    defer authService.Close()

    // Set up routes including admin functionality
    mux := http.NewServeMux()

    // Regular auth routes
    mux.HandleFunc("POST /signup", handleSignUp(authService))
    mux.HandleFunc("POST /signin", handleSignIn(authService))

    // Admin routes (protected)
    mux.Handle("POST /admin/reset-password", authService.AuthMiddleware(
        http.HandlerFunc(adminResetPasswordHandler(authService)),
    ))

    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", mux)
}

// adminResetPasswordHandler handles admin password reset requests
func adminResetPasswordHandler(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Get the current admin user from context
        adminUser := core.GetUserFromContext(r)
        if adminUser == nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Check if user is admin (application-level logic)
        if !isUserAdmin(adminUser) {
            http.Error(w, "Admin access required", http.StatusForbidden)
            return
        }

        // Parse request
        var req struct {
            TargetUserID uint `json:"target_user_id"`
        }

        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        // Perform admin password reset
        tempPassword, err := authService.AdminResetPassword(adminUser.ID, req.TargetUserID)
        if err != nil {
            log.Printf("Admin password reset failed: %v", err)
            http.Error(w, "Failed to reset password", http.StatusInternalServerError)
            return
        }

        // Return response with temporary password
        response := map[string]interface{}{
            "success":       true,
            "message":       "Password reset successfully",
            "temp_password": tempPassword, // Only return this securely!
            "target_user_id": req.TargetUserID,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}

// isUserAdmin checks if a user has admin privileges
// This is application-specific logic - implement based on your requirements
func isUserAdmin(user *core.User) bool {
    // Example implementations:

    // 1. Check against a hardcoded admin email
    // return user.Email == "admin@yourcompany.com"

    // 2. Check against a list of admin user IDs
    // adminUserIDs := []uint{1, 2, 3}
    // for _, id := range adminUserIDs {
    //     if user.ID == id {
    //         return true
    //     }
    // }
    // return false

    // 3. Check a custom field (would require extending the User struct)
    // return user.IsAdmin

    // For this example, we'll use a simple email check
    return user.Email == "admin@example.com"
}
```

### Advanced Example with Email Notification

```go
// adminResetPasswordWithEmailHandler includes email notification
func adminResetPasswordWithEmailHandler(authService *core.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        adminUser := core.GetUserFromContext(r)
        if adminUser == nil || !isUserAdmin(adminUser) {
            http.Error(w, "Unauthorized", http.StatusForbidden)
            return
        }

        var req struct {
            TargetUserID uint   `json:"target_user_id"`
            SendEmail    bool   `json:"send_email,omitempty"` // Option to send email
        }

        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        // Reset the password
        tempPassword, err := authService.AdminResetPassword(adminUser.ID, req.TargetUserID)
        if err != nil {
            log.Printf("Admin password reset failed: %v", err)
            http.Error(w, "Failed to reset password", http.StatusInternalServerError)
            return
        }

        // Get target user info for email
        targetUser, err := authService.GetStorage().GetUserByID(req.TargetUserID)
        if err != nil || targetUser == nil {
            http.Error(w, "User not found", http.StatusNotFound)
            return
        }

        response := map[string]interface{}{
            "success": true,
            "message": "Password reset successfully",
            "target_user_id": req.TargetUserID,
        }

        // Send email if requested (implement your email service)
        if req.SendEmail {
            err := sendPasswordResetEmail(targetUser.Email, tempPassword)
            if err != nil {
                log.Printf("Failed to send email: %v", err)
                response["email_sent"] = false
                response["email_error"] = err.Error()
            } else {
                response["email_sent"] = true
                // Don't include temp password in response if email was sent
            }
        } else {
            // Include temp password only if not sending email
            response["temp_password"] = tempPassword
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}

// sendPasswordResetEmail sends a password reset notification
func sendPasswordResetEmail(email, tempPassword string) error {
    // Implement your email sending logic here
    // This could use services like SendGrid, AWS SES, etc.

    subject := "Your Password Has Been Reset"
    body := fmt.Sprintf(`
Hello,

Your password has been reset by an administrator.

Your temporary password is: %s

Please log in with this temporary password and change it immediately.

For security reasons, you will be required to set a new password on your next login.

If you did not request this change, please contact support immediately.

Best regards,
Your Application Team
`, tempPassword)

    log.Printf("Would send email to %s: %s", email, body)
    // return yourEmailService.Send(email, subject, body)
    return nil
}
```

### Frontend Integration Example

```javascript
// Example frontend code for admin password reset
async function resetUserPassword(targetUserId) {
    try {
        const response = await fetch('/admin/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${adminToken}`
            },
            body: JSON.stringify({
                target_user_id: targetUserId,
                send_email: true
            })
        });

        const result = await response.json();

        if (result.success) {
            alert('Password reset successfully. User has been notified via email.');
        } else {
            alert('Failed to reset password: ' + result.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while resetting the password.');
    }
}
```

## Security Considerations

### Access Control
- Always verify admin permissions before calling `AdminResetPassword`
- Implement proper role-based access control (RBAC) in your application
- Log all admin actions for audit purposes

### Password Handling
- Temporary passwords are returned only once - store them securely
- Communicate temporary passwords through secure channels (email, secure messaging)
- Never log temporary passwords in plain text

### Session Management
- All existing user sessions are automatically invalidated
- Users must re-authenticate with the temporary password
- Users are forced to change their password on next login

### Audit Logging
- All admin password resets are logged as security events
- Both admin and target user actions are tracked
- Use the security event logs for compliance and monitoring

## API Reference

### AdminResetPassword Method

```go
func (a *AuthService) AdminResetPassword(adminUserID, targetUserID uint) (string, error)
```

**Parameters:**
- `adminUserID`: ID of the administrator performing the reset
- `targetUserID`: ID of the user whose password is being reset

**Returns:**
- `string`: Temporary password for the user
- `error`: Any error encountered during the reset

**Security Features:**
- Generates cryptographically secure temporary password
- Forces password change on next login
- Invalidates all existing sessions
- Logs security events for both admin and target user

## Error Handling

The method may return the following errors:
- `"target user not found"`: The specified user ID does not exist
- `"failed to get target user"`: Database error retrieving user
- `"failed to generate temporary password"`: Cryptographic error
- `"failed to hash temporary password"`: Password hashing error
- `"failed to update user password"`: Database error updating password
- `"failed to get user security"`: Database error retrieving security info
- `"failed to update user security"`: Database error updating security settings

## Best Practices

1. **Secure Communication**: Always send temporary passwords via email or secure channels
2. **Immediate Notification**: Inform users immediately when their password is reset
3. **Audit Everything**: Log all admin actions and monitor for suspicious activity
4. **Rate Limiting**: Implement rate limiting on admin endpoints
5. **Password Policies**: Ensure temporary passwords meet your security requirements
6. **User Experience**: Provide clear instructions for users on what to do after reset

## Integration with User Management Systems

This functionality integrates well with user management dashboards:

```go
// Example user management function
func resetUserPassword(adminID uint, userEmail string) error {
    // Get user by email
    user, err := authService.GetStorage().GetUserByEmail(userEmail, "email")
    if err != nil {
        return fmt.Errorf("user not found: %w", err)
    }

    // Reset password
    tempPassword, err := authService.AdminResetPassword(adminID, user.ID)
    if err != nil {
        return fmt.Errorf("password reset failed: %w", err)
    }

    // Send notification (implement based on your needs)
    return notifyUserOfPasswordReset(user.Email, tempPassword)
}
```

This admin password reset functionality provides a secure, auditable way for administrators to manage user accounts while maintaining the security principles of the wispy-auth library.