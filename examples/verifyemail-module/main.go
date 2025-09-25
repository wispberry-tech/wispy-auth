package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/wispberry-tech/wispy-auth/core"
	// "github.com/wispberry-tech/wispy-auth/verifyemail"
	// Note: You would need storage implementations that support both core and verifyemail
	// For now, this is a conceptual example
)

// SignupRequest represents the signup request
type SignupRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// SignupResponse represents the signup response
type SignupResponse struct {
	Token            string     `json:"token"`
	User             *core.User `json:"user"`
	VerificationSent bool       `json:"verification_sent"`
	Error            string     `json:"error,omitempty"`
}

// VerifyEmailRequest represents email verification request
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmailResponse represents email verification response
type VerifyEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

func main() {
	// Initialize storage (conceptual - you need actual implementation)
	// storage := yourstorage.NewStorage("connection_string")

	// Initialize core auth service
	coreConfig := core.Config{
		// storage:        storage,
		SecurityConfig: core.DefaultSecurityConfig(),
	}
	authService, err := core.NewAuthService(coreConfig)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}

	// Initialize email verification module
	// Note: This would fail without proper storage implementation that implements verifyemail.Storage
	/*
		verifyConfig := verifyemail.Config{
			BaseURL:      "http://localhost:8080",
			AppName:      "My App",
			SupportEmail: "support@myapp.com",
			Provider:     "resend",
			ProviderConfig: map[string]interface{}{
				"api_key": "your-resend-api-key",
			},
		}

		verifyModule, err := verifyemail.NewVerifyEmailModule(storage, verifyConfig)
		if err != nil {
			log.Fatal("Failed to create email verification module:", err)
		}
		defer verifyModule.Close()

		// Get utilities for manual integration
		verifyUtils := verifyModule.GetUtilities()
	*/

	// Setup routes with manual email verification integration
	http.HandleFunc("/signup", signupWithEmailVerificationHandler(authService /* , verifyUtils */))
	http.HandleFunc("/verify-email", verifyEmailHandler( /* verifyUtils */ ))
	http.HandleFunc("/resend-verification", resendVerificationHandler( /* verifyUtils */ ))

	log.Println("Server starting on :8080")
	log.Println("Example endpoints:")
	log.Println("POST /signup - Sign up and send verification email")
	log.Println("POST /verify-email - Verify email with token")
	log.Println("POST /resend-verification - Resend verification email")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// signupWithEmailVerificationHandler demonstrates manual integration pattern
func signupWithEmailVerificationHandler(authService *core.AuthService /*, verifyUtils *verifyemail.Utilities*/) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SignupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(SignupResponse{Error: "Invalid request format"})
			return
		}

		// STEP 1: Call core signup first
		result := authService.SignUpHandler(r)
		if result.StatusCode != http.StatusCreated {
			// Forward the core signup error
			w.WriteHeader(result.StatusCode)
			json.NewEncoder(w).Encode(SignupResponse{Error: result.Error})
			return
		}

		// STEP 2: Send verification email after successful signup
		verificationSent := false
		/*
			// This is how it would work with actual implementation:

			sendOptions := verifyemail.SendOptions{
				CustomData: map[string]interface{}{
					"welcome_message": "Welcome to our platform!",
				},
			}

			_, err := verifyUtils.SendVerificationEmail(result.User, sendOptions)
			if err != nil {
				// Log error but don't fail the signup since user was created successfully
				log.Printf("Failed to send verification email: %v", err)
			} else {
				verificationSent = true
				log.Printf("Verification email sent to %s", result.User.Email)
			}
		*/

		// For this example, we'll just simulate it
		verificationSent = true

		// STEP 3: Return success response with verification info
		response := SignupResponse{
			Token:            result.Token,
			User:             result.User,
			VerificationSent: verificationSent,
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}
}

// verifyEmailHandler demonstrates email verification
func verifyEmailHandler( /*verifyUtils *verifyemail.Utilities*/ ) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(VerifyEmailResponse{
				Success: false,
				Error:   "Invalid request format",
			})
			return
		}

		/*
			// This is how it would work with actual implementation:

			verifyOptions := verifyemail.VerifyOptions{
				UpdateEmailStatus:   true, // Update user's email verification status
				DeleteTokenAfterUse: true, // Clean up token after use
			}

			verifiedToken, err := verifyUtils.VerifyEmail(req.Token, verifyOptions)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(VerifyEmailResponse{
					Success: false,
					Error:   err.Error(),
				})
				return
			}

			log.Printf("Email verified successfully for user %d", verifiedToken.UserID)
		*/

		// For this example, we'll just simulate success
		response := VerifyEmailResponse{
			Success: true,
			Message: "Email verified successfully!",
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// resendVerificationHandler demonstrates resending verification emails
func resendVerificationHandler( /*verifyUtils *verifyemail.Utilities*/ ) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In a real app, get user from authentication
		// user := getUserFromAuth(r)

		/*
			// This is how it would work with actual implementation:

			sendOptions := verifyemail.SendOptions{
				CustomTemplate: &verifyemail.EmailTemplate{
					Subject: "Resend: Verify your email for {{.AppName}}",
					// ... custom template
				},
			}

			_, err := verifyUtils.ResendVerificationEmail(user, sendOptions)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": err.Error(),
				})
				return
			}
		*/

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Verification email sent successfully",
		})
	}
}
