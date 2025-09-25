package main

import (
	"log"
	"net/http"

	"github.com/wispberry-tech/wispy-auth/core"
	"github.com/wispberry-tech/wispy-auth/verifyemail"
)

func main() {
	// Initialize core auth service (assuming you have storage)
	// In a real app, you'd initialize your storage implementation
	var storage verifyemail.Storage // This would be your actual storage implementation

	// Configure email verification module with REST API provider
	verifyConfig := verifyemail.Config{
		Provider: "resend", // or "sendgrid", "mailgun"
		ProviderConfig: map[string]interface{}{
			"api_key": "re_your_api_key_here",
		},
		BaseURL:      "https://yourapp.com",
		VerifyPath:   "/verify-email",
		AppName:      "Your App Name",
		SupportEmail: "support@yourapp.com",
	}

	// Initialize verification module
	verifyModule, err := verifyemail.NewVerifyEmailModule(storage, verifyConfig)
	if err != nil {
		log.Fatal("Failed to initialize verify email module:", err)
	}
	utils := verifyModule.GetUtilities()

	// Set up routes
	http.HandleFunc("/signup", signupHandler(utils))
	http.HandleFunc("/verify-email", verifyEmailHandler(utils))
	http.HandleFunc("/resend-verification", resendVerificationHandler(utils))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Example signup handler with email verification
func signupHandler(verifyUtils *verifyemail.Utilities) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Handle core signup (implement your own signup logic)
		user := &core.User{
			ID:        1,
			Email:     "user@example.com",
			FirstName: "John",
		}

		// Step 2: Send verification email
		_, err := verifyUtils.SendVerificationEmail(user, verifyemail.SendOptions{
			CustomData: map[string]interface{}{
				"welcome_message": "Welcome to our platform!",
			},
		})

		if err != nil {
			log.Printf("Failed to send verification email: %v", err)
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Account created! Please check your email for verification link."))
	}
}

// Example verification handler
func verifyEmailHandler(verifyUtils *verifyemail.Utilities) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Token required", http.StatusBadRequest)
			return
		}

		verificationToken, err := verifyUtils.VerifyEmail(token, verifyemail.VerifyOptions{})
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		w.Write([]byte("Email verified successfully for " + verificationToken.Email))
	}
}

// Example resend verification handler
func resendVerificationHandler(verifyUtils *verifyemail.Utilities) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := getUserIDFromRequest(r) // Implement based on your auth

		user, err := getUserByID(userID) // Implement based on your user service
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		_, err = verifyUtils.ResendVerificationEmail(user, verifyemail.SendOptions{})
		if err != nil {
			http.Error(w, "Failed to resend verification email", http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Verification email sent"))
	}
}

// Helper functions (implement based on your needs)
func getUserIDFromRequest(r *http.Request) uint {
	// Extract user ID from JWT token or session
	return 1 // placeholder
}

func getUserByID(userID uint) (*core.User, error) {
	// Fetch user from your storage
	return &core.User{ID: userID, Email: "user@example.com"}, nil // placeholder
}
