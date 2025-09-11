package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/go-playground/validator/v10"
	auth "github.com/wispberry-tech/wispy-auth"
)

// Custom context key type to avoid collisions
type contextKey string

const (
	userContextKey contextKey = "user"
)

// EmailService interface for sending emails
type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
	SendWelcomeEmail(email, name string) error
}

// MockEmailService - replace with your actual email service
type MockEmailService struct{}

func NewEmailService() EmailService {
	return &MockEmailService{}
}

func (m *MockEmailService) SendVerificationEmail(email, token string) error {
	log.Printf("📧 [MOCK] Sending verification email to %s", email)
	log.Printf("    Verification URL: http://localhost:3000/verify-email?token=%s", url.QueryEscape(token))
	
	// Here you would integrate with your email service:
	// - SendGrid: https://github.com/sendgrid/sendgrid-go
	// - Mailgun: https://github.com/mailgun/mailgun-go
	// - AWS SES: https://github.com/aws/aws-sdk-go
	// 
	// Example with SendGrid:
	// return m.sendGridClient.Send(ctx, &mail.SGMailV3{
	//     From: &mail.Email{Email: "noreply@yourapp.com", Name: "Your App"},
	//     To: []*mail.Email{{Email: email}},
	//     Subject: "Verify Your Email",
	//     Content: []*mail.Content{{
	//         Type:  "text/html",
	//         Value: fmt.Sprintf(`<a href="https://yourapp.com/verify?token=%s">Verify Email</a>`, token),
	//     }},
	// })
	
	return nil
}

func (m *MockEmailService) SendPasswordResetEmail(email, token string) error {
	log.Printf("📧 [MOCK] Sending password reset email to %s", email)
	log.Printf("    Reset URL: http://localhost:3000/reset-password?token=%s", url.QueryEscape(token))
	
	// Production implementation would include:
	// - Secure reset link with proper token
	// - Expiration time display
	// - HTML template with styling
	// - Security warnings/instructions
	
	return nil
}

func (m *MockEmailService) SendWelcomeEmail(email, name string) error {
	log.Printf("📧 [MOCK] Sending welcome email to %s (%s)", email, name)
	return nil
}

// Request validation structs with proper validation tags
type SignUpRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Name     string `json:"name" validate:"required,min=2,max=100"`
}

type SignInRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=1,max=128"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email,max=255"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required,min=10,max=255"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required,min=10,max=255"`
}

// Validator instance
var validate *validator.Validate

func init() {
	validate = validator.New()
	
	// Register custom validations if needed
	validate.RegisterValidation("password", validatePassword)
}

// Custom password validation
func validatePassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	if len(password) < 8 {
		return false
	}
	
	// Add more password complexity rules here
	// hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	// for _, char := range password {
	//     switch {
	//     case unicode.IsUpper(char):
	//         hasUpper = true
	//     case unicode.IsLower(char):
	//         hasLower = true
	//     case unicode.IsDigit(char):
	//         hasDigit = true
	//     case unicode.IsPunct(char) || unicode.IsSymbol(char):
	//         hasSpecial = true
	//     }
	// }
	// return hasUpper && hasLower && hasDigit
	
	return true
}

// Helper function to validate request and return errors
func validateRequest(req interface{}) map[string]string {
	err := validate.Struct(req)
	if err == nil {
		return nil
	}

	errors := make(map[string]string)
	for _, err := range err.(validator.ValidationErrors) {
		field := err.Field()
		switch err.Tag() {
		case "required":
			errors[field] = fmt.Sprintf("%s is required", field)
		case "email":
			errors[field] = "Invalid email format"
		case "min":
			errors[field] = fmt.Sprintf("%s must be at least %s characters", field, err.Param())
		case "max":
			errors[field] = fmt.Sprintf("%s must not exceed %s characters", field, err.Param())
		case "password":
			errors[field] = "Password must be at least 8 characters with uppercase, lowercase, and digits"
		default:
			errors[field] = fmt.Sprintf("%s is invalid", field)
		}
	}
	
	return errors
}

// Helper to send validation errors
func sendValidationErrors(w http.ResponseWriter, errors map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "Validation failed",
		"errors": errors,
	})
}

// Helper to convert auth requests
func convertToAuthSignUpRequest(req SignUpRequest) auth.SignUpRequest {
	return auth.SignUpRequest{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
	}
}

func convertToAuthSignInRequest(req SignInRequest) auth.SignInRequest {
	return auth.SignInRequest{
		Email:    req.Email,
		Password: req.Password,
	}
}

func convertToAuthForgotPasswordRequest(req ForgotPasswordRequest) auth.ForgotPasswordRequest {
	return auth.ForgotPasswordRequest{
		Email: req.Email,
	}
}

func convertToAuthResetPasswordRequest(req ResetPasswordRequest) auth.ResetPasswordRequest {
	return auth.ResetPasswordRequest{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	}
}

func convertToAuthVerifyEmailRequest(req VerifyEmailRequest) auth.VerifyEmailRequest {
	return auth.VerifyEmailRequest{
		Token: req.Token,
	}
}