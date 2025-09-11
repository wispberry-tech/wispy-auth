package main

import (
	"log"
	"net/url"
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

