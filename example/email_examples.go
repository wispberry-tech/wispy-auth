package main

import (
	"fmt"
	"os"

	// Example email service integrations
	// Uncomment the ones you want to use and add them to go.mod

	// SendGrid
	// "github.com/sendgrid/sendgrid-go"
	// "github.com/sendgrid/sendgrid-go/helpers/mail"

	// Mailgun
	// "github.com/mailgun/mailgun-go/v4"

	// AWS SES
	// "github.com/aws/aws-sdk-go/aws"
	// "github.com/aws/aws-sdk-go/aws/session"
	// "github.com/aws/aws-sdk-go/service/ses"
)

// Example SendGrid implementation
type SendGridEmailService struct {
	// client *sendgrid.Client
	fromEmail string
	fromName  string
}

func NewSendGridEmailService() EmailService {
	return &SendGridEmailService{
		// client:    sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY")),
		fromEmail: os.Getenv("FROM_EMAIL"),
		fromName:  os.Getenv("FROM_NAME"),
	}
}

func (s *SendGridEmailService) SendVerificationEmail(email, token string) error {
	// Example SendGrid implementation
	/*
	from := mail.NewEmail(s.fromName, s.fromEmail)
	to := mail.NewEmail("", email)
	subject := "Verify Your Email Address"
	
	// HTML content with verification link
	htmlContent := fmt.Sprintf(`
		<div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif;">
			<h2>Verify Your Email Address</h2>
			<p>Thank you for signing up! Please click the button below to verify your email address:</p>
			<a href="https://yourapp.com/verify-email?token=%s" 
			   style="display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px;">
				Verify Email Address
			</a>
			<p>If the button doesn't work, copy and paste this link into your browser:</p>
			<p><a href="https://yourapp.com/verify-email?token=%s">https://yourapp.com/verify-email?token=%s</a></p>
			<p>This link will expire in 24 hours.</p>
		</div>
	`, token, token, token)

	message := mail.NewSingleEmail(from, subject, to, "", htmlContent)
	
	response, err := s.client.Send(message)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}
	
	if response.StatusCode >= 400 {
		return fmt.Errorf("sendgrid error: %s", response.Body)
	}
	*/

	// Mock implementation for now
	fmt.Printf("📧 [SendGrid Mock] Verification email sent to %s\n", email)
	return nil
}

func (s *SendGridEmailService) SendPasswordResetEmail(email, token string) error {
	// Similar implementation for password reset
	fmt.Printf("📧 [SendGrid Mock] Password reset email sent to %s\n", email)
	return nil
}

func (s *SendGridEmailService) SendWelcomeEmail(email, name string) error {
	// Welcome email implementation
	fmt.Printf("📧 [SendGrid Mock] Welcome email sent to %s (%s)\n", email, name)
	return nil
}

// Example Mailgun implementation
type MailgunEmailService struct {
	// client *mailgun.MailgunImpl
	domain string
	from   string
}

func NewMailgunEmailService() EmailService {
	return &MailgunEmailService{
		// client: mailgun.NewMailgun(os.Getenv("MAILGUN_DOMAIN"), os.Getenv("MAILGUN_API_KEY")),
		domain: os.Getenv("MAILGUN_DOMAIN"),
		from:   os.Getenv("FROM_EMAIL"),
	}
}

func (m *MailgunEmailService) SendVerificationEmail(email, token string) error {
	// Example Mailgun implementation
	/*
	subject := "Verify Your Email Address"
	htmlContent := fmt.Sprintf(`
		<h2>Verify Your Email Address</h2>
		<p>Please click <a href="https://yourapp.com/verify-email?token=%s">here</a> to verify your email.</p>
	`, token)

	message := m.client.NewMessage(m.from, subject, "", email)
	message.SetHtml(htmlContent)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, _, err := m.client.Send(ctx, message)
	return err
	*/

	fmt.Printf("📧 [Mailgun Mock] Verification email sent to %s\n", email)
	return nil
}

func (m *MailgunEmailService) SendPasswordResetEmail(email, token string) error {
	fmt.Printf("📧 [Mailgun Mock] Password reset email sent to %s\n", email)
	return nil
}

func (m *MailgunEmailService) SendWelcomeEmail(email, name string) error {
	fmt.Printf("📧 [Mailgun Mock] Welcome email sent to %s (%s)\n", email, name)
	return nil
}

// Example AWS SES implementation
type SESEmailService struct {
	// client *ses.SES
	from string
}

func NewSESEmailService() EmailService {
	return &SESEmailService{
		// client: ses.New(session.Must(session.NewSession())),
		from: os.Getenv("FROM_EMAIL"),
	}
}

func (s *SESEmailService) SendVerificationEmail(email, token string) error {
	// Example AWS SES implementation
	/*
	subject := "Verify Your Email Address"
	htmlContent := fmt.Sprintf(`
		<h2>Verify Your Email Address</h2>
		<p>Please click <a href="https://yourapp.com/verify-email?token=%s">here</a> to verify your email.</p>
	`, token)

	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{aws.String(email)},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Data: aws.String(htmlContent),
				},
			},
			Subject: &ses.Content{
				Data: aws.String(subject),
			},
		},
		Source: aws.String(s.from),
	}

	_, err := s.client.SendEmail(input)
	return err
	*/

	fmt.Printf("📧 [AWS SES Mock] Verification email sent to %s\n", email)
	return nil
}

func (s *SESEmailService) SendPasswordResetEmail(email, token string) error {
	fmt.Printf("📧 [AWS SES Mock] Password reset email sent to %s\n", email)
	return nil
}

func (s *SESEmailService) SendWelcomeEmail(email, name string) error {
	fmt.Printf("📧 [AWS SES Mock] Welcome email sent to %s (%s)\n", email, name)
	return nil
}

// Factory function to create the appropriate email service
func createEmailService() EmailService {
	emailProvider := os.Getenv("EMAIL_PROVIDER")
	
	switch emailProvider {
	case "sendgrid":
		return NewSendGridEmailService()
	case "mailgun":
		return NewMailgunEmailService() 
	case "ses":
		return NewSESEmailService()
	default:
		return NewEmailService() // Default mock service
	}
}

/*
To use real email services, add these dependencies to go.mod:

// For SendGrid:
require github.com/sendgrid/sendgrid-go v3.12.0+incompatible

// For Mailgun:
require github.com/mailgun/mailgun-go/v4 v4.8.1

// For AWS SES:
require github.com/aws/aws-sdk-go v1.44.0

And set these environment variables:

# For SendGrid:
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=your-sendgrid-api-key
FROM_EMAIL=noreply@yourapp.com
FROM_NAME=Your App Name

# For Mailgun:
EMAIL_PROVIDER=mailgun
MAILGUN_DOMAIN=your-mailgun-domain.com
MAILGUN_API_KEY=your-mailgun-api-key
FROM_EMAIL=noreply@yourapp.com

# For AWS SES:
EMAIL_PROVIDER=ses
FROM_EMAIL=noreply@yourapp.com
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
*/