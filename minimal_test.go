package auth

import (
	"testing"
	"time"

	"github.com/wispberry-tech/wispy-auth/storage"
)

// Simple MockEmailService for testing
type TestEmailService struct{}

func (t *TestEmailService) SendVerificationEmail(email, token string) error {
	return nil
}

func (t *TestEmailService) SendPasswordResetEmail(email, token string) error {
	return nil
}

func (t *TestEmailService) SendWelcomeEmail(email, name string) error {
	return nil
}

func (t *TestEmailService) Send2FACode(email, code string) error {
	return nil
}

func (t *TestEmailService) Send2FAEnabled(email string) error {
	return nil
}

func (t *TestEmailService) Send2FADisabled(email string) error {
	return nil
}

func TestBasicAuthService(t *testing.T) {
	// Create in-memory storage
	sqliteStorage, err := storage.NewInMemorySQLiteStorage()
	if err != nil {
		t.Fatal("Failed to create storage:", err)
	}

	// Create config
	config := Config{
		Storage:      sqliteStorage,
		EmailService: &TestEmailService{},
		SecurityConfig: SecurityConfig{
			PasswordMinLength:        8,
			RequireEmailVerification: false,
			DefaultUserRoleName:      "user",
			SessionLifetime:          24 * time.Hour,
		},
	}

	// Test creating auth service
	authService, err := NewAuthService(config)
	if err != nil {
		t.Fatal("Failed to create auth service:", err)
	}

	if authService == nil {
		t.Error("AuthService should not be nil")
	}

	// Test that storage is properly initialized
	if authService.storage == nil {
		t.Error("Storage should be initialized")
	}

	// Test that email service is properly initialized
	if authService.emailService == nil {
		t.Error("Email service should be initialized")
	}
}

func TestStorageCreation(t *testing.T) {
	// Test in-memory SQLite storage creation
	storage, err := storage.NewInMemorySQLiteStorage()
	if err != nil {
		t.Fatal("Failed to create in-memory storage:", err)
	}

	if storage == nil {
		t.Error("Storage should not be nil")
	}
}

func TestEmailServiceMock(t *testing.T) {
	emailService := &TestEmailService{}

	// Test that all email methods work without error
	err := emailService.SendVerificationEmail("test@example.com", "token123")
	if err != nil {
		t.Error("SendVerificationEmail should not return error:", err)
	}

	err = emailService.SendPasswordResetEmail("test@example.com", "token123")
	if err != nil {
		t.Error("SendPasswordResetEmail should not return error:", err)
	}

	err = emailService.SendWelcomeEmail("test@example.com", "Test User")
	if err != nil {
		t.Error("SendWelcomeEmail should not return error:", err)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    func() Config
		shouldErr bool
	}{
		{
			name: "nil email service should work (optional)",
			config: func() Config {
				storage, _ := storage.NewInMemorySQLiteStorage()
				return Config{
					Storage:      storage,
					EmailService: nil,
					SecurityConfig: SecurityConfig{
						DefaultUserRoleName: "user",
						SessionLifetime:     time.Hour,
					},
				}
			},
			shouldErr: false,
		},
		{
			name: "valid config should work",
			config: func() Config {
				storage, _ := storage.NewInMemorySQLiteStorage()
				return Config{
					Storage:      storage,
					EmailService: &TestEmailService{},
					SecurityConfig: SecurityConfig{
						DefaultUserRoleName: "user",
						SessionLifetime:     time.Hour,
					},
				}
			},
			shouldErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAuthService(test.config())

			if test.shouldErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.shouldErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}