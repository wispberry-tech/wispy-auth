package verifyemail

import (
	"fmt"
	"log/slog"
)

// VerifyEmailModule is the main module interface for email verification functionality
// It provides utilities and middleware that developers can use in their routes
type VerifyEmailModule struct {
	storage        Storage
	config         Config
	provider       EmailProvider
	templateEngine *TemplateEngine
	utils          *Utilities
}

// NewVerifyEmailModule creates a new email verification module
func NewVerifyEmailModule(storage Storage, config Config) (*VerifyEmailModule, error) {
	if storage == nil {
		return nil, fmt.Errorf("storage is required")
	}

	// Test storage connection
	if err := storage.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to storage: %w", err)
	}

	// Set default config values if needed
	if config.TokenLength == 0 {
		config = DefaultConfig()
	}

	// Initialize email provider
	provider, err := GetEmailProvider(config.Provider, config.ProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize email provider: %w", err)
	}

	// Validate provider config
	if err := provider.ValidateConfig(config.ProviderConfig); err != nil {
		return nil, fmt.Errorf("invalid provider configuration: %w", err)
	}

	// Initialize template engine
	templateEngine := NewTemplateEngine()

	// Create utilities instance
	utils := &Utilities{
		storage:        storage,
		config:         config,
		provider:       provider,
		templateEngine: templateEngine,
	}

	module := &VerifyEmailModule{
		storage:        storage,
		config:         config,
		provider:       provider,
		templateEngine: templateEngine,
		utils:          utils,
	}

	slog.Info("Email verification module initialized",
		"provider", config.Provider,
		"token_length", config.TokenLength,
		"token_expiry", config.TokenExpiry,
		"base_url", config.BaseURL)

	return module, nil
}

// GetUtilities returns the utilities instance for manual integration
// This is what developers will use in their route handlers
func (m *VerifyEmailModule) GetUtilities() *Utilities {
	return m.utils
}

// GetConfig returns the current configuration
func (m *VerifyEmailModule) GetConfig() Config {
	return m.config
}

// GetProvider returns the email provider
func (m *VerifyEmailModule) GetProvider() EmailProvider {
	return m.provider
}

// GetTemplateEngine returns the template engine
func (m *VerifyEmailModule) GetTemplateEngine() *TemplateEngine {
	return m.templateEngine
}

// UpdateProvider allows changing the email provider at runtime
func (m *VerifyEmailModule) UpdateProvider(providerName string, config map[string]interface{}) error {
	provider, err := GetEmailProvider(providerName, config)
	if err != nil {
		return fmt.Errorf("failed to create new provider: %w", err)
	}

	if err := provider.ValidateConfig(config); err != nil {
		return fmt.Errorf("invalid provider configuration: %w", err)
	}

	// Close old provider
	if m.provider != nil {
		m.provider.Close()
	}

	// Update provider
	m.provider = provider
	m.utils.provider = provider
	m.config.Provider = providerName
	m.config.ProviderConfig = config

	slog.Info("Email provider updated", "provider", providerName)
	return nil
}

// Close shuts down the module and cleans up resources
func (m *VerifyEmailModule) Close() error {
	if m.provider != nil {
		if err := m.provider.Close(); err != nil {
			slog.Error("Failed to close email provider", "error", err)
		}
	}

	slog.Info("Email verification module closed")
	return nil
}
