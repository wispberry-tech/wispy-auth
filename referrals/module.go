package referrals

import (
	"fmt"
	"log/slog"
)

// ReferralsModule is the main module interface for referral functionality
// It provides utilities and middleware that developers can use in their routes
type ReferralsModule struct {
	storage Storage
	config  Config
	utils   *Utilities
}

// NewReferralsModule creates a new referrals module
func NewReferralsModule(storage Storage, config Config) (*ReferralsModule, error) {
	if storage == nil {
		return nil, fmt.Errorf("storage is required")
	}

	// Test storage connection
	if err := storage.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to storage: %w", err)
	}

	// Set default config values if needed
	if config.CodeLength == 0 {
		config = DefaultConfig()
	}

	// Create utilities instance
	utils := &Utilities{
		storage: storage,
		config:  config,
	}

	module := &ReferralsModule{
		storage: storage,
		config:  config,
		utils:   utils,
	}

	slog.Info("Referrals module initialized",
		"code_length", config.CodeLength,
		"require_referral", config.RequireReferralCode,
		"max_codes_per_user", config.MaxCodesPerUser)

	return module, nil
}

// GetUtilities returns the utilities instance for manual integration
// This is what developers will use in their route handlers
func (m *ReferralsModule) GetUtilities() *Utilities {
	return m.utils
}

// GetMiddleware returns a middleware provider for optional middleware usage
func (m *ReferralsModule) GetMiddleware() *MiddlewareProvider {
	return &MiddlewareProvider{
		storage: m.storage,
		config:  m.config,
	}
}

// GetConfig returns the current configuration
func (m *ReferralsModule) GetConfig() Config {
	return m.config
}

// Close shuts down the module and cleans up resources
func (m *ReferralsModule) Close() error {
	slog.Info("Referrals module closed")
	return nil
}

// MiddlewareProvider provides HTTP middleware functions
type MiddlewareProvider struct {
	storage Storage
	config  Config
}
