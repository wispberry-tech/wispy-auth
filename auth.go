package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// Discord OAuth2 endpoints
var (
	DiscordAuthURL  = "https://discord.com/api/oauth2/authorize"
	DiscordTokenURL = "https://discord.com/api/oauth2/token"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidProvider    = errors.New("invalid OAuth provider")
)

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Email        string    `gorm:"uniqueIndex" json:"email"`
	PasswordHash string    `json:"-"` // Hide password from JSON
	Name         string    `json:"name"`
	AvatarURL    string    `json:"avatar_url,omitempty"`
	Provider     string    `json:"provider"` // "email", "google", "github", "discord"
	ProviderID   string    `json:"provider_id" gorm:"index"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type AuthService struct {
	storage       StorageInterface
	jwtSecret     []byte
	oauthConfigs  map[string]*oauth2.Config
	storageConfig StorageConfig
}

type Config struct {
	DatabaseDSN     string
	JWTSecret       string
	OAuthProviders  map[string]OAuthProviderConfig
	StorageConfig   StorageConfig
}

func NewAuthService(cfg Config) (*AuthService, error) {
	// Initialize storage interface with PostgreSQL
	storage, err := NewPostgresStorage(cfg.DatabaseDSN, cfg.StorageConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Set up OAuth2 configurations for multiple providers
	oauthConfigs := make(map[string]*oauth2.Config)

	for provider, providerCfg := range cfg.OAuthProviders {
		var endpoint oauth2.Endpoint
		var scopes []string

		switch provider {
		case "google":
			endpoint = google.Endpoint
			scopes = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
		case "github":
			endpoint = github.Endpoint
			scopes = []string{"user:email", "read:user"}
		case "discord":
			endpoint = oauth2.Endpoint{
				AuthURL:  DiscordAuthURL,
				TokenURL: DiscordTokenURL,
			}
			scopes = []string{"identify", "email"}
		default:
			return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
		}

		oauthConfigs[provider] = &oauth2.Config{
			ClientID:     providerCfg.ClientID,
			ClientSecret: providerCfg.ClientSecret,
			RedirectURL:  providerCfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     endpoint,
		}
	}

	return &AuthService{
		storage:       storage,
		jwtSecret:     []byte(cfg.JWTSecret),
		oauthConfigs:  oauthConfigs,
		storageConfig: cfg.StorageConfig,
	}, nil
}

func (a *AuthService) SignUp(email, password, name string) (*User, error) {
	return a.SignUpWithTenant(email, password, name, 0) // Use default tenant
}

func (a *AuthService) SignUpWithTenant(email, password, name string, tenantID uint) (*User, error) {
	// Check if user already exists
	_, err := a.storage.GetUserByEmail(email, "email")
	if err == nil {
		return nil, ErrUserExists
	}
	if err != ErrUserNotFound {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := User{
		Email:        email,
		PasswordHash: hashedPassword,
		Name:         name,
		Provider:     "email",
	}

	if err := a.storage.CreateUser(&user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign user to tenant if multi-tenant is enabled
	if err := a.assignUserToDefaultTenant(&user, tenantID); err != nil {
		return nil, fmt.Errorf("failed to assign user to tenant: %w", err)
	}

	return &user, nil
}

func (a *AuthService) SignIn(email, password string) (*User, error) {
	user, err := a.storage.GetUserByEmail(email, "email")
	if err != nil {
		if err == ErrUserNotFound {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	if !checkPasswordHash(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func (a *AuthService) ValidateUser(token string) (*User, error) {
	if token == "" {
		return nil, errors.New("invalid token")
	}

	parts := strings.Split(token, "|")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	// Convert string ID to uint
	var userID uint
	if _, err := fmt.Sscanf(parts[0], "%d", &userID); err != nil {
		return nil, errors.New("invalid user ID in token")
	}

	user, err := a.storage.GetUserByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Verify token (simplified example - use proper JWT validation in production)
	if parts[1] != "valid-token" {
		return nil, errors.New("invalid token")
	}

	return user, nil
}

func (a *AuthService) GenerateToken(user *User) (string, error) {
	// In a real implementation, generate JWT token
	token := fmt.Sprintf("%d|valid-token", user.ID)
	return token, nil
}

func (a *AuthService) GetOAuthURL(provider, state string) (string, error) {
	config, exists := a.oauthConfigs[provider]
	if !exists {
		return "", ErrInvalidProvider
	}
	return config.AuthCodeURL(state), nil
}

// Multi-tenant helper methods
func (a *AuthService) assignUserToDefaultTenant(user *User, tenantID uint) error {
	// Get storage config to check if multi-tenant is enabled
	storageConfig := a.getStorageConfig()
	if !storageConfig.MultiTenant.Enabled {
		return nil // Skip if multi-tenant is disabled
	}

	// Use provided tenantID or fall back to default
	targetTenantID := tenantID
	if targetTenantID == 0 {
		targetTenantID = storageConfig.MultiTenant.DefaultTenantID
	}

	// Get default role for the tenant (assume ID 1 is default user role)
	defaultRoleID := uint(1) // This should be configurable

	return a.storage.AssignUserToTenant(user.ID, targetTenantID, defaultRoleID)
}

func (a *AuthService) getStorageConfig() *StorageConfig {
	return &a.storageConfig
}

// Multi-tenant API methods

// CreateTenant creates a new tenant
func (a *AuthService) CreateTenant(name, slug, domain string) (*Tenant, error) {
	tenant := &Tenant{
		Name:     name,
		Slug:     slug,
		Domain:   domain,
		IsActive: true,
		Settings: "{}",
	}
	
	if err := a.storage.CreateTenant(tenant); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}
	
	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (a *AuthService) GetTenant(id uint) (*Tenant, error) {
	return a.storage.GetTenantByID(id)
}

// GetTenantBySlug retrieves a tenant by slug
func (a *AuthService) GetTenantBySlug(slug string) (*Tenant, error) {
	return a.storage.GetTenantBySlug(slug)
}

// CreateRole creates a new role for a tenant
func (a *AuthService) CreateRole(tenantID uint, name, description string, isSystem bool) (*Role, error) {
	role := &Role{
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		IsSystem:    isSystem,
	}
	
	if err := a.storage.CreateRole(role); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	
	return role, nil
}

// GetRolesByTenant retrieves all roles for a tenant
func (a *AuthService) GetRolesByTenant(tenantID uint) ([]*Role, error) {
	return a.storage.GetRolesByTenant(tenantID)
}

// CreatePermission creates a new permission
func (a *AuthService) CreatePermission(name, resource, action, description string) (*Permission, error) {
	permission := &Permission{
		Name:        name,
		Resource:    resource,
		Action:      action,
		Description: description,
	}
	
	if err := a.storage.CreatePermission(permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}
	
	return permission, nil
}

// AssignPermissionToRole assigns a permission to a role
func (a *AuthService) AssignPermissionToRole(roleID, permissionID uint) error {
	return a.storage.AssignPermissionToRole(roleID, permissionID)
}

// AssignUserToTenant assigns a user to a tenant with a role
func (a *AuthService) AssignUserToTenant(userID, tenantID, roleID uint) error {
	return a.storage.AssignUserToTenant(userID, tenantID, roleID)
}

// GetUserTenants retrieves all tenants for a user
func (a *AuthService) GetUserTenants(userID uint) ([]*UserTenant, error) {
	return a.storage.GetUserTenants(userID)
}

// UserHasPermission checks if a user has a specific permission in a tenant
func (a *AuthService) UserHasPermission(userID, tenantID uint, permission string) (bool, error) {
	return a.storage.UserHasPermission(userID, tenantID, permission)
}

// GetUserPermissionsInTenant gets all permissions for a user in a specific tenant
func (a *AuthService) GetUserPermissionsInTenant(userID, tenantID uint) ([]*Permission, error) {
	return a.storage.GetUserPermissionsInTenant(userID, tenantID)
}
