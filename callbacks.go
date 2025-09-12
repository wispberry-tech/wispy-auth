package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

func (a *AuthService) HandleOAuthCallback(provider, code string) (*User, error) {
	config, exists := a.oauthConfigs[provider]
	if !exists {
		return nil, ErrInvalidProvider
	}

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		slog.Error("OAuth exchange failed", "error", err, "provider", provider, "code", code)
		return nil, fmt.Errorf("oauth exchange failed: %w", err)
	}

	// Get user info from the provider
	var userInfo struct {
		Email     string `json:"email"`
		Name      string `json:"name"`
		Username  string `json:"username"` // For Discord
		ID        string `json:"id"`
		Avatar    string `json:"avatar,omitempty"`     // For Discord
		Picture   string `json:"picture,omitempty"`    // For Google
		AvatarURL string `json:"avatar_url,omitempty"` // For GitHub
	}

	client := config.Client(context.Background(), token)

	var userInfoURL string
	switch provider {
	case "google":
		userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	case "github":
		userInfoURL = "https://api.github.com/user"
	case "discord":
		userInfoURL = "https://discord.com/api/users/@me"
	default:
		return nil, ErrInvalidProvider
	}

	resp, err := client.Get(userInfoURL)
	if err != nil {
		slog.Error("Failed to get user info from OAuth provider", "error", err, "provider", provider, "url", userInfoURL)
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		slog.Error("Failed to decode user info from OAuth provider", "error", err, "provider", provider)
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Process provider-specific data
	userEmail := userInfo.Email
	userName := userInfo.Name
	avatarURL := ""

	switch provider {
	case "discord":
		if userName == "" {
			userName = userInfo.Username
		}
		if userInfo.Avatar != "" {
			avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", userInfo.ID, userInfo.Avatar)
		}
	case "github":
		if userInfo.AvatarURL != "" {
			avatarURL = userInfo.AvatarURL
		}
	case "google":
		if userInfo.Picture != "" {
			avatarURL = userInfo.Picture
		}
	}

	// Check if user exists with this provider
	user, err := a.storage.GetUserByProviderID(provider, userInfo.ID)

	if err == ErrUserNotFound {
		// Check if email already exists with another provider
		existingEmailUser, err := a.storage.GetUserByEmailAnyProvider(userEmail)
		if err == nil {
			// Email exists but with different provider - update the provider info
			existingEmailUser.Provider = provider
			existingEmailUser.ProviderID = userInfo.ID
			existingEmailUser.AvatarURL = avatarURL
			if err := a.storage.UpdateUser(existingEmailUser); err != nil {
				slog.Error("Failed to update user provider", "error", err, "user_id", existingEmailUser.ID, "provider", provider)
				return nil, fmt.Errorf("failed to update user provider: %w", err)
			}
			return existingEmailUser, nil
		}

		// Create new user
		newUser := User{
			Email:      userEmail,
			Username:   userName,
			Provider:   provider,
			ProviderID: userInfo.ID,
			AvatarURL:  avatarURL,
		}
		if err := a.storage.CreateUser(&newUser); err != nil {
			slog.Error("Failed to create OAuth user", "error", err, "email", userEmail, "provider", provider)
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		// Assign user to default tenant if multi-tenant is enabled
		if err := a.assignUserToDefaultTenant(&newUser, 0); err != nil {
			slog.Error("Failed to assign OAuth user to tenant", "error", err, "user_id", newUser.ID, "provider", provider)
			return nil, fmt.Errorf("failed to assign user to tenant: %w", err)
		}

		user = &newUser
	} else if err != nil {
		slog.Error("Database error during OAuth callback", "error", err, "provider", provider, "provider_id", userInfo.ID)
		return nil, fmt.Errorf("database error: %w", err)
	} else {
		// Update existing user's info
		user.Username = userName // Only updating username since that's what OAuth providers typically give us
		user.AvatarURL = avatarURL
		if err := a.storage.UpdateUser(user); err != nil {
			slog.Error("Failed to update existing OAuth user", "error", err, "user_id", user.ID, "provider", provider)
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
	}

	return user, nil
}
