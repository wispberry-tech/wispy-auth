package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// OAuthUser represents user information from OAuth providers
type OAuthUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	Username  string `json:"username,omitempty"`
}

// OAuthInitHandler initiates OAuth flow for a given provider
func (a *AuthService) OAuthInitHandler(w http.ResponseWriter, r *http.Request, provider string) {
	// Check if provider is supported
	oauthConfig, exists := a.oauthConfigs[provider]
	if !exists {
		slog.Debug("Unsupported OAuth provider", "provider", provider)
		writeJSON(w, http.StatusBadRequest, OAuthResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Unsupported OAuth provider",
		})
		return
	}

	// Generate state token for security
	stateToken, err := GenerateSecureToken(32)
	if err != nil {
		slog.Error("Failed to generate state token", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "State token generation failed",
		})
		return
	}

	// Store OAuth state in database
	oauthState := &OAuthState{
		State:       stateToken,
		Provider:    provider,
		RedirectURL: r.URL.Query().Get("redirect_url"),
		ExpiresAt:   time.Now().Add(a.securityConfig.OAuthStateExpiry),
	}

	if err := a.storage.StoreOAuthState(r.Context(), oauthState); err != nil {
		slog.Error("Failed to store OAuth state", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "OAuth state storage failed",
		})
		return
	}

	// Generate OAuth URL
	url := oauthConfig.AuthCodeURL(stateToken)

	slog.Debug("OAuth flow initiated", "provider", provider)

	writeJSON(w, http.StatusOK, OAuthResponse{
		StatusCode: http.StatusOK,
		URL:        url,
	})
}

// OAuthCallbackHandler handles OAuth callbacks from providers
func (a *AuthService) OAuthCallbackHandler(w http.ResponseWriter, r *http.Request, provider string) {
	// Get OAuth configuration
	oauthConfig, exists := a.oauthConfigs[provider]
	if !exists {
		slog.Debug("Unsupported OAuth provider", "provider", provider)
		writeJSON(w, http.StatusBadRequest, OAuthResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Unsupported OAuth provider",
		})
		return
	}

	// Get state and code from query parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		slog.Debug("Missing state or code in OAuth callback")
		writeJSON(w, http.StatusBadRequest, OAuthResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Missing state or code parameter",
		})
		return
	}

	// Verify state token
	storedState, err := a.storage.GetOAuthState(r.Context(), state)
	if err != nil {
		slog.Error("Failed to get OAuth state", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "OAuth state retrieval failed",
		})
		return
	}

	if storedState == nil {
		slog.Debug("Invalid OAuth state", "state", state)
		writeJSON(w, http.StatusBadRequest, OAuthResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Invalid state parameter",
		})
		return
	}

	// Check if state is expired
	if time.Now().After(storedState.ExpiresAt) {
		slog.Debug("Expired OAuth state", "state", state)
		writeJSON(w, http.StatusBadRequest, OAuthResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "State parameter expired",
		})
		return
	}

	// Clean up OAuth state
	if err := a.storage.DeleteOAuthState(r.Context(), state); err != nil {
		slog.Error("Failed to delete OAuth state", "error", err)
	}

	// Exchange code for token
	ctx := context.Background()
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		slog.Error("Failed to exchange OAuth code", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to exchange authorization code",
		})
		return
	}

	// Get user info from provider
	oauthUser, err := a.fetchOAuthUserInfo(ctx, provider, token.AccessToken)
	if err != nil {
		slog.Error("Failed to fetch OAuth user info", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to fetch user information",
		})
		return
	}

	if oauthUser.Email == "" {
		slog.Debug("OAuth user has no email", "provider", provider, "user_id", oauthUser.ID)
		writeJSON(w, http.StatusBadRequest, OAuthResponse{
			StatusCode: http.StatusBadRequest,
			Error:      "Email is required from OAuth provider",
		})
		return
	}

	ip := extractIP(r)
	userAgent := r.UserAgent()

	// Check if user exists
	existingUser, err := a.storage.GetUserByProviderID(r.Context(), provider, oauthUser.ID)
	if err != nil {
		slog.Error("Failed to get user by provider ID", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Database error while checking OAuth user",
		})
		return
	}

	var user *User
	isNewUser := false

	if existingUser == nil {
		// Check if user exists with same email but different provider
		existingEmailUser, err := a.storage.GetUserByEmailAnyProvider(r.Context(), oauthUser.Email)
		if err != nil {
			slog.Error("Failed to check existing email", "error", err)
			writeJSON(w, http.StatusInternalServerError, OAuthResponse{
				StatusCode: http.StatusInternalServerError,
				Error:      "Database error while checking existing email",
			})
			return
		}

		if existingEmailUser != nil {
			// Update existing user to link with OAuth provider
			existingEmailUser.Provider = provider
			existingEmailUser.ProviderID = oauthUser.ID
			existingEmailUser.AvatarURL = oauthUser.AvatarURL
			existingEmailUser.EmailVerified = true // OAuth emails are typically verified

			if err := a.storage.UpdateUser(r.Context(), existingEmailUser); err != nil {
				slog.Error("Failed to update user with OAuth info", "error", err)
				writeJSON(w, http.StatusInternalServerError, OAuthResponse{
					StatusCode: http.StatusInternalServerError,
					Error:      "Failed to link account",
				})
				return
			}

			user = existingEmailUser
			a.logSecurityEvent(&user.ID, "oauth_account_linked", fmt.Sprintf("Account linked with %s", provider), ip, userAgent, true)
		} else {
			// Create new user
			firstName, lastName := splitName(oauthUser.Name, oauthUser.FirstName, oauthUser.LastName)
			user = &User{
				Email:         strings.ToLower(oauthUser.Email),
				Username:      oauthUser.Username,
				FirstName:     firstName,
				LastName:      lastName,
				Provider:      provider,
				ProviderID:    oauthUser.ID,
				AvatarURL:     oauthUser.AvatarURL,
				EmailVerified: true, // OAuth emails are typically verified
				IsActive:      true,
				IsSuspended:   false,
			}

			// Create user security record
			userSecurity := &UserSecurity{
				LoginAttempts:    0,
				TwoFactorEnabled: false,
			}

			// Create user and security record atomically in a transaction
			if err := a.storage.CreateUserWithSecurity(r.Context(), user, userSecurity); err != nil {
				slog.Error("Failed to create OAuth user with security", "error", err)
				writeJSON(w, http.StatusInternalServerError, OAuthResponse{
					StatusCode: http.StatusInternalServerError,
					Error:      "Failed to create user account",
				})
				return
			}

			isNewUser = true
			a.logSecurityEvent(&user.ID, "oauth_user_created", fmt.Sprintf("New user created via %s OAuth", provider), ip, userAgent, true)
		}
	} else {
		// Update existing OAuth user info
		user = existingUser
		user.AvatarURL = oauthUser.AvatarURL // Update avatar URL

		if err := a.storage.UpdateUser(r.Context(), user); err != nil {
			slog.Error("Failed to update OAuth user", "error", err)
			writeJSON(w, http.StatusInternalServerError, OAuthResponse{
				StatusCode: http.StatusInternalServerError,
				Error:      "Failed to update user account",
			})
			return
		}
	}

	// Check if user is active
	if !user.IsActive || user.IsSuspended {
		slog.Debug("OAuth user account is inactive", "user_id", user.ID)
		a.logSecurityEvent(&user.ID, "oauth_login_failed", "OAuth login attempt on inactive account", ip, userAgent, false)
		writeJSON(w, http.StatusUnauthorized, OAuthResponse{
			StatusCode: http.StatusUnauthorized,
			Error:      "Account is not active",
		})
		return
	}

	// Update last login
	if err := a.storage.UpdateLastLogin(r.Context(), user.ID, &ip); err != nil {
		slog.Error("Failed to update last login", "error", err)
	}

	// Create session
	session, err := a.newSession(user.ID, ip, userAgent)
	if err != nil {
		slog.Error("Failed to generate session token", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session token generation failed",
		})
		return
	}
	sessionToken := session.Token

	if err := a.storage.CreateSession(r.Context(), session); err != nil {
		slog.Error("Failed to create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, OAuthResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      "Session creation failed",
		})
		return
	}

	// Log successful OAuth login
	eventType := "oauth_login"
	if isNewUser {
		eventType = "oauth_signup"
	}
	a.logSecurityEvent(&user.ID, eventType, fmt.Sprintf("User successfully authenticated via %s", provider), ip, userAgent, true)

	slog.Info("OAuth authentication successful", "user_id", user.ID, "provider", provider, "is_new_user", isNewUser)

	// Clear password hash from response
	user.PasswordHash = ""

	writeJSON(w, http.StatusOK, OAuthResponse{
		StatusCode: http.StatusOK,
		Token:      sessionToken,
		User:       user,
		IsNewUser:  isNewUser,
	})
}

// fetchOAuthUserInfo fetches user information from OAuth providers
func (a *AuthService) fetchOAuthUserInfo(ctx context.Context, provider, accessToken string) (*OAuthUser, error) {
	var userInfoURL string
	switch provider {
	case "google":
		userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	case "github":
		userInfoURL = "https://api.github.com/user"
	case "discord":
		userInfoURL = "https://discord.com/api/users/@me"
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Make request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch user info: status %d", resp.StatusCode)
	}

	// Parse response based on provider
	switch provider {
	case "google":
		return parseGoogleUser(ctx, resp, accessToken)
	case "github":
		return parseGitHubUser(ctx, resp, accessToken)
	case "discord":
		return parseDiscordUser(ctx, resp, accessToken)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

// parseGoogleUser parses Google OAuth user information
func parseGoogleUser(_ context.Context, resp *http.Response, _ string) (*OAuthUser, error) {
	var googleUser struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		FirstName string `json:"given_name"`
		LastName  string `json:"family_name"`
		Picture   string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode Google user: %w", err)
	}

	return &OAuthUser{
		ID:        googleUser.ID,
		Email:     googleUser.Email,
		Name:      googleUser.Name,
		FirstName: googleUser.FirstName,
		LastName:  googleUser.LastName,
		AvatarURL: googleUser.Picture,
	}, nil
}

// parseGitHubUser parses GitHub OAuth user information
func parseGitHubUser(ctx context.Context, resp *http.Response, accessToken string) (*OAuthUser, error) {
	var githubUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub user: %w", err)
	}

	// GitHub might not return email in the user endpoint, fetch from emails endpoint
	if githubUser.Email == "" {
		email, err := fetchGitHubUserEmail(ctx, accessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch GitHub user email: %w", err)
		}
		githubUser.Email = email
	}

	return &OAuthUser{
		ID:        fmt.Sprintf("%d", githubUser.ID),
		Email:     githubUser.Email,
		Name:      githubUser.Name,
		Username:  githubUser.Login,
		AvatarURL: githubUser.AvatarURL,
	}, nil
}

// parseDiscordUser parses Discord OAuth user information
func parseDiscordUser(_ context.Context, resp *http.Response, _ string) (*OAuthUser, error) {
	var discordUser struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Avatar   string `json:"avatar"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&discordUser); err != nil {
		return nil, fmt.Errorf("failed to decode Discord user: %w", err)
	}

	// Construct Discord avatar URL
	avatarURL := ""
	if discordUser.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", discordUser.ID, discordUser.Avatar)
	}

	return &OAuthUser{
		ID:        discordUser.ID,
		Email:     discordUser.Email,
		Username:  discordUser.Username,
		Name:      discordUser.Username, // Discord uses username as display name
		AvatarURL: avatarURL,
	}, nil
}

// fetchGitHubUserEmail fetches primary email from GitHub emails endpoint
func fetchGitHubUserEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch emails: status %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("failed to decode emails: %w", err)
	}

	// Find primary verified email
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	// Find any verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}

// splitName splits a full name into first and last name components
func splitName(fullName, firstName, lastName string) (string, string) {
	// If we already have first and last name, return them
	if firstName != "" || lastName != "" {
		return firstName, lastName
	}

	// If no full name, return empty strings
	if fullName == "" {
		return "", ""
	}

	// Split full name by spaces
	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}

	// First part is first name, rest is last name
	return parts[0], strings.Join(parts[1:], " ")
}
