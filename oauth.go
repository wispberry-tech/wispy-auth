package auth

import (
	"errors"
	"time"
)

// OAuthState represents the state of an OAuth2 flow with security enhancements
type OAuthState struct {
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	CSRF      string    `json:"csrf_token"` // Anti-CSRF token for protection against CSRF attacks
}

// Validate checks if the OAuth state is valid and not expired
func (s *OAuthState) Validate() error {
	if s.State == "" {
		return errors.New("empty state")
	}

	if s.CSRF == "" {
		return errors.New("empty CSRF token")
	}

	if time.Now().After(s.ExpiresAt) {
		return errors.New("state expired")
	}

	return nil
}
