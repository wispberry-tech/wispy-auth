package core

import (
	"errors"
	"time"
)

// ValidateOAuthState checks if the OAuth state is valid and not expired
func ValidateOAuthState(s *OAuthState) error {
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