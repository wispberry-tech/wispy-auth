package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// generateSecureRandomString generates a cryptographically secure random string
// of the specified length. The string is URL-safe base64 encoded.
func generateSecureRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
