package auth

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	UserID uint   `json:"uid"`
	Role   string `json:"role,omitempty"`
}

func (a *AuthService) GenerateToken(user *User) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)), // 24 hour expiry
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "nucleus-auth",
			Subject:   fmt.Sprintf("%d", user.ID),
		},
		UserID: user.ID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

func (a *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			slog.Warn("Unexpected JWT signing method", "method", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		slog.Warn("Failed to parse JWT token", "error", err)
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		slog.Warn("Invalid JWT token claims", "valid", token.Valid, "claims_ok", ok)
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (a *AuthService) ValidateUser(tokenString string) (*User, error) {
	claims, err := a.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	user, err := a.storage.GetUserByID(claims.UserID)
	if err != nil {
		slog.Warn("User not found during token validation", "error", err, "user_id", claims.UserID)
		return nil, ErrUserNotFound
	}

	return user, nil
}
