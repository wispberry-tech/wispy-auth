package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// HTTP Handlers
func (a *AuthService) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := a.SignUp(request.Email, request.Password, request.Name)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			http.Error(w, "User already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
		}
		return
	}

	token, err := a.GenerateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"token": token,
		"user":  user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (a *AuthService) SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := a.SignIn(request.Email, request.Password)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrInvalidCredentials) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	token, err := a.GenerateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"token": token,
		"user":  user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (a *AuthService) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	// Remove "Bearer " prefix if present
	if after, ok := strings.CutPrefix(token, "Bearer "); ok {
		token = after
	}

	user, err := a.ValidateUser(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (a *AuthService) OAuthHandler(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		http.Error(w, "Provider parameter required", http.StatusBadRequest)
		return
	}

	state := generateRandomPassword()
	url, err := a.GetOAuthURL(provider, state)
	if err != nil {
		http.Error(w, "Invalid OAuth provider", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *AuthService) OAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		http.Error(w, "Provider parameter required", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not provided", http.StatusBadRequest)
		return
	}

	user, err := a.HandleOAuthCallback(provider, code)
	if err != nil {
		http.Error(w, "OAuth failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := a.GenerateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// In a real application, you might redirect to a frontend URL with the token
	response := map[string]interface{}{
		"token": token,
		"user":  user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
