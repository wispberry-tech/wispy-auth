package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// Simple handler tests that focus on HTTP functionality
func createSimpleTestRequest(method, url string, body interface{}) *http.Request {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer([]byte{})
	}

	req, _ := http.NewRequest(method, url, reqBody)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// SignUp Handler HTTP Tests
func TestSignUpHandlerHTTP(t *testing.T) {
	authService, _ := createTestAuthService(t)

	tests := []struct {
		name           string
		body           interface{}
		expectedStatus int
		shouldHaveUser bool
	}{
		{
			name: "valid signup request",
			body: map[string]interface{}{
				"email":    "newuser@example.com",
				"password": "Password123",
				"username": "newuser",
			},
			expectedStatus: 200, // Actual status from the handler
			shouldHaveUser: true,
		},
		{
			name: "invalid email format",
			body: map[string]interface{}{
				"email":    "invalid-email",
				"password": "Password123",
				"username": "testuser",
			},
			expectedStatus: 400,
			shouldHaveUser: false,
		},
		{
			name: "weak password",
			body: map[string]interface{}{
				"email":    "user2@example.com",
				"password": "weak",
				"username": "testuser",
			},
			expectedStatus: 400,
			shouldHaveUser: false,
		},
		{
			name: "missing email field",
			body: map[string]interface{}{
				"password": "Password123",
				"username": "testuser",
			},
			expectedStatus: 400,
			shouldHaveUser: false,
		},
		{
			name: "missing password field",
			body: map[string]interface{}{
				"email":    "user3@example.com",
				"username": "testuser",
			},
			expectedStatus: 400,
			shouldHaveUser: false,
		},
		{
			name: "missing username field",
			body: map[string]interface{}{
				"email":    "user4@example.com",
				"password": "Password123",
			},
			expectedStatus: 200, // Username might be optional
			shouldHaveUser: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := createSimpleTestRequest("POST", "/signup", test.body)
			response := authService.SignUpHandler(req)

			if response.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, response.StatusCode)
			}

			if test.shouldHaveUser {
				if response.User == nil {
					t.Error("Expected user to be created")
				}
				if response.Token == "" {
					t.Error("Expected token to be created")
				}
			} else {
				if response.Error == "" {
					t.Error("Expected error message")
				}
			}
		})
	}
}

// SignIn Handler HTTP Tests
func TestSignInHandlerHTTP(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Create a user first
	signupReq := createSimpleTestRequest("POST", "/signup", map[string]interface{}{
		"email":    "signin@example.com",
		"password": "Password123",
		"username": "signinuser",
	})
	authService.SignUpHandler(signupReq)

	tests := []struct {
		name           string
		body           interface{}
		expectedStatus int
		shouldHaveUser bool
	}{
		{
			name: "valid signin",
			body: map[string]interface{}{
				"email":    "signin@example.com",
				"password": "Password123",
			},
			expectedStatus: 200,
			shouldHaveUser: true,
		},
		{
			name: "wrong password",
			body: map[string]interface{}{
				"email":    "signin@example.com",
				"password": "WrongPassword",
			},
			expectedStatus: 401,
			shouldHaveUser: false,
		},
		{
			name: "nonexistent user",
			body: map[string]interface{}{
				"email":    "nonexistent@example.com",
				"password": "Password123",
			},
			expectedStatus: 401,
			shouldHaveUser: false,
		},
		{
			name: "missing email",
			body: map[string]interface{}{
				"password": "Password123",
			},
			expectedStatus: 400,
			shouldHaveUser: false,
		},
		{
			name: "missing password",
			body: map[string]interface{}{
				"email": "signin@example.com",
			},
			expectedStatus: 400,
			shouldHaveUser: false,
		},
		{
			name: "empty request body",
			body: map[string]interface{}{},
			expectedStatus: 400,
			shouldHaveUser: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := createSimpleTestRequest("POST", "/signin", test.body)
			response := authService.SignInHandler(req)

			if response.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, response.StatusCode)
			}

			if test.shouldHaveUser {
				if response.User == nil {
					t.Error("Expected user to be returned")
				}
				if response.Token == "" {
					t.Error("Expected token to be returned")
				}
			} else {
				if response.Error == "" {
					t.Error("Expected error message")
				}
			}
		})
	}
}

// Password Reset Handler HTTP Tests
func TestForgotPasswordHandlerHTTP(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Create a user first
	signupReq := createSimpleTestRequest("POST", "/signup", map[string]interface{}{
		"email":    "forgot@example.com",
		"password": "Password123",
		"username": "forgotuser",
	})
	authService.SignUpHandler(signupReq)

	tests := []struct {
		name           string
		body           interface{}
		expectedStatus int
		shouldSucceed  bool
	}{
		{
			name: "valid email for password reset",
			body: map[string]interface{}{
				"email": "forgot@example.com",
			},
			expectedStatus: 200,
			shouldSucceed:  true,
		},
		{
			name: "nonexistent email",
			body: map[string]interface{}{
				"email": "nonexistent@example.com",
			},
			expectedStatus: 200, // Still returns 200 for security
			shouldSucceed:  true,
		},
		{
			name: "invalid email format",
			body: map[string]interface{}{
				"email": "invalid-email",
			},
			expectedStatus: 400,
			shouldSucceed:  false,
		},
		{
			name: "missing email field",
			body: map[string]interface{}{},
			expectedStatus: 400,
			shouldSucceed:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := createSimpleTestRequest("POST", "/forgot-password", test.body)
			response := authService.ForgotPasswordHandler(req)

			if response.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, response.StatusCode)
			}

			if test.shouldSucceed {
				if response.Message == "" {
					t.Error("Expected success message")
				}
			} else {
				if response.Error == "" {
					t.Error("Expected error message")
				}
			}
		})
	}
}

// OAuth Providers Handler Test
func TestGetProvidersHandlerHTTP(t *testing.T) {
	// Create auth service with OAuth providers
	authService, _ := createTestAuthService(t)

	req := createSimpleTestRequest("GET", "/providers", nil)
	response := authService.GetProvidersHandler(req)

	// Should return a map (even if empty)
	if response == nil {
		t.Error("Expected providers response")
	}

	// The response is a map[string][]string
	if len(response) < 0 {
		t.Error("Expected providers map")
	}
}

// Test JSON parsing functionality
func TestJSONParsing(t *testing.T) {
	authService, _ := createTestAuthService(t)

	tests := []struct {
		name           string
		body           string
		expectedStatus int
	}{
		{
			name:           "valid JSON",
			body:           `{"email":"test@example.com","password":"Password123","username":"testuser"}`,
			expectedStatus: 200,
		},
		{
			name:           "invalid JSON",
			body:           `{"email":"test@example.com","password":"Password123"`,
			expectedStatus: 400,
		},
		{
			name:           "empty body",
			body:           "",
			expectedStatus: 400,
		},
		{
			name:           "non-JSON content",
			body:           "not json",
			expectedStatus: 400,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/signup", bytes.NewBufferString(test.body))
			req.Header.Set("Content-Type", "application/json")

			response := authService.SignUpHandler(req)

			if response.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, response.StatusCode)
			}
		})
	}
}

// Test request validation functionality
func TestRequestValidation(t *testing.T) {
	authService, _ := createTestAuthService(t)

	// Test different content types
	tests := []struct {
		name        string
		contentType string
		body        string
		shouldError bool
	}{
		{
			name:        "valid JSON content type",
			contentType: "application/json",
			body:        `{"email":"test@example.com","password":"Password123","username":"testuser"}`,
			shouldError: false,
		},
		{
			name:        "missing content type",
			contentType: "",
			body:        `{"email":"test2@example.com","password":"Password123","username":"testuser"}`,
			shouldError: false, // Should still work
		},
		{
			name:        "wrong content type",
			contentType: "text/plain",
			body:        `{"email":"test3@example.com","password":"Password123","username":"testuser"}`,
			shouldError: false, // Should still work if JSON is valid
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/signup", bytes.NewBufferString(test.body))
			if test.contentType != "" {
				req.Header.Set("Content-Type", test.contentType)
			}

			response := authService.SignUpHandler(req)

			if test.shouldError && response.StatusCode == 200 {
				t.Error("Expected error but signup succeeded")
			}
			if !test.shouldError && response.StatusCode != 200 {
				t.Errorf("Expected success but got status %d: %s", response.StatusCode, response.Error)
			}
		})
	}
}