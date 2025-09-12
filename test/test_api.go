package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username,omitempty"`
}

type SignUpResponse struct {
	Token                     string `json:"token"`
	User                      *User  `json:"user"`
	RequiresEmailVerification bool   `json:"requires_email_verification"`
	Error                     string `json:"error,omitempty"`
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInResponse struct {
	Token            string    `json:"token"`
	User             *User     `json:"user"`
	SessionID        string    `json:"session_id"`
	Requires2FA      bool      `json:"requires_2fa"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
	Error            string    `json:"error,omitempty"`
}

type User struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func main() {
	baseURL := "http://localhost:8080/api/auth"
	
	// Test 1: Health check
	fmt.Println("=== Testing Health Check ===")
	resp, err := http.Get("http://localhost:8080/health")
	if err != nil {
		log.Printf("Health check failed: %v", err)
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("Health check: %s - %s\n", resp.Status, string(body))
	}

	// Test 2: Sign up new user
	fmt.Println("\n=== Testing Sign Up ===")
	signUpReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "TestPassword123!",
		Username: "testuser", // Optional
	}
	
	reqBody, _ := json.Marshal(signUpReq)
	resp, err = http.Post(baseURL+"/signup", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatalf("Sign up request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var signUpResp SignUpResponse
	json.Unmarshal(body, &signUpResp)
	
	fmt.Printf("Sign Up Response (%s):\n", resp.Status)
	fmt.Printf("  Token: %s\n", signUpResp.Token[:min(20, len(signUpResp.Token))]+"...")
	fmt.Printf("  User ID: %d\n", signUpResp.User.ID)
	fmt.Printf("  Email: %s\n", signUpResp.User.Email)
	fmt.Printf("  Username: %s\n", signUpResp.User.Username)
	fmt.Printf("  Requires Email Verification: %t\n", signUpResp.RequiresEmailVerification)
	if signUpResp.Error != "" {
		fmt.Printf("  Error: %s\n", signUpResp.Error)
	}

	// Test 3: Sign up without username (should auto-generate)
	fmt.Println("\n=== Testing Sign Up Without Username ===")
	signUpReq2 := SignUpRequest{
		Email:    "hey_theodore@icloud.com",
		Password: "kvr-gfw9ZHK0xab!ehy",
		// Username intentionally omitted
	}
	
	reqBody2, _ := json.Marshal(signUpReq2)
	resp, err = http.Post(baseURL+"/signup", "application/json", bytes.NewBuffer(reqBody2))
	if err != nil {
		log.Fatalf("Sign up request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	var signUpResp2 SignUpResponse
	json.Unmarshal(body, &signUpResp2)
	
	fmt.Printf("Sign Up Response (%s):\n", resp.Status)
	if signUpResp2.User != nil {
		fmt.Printf("  User ID: %d\n", signUpResp2.User.ID)
		fmt.Printf("  Email: %s\n", signUpResp2.User.Email)
		fmt.Printf("  Username: %s (auto-generated)\n", signUpResp2.User.Username)
		fmt.Printf("  Requires Email Verification: %t\n", signUpResp2.RequiresEmailVerification)
	}
	if signUpResp2.Error != "" {
		fmt.Printf("  Error: %s\n", signUpResp2.Error)
		return
	}
	
	// Test 4: Sign in with the created user
	fmt.Println("\n=== Testing Sign In ===")
	signInReq := SignInRequest{
		Email:    signUpResp2.User.Email,
		Password: "kvr-gfw9ZHK0xab!ehy",
	}
	
	reqBody3, _ := json.Marshal(signInReq)
	resp, err = http.Post(baseURL+"/signin", "application/json", bytes.NewBuffer(reqBody3))
	if err != nil {
		log.Fatalf("Sign in request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	var signInResp SignInResponse
	json.Unmarshal(body, &signInResp)
	
	fmt.Printf("Sign In Response (%s):\n", resp.Status)
	if signInResp.User != nil {
		fmt.Printf("  Token: %s\n", signInResp.Token[:min(20, len(signInResp.Token))]+"...")
		fmt.Printf("  User: %s (%s)\n", signInResp.User.Username, signInResp.User.Email)
		fmt.Printf("  Session ID: %s\n", signInResp.SessionID)
		fmt.Printf("  Requires 2FA: %t\n", signInResp.Requires2FA)
	}
	if signInResp.Error != "" {
		fmt.Printf("  Error: %s\n", signInResp.Error)
	}

	// Test 5: Validate token
	fmt.Println("\n=== Testing Token Validation ===")
	req, _ := http.NewRequest("GET", baseURL+"/validate", nil)
	req.Header.Set("Authorization", "Bearer "+signInResp.Token)
	
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalf("Validate request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	fmt.Printf("Validate Response (%s): %s\n", resp.Status, string(body))

	fmt.Println("\n=== All Tests Completed ===")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}