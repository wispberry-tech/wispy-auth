package core

import (
	"sync"
)

type MockEmailService struct {
	mu         sync.Mutex
	sentEmails []SentEmail
}

type SentEmail struct {
	To      string
	Subject string
	Body    string
}

func NewMockEmailService() *MockEmailService {
	return &MockEmailService{
		sentEmails: make([]SentEmail, 0),
	}
}

func (m *MockEmailService) Send2FACode(email, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentEmails = append(m.sentEmails, SentEmail{
		To:      email,
		Subject: "Your 2FA Code",
		Body:    code,
	})
	return nil
}

func (m *MockEmailService) SendPasswordReset(email, resetURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentEmails = append(m.sentEmails, SentEmail{
		To:      email,
		Subject: "Password Reset Request",
		Body:    resetURL,
	})
	return nil
}

func (m *MockEmailService) SendWelcome(email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentEmails = append(m.sentEmails, SentEmail{
		To:      email,
		Subject: "Welcome!",
		Body:    "",
	})
	return nil
}

func (m *MockEmailService) GetSentEmails() []SentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sentEmails
}

func (m *MockEmailService) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentEmails = make([]SentEmail, 0)
}

func (m *MockEmailService) Close() error {
	return nil
}
