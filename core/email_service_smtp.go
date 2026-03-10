package core

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

type SMTPEmailService struct {
	config EmailServiceConfig
}

func NewSMTPEmailService(cfg EmailServiceConfig) *SMTPEmailService {
	return &SMTPEmailService{config: cfg}
}

func (s *SMTPEmailService) Send2FACode(email, code string) error {
	body := s.formatTemplate(s.config.Template2FACode, map[string]string{
		"Code": code,
	})
	return s.sendEmail(email, "Your 2FA Code", body)
}

func (s *SMTPEmailService) SendPasswordReset(email, resetURL string) error {
	body := s.formatTemplate(s.config.TemplatePasswordReset, map[string]string{
		"ResetURL": resetURL,
	})
	return s.sendEmail(email, "Password Reset Request", body)
}

func (s *SMTPEmailService) SendWelcome(email string) error {
	body := s.formatTemplate(s.config.TemplateWelcome, nil)
	return s.sendEmail(email, "Welcome!", body)
}

func (s *SMTPEmailService) sendEmail(to, subject, body string) error {
	from := s.config.From

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		from, to, subject, body)

	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)

	var auth smtp.Auth
	if s.config.SMTPUsername != "" {
		auth = smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)
	}

	if s.config.SMTPUseTLS {
		client, err := smtp.Dial(addr)
		if err != nil {
			return err
		}
		defer client.Close()

		tlsConfig := &tls.Config{
			ServerName: s.config.SMTPHost,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}

		if err := client.Mail(from); err != nil {
			return err
		}

		if err := client.Rcpt(to); err != nil {
			return err
		}

		w, err := client.Data()
		if err != nil {
			return err
		}
		defer w.Close()

		_, err = fmt.Fprint(w, msg)
		return err
	}

	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}

func (s *SMTPEmailService) formatTemplate(template string, vars map[string]string) string {
	result := template
	for key, value := range vars {
		result = strings.ReplaceAll(result, "{{"+key+"}}", value)
	}
	return result
}

func (s *SMTPEmailService) Close() error {
	return nil
}
