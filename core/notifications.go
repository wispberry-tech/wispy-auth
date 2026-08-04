package core

import "context"

// Notification describes an event the host application should surface to a
// user (typically by email). Wispy Auth owns what happened; the application
// owns rendering, templates, and delivery (SMTP, ESP, queue).
type Notification interface {
	isNotification()
}

// TwoFactorCodeNotification carries a 2FA verification code.
type TwoFactorCodeNotification struct {
	Email string
	Code  string
}

func (TwoFactorCodeNotification) isNotification() {}

// PasswordResetNotification carries a password reset token; the application
// builds the reset link from it.
type PasswordResetNotification struct {
	Email string
	Token string
}

func (PasswordResetNotification) isNotification() {}

// NotificationHandler delivers a Notification. Set Config.Notifications to
// receive them; when nil, notification-triggering operations are disabled.
type NotificationHandler func(ctx context.Context, n Notification) error
