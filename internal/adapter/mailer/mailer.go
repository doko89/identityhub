// Package mailer implements domain.Mailer for transactional email
// (password reset links, MFA notifications). Two implementations: SMTP
// over the standard library, and a log mailer used when SMTP is not
// configured (development) so password flows keep working end to end.
package mailer

import (
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Config mirrors the SMTP settings from internal/config.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// Timeout bounds the whole send. Zero takes DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout bounds one SMTP send (PRD §5.1: upstreams never hang).
const DefaultTimeout = 15 * time.Second

// SMTPMailer delivers via SMTP with PLAIN auth when credentials are set.
// No auth is attempted for empty usernames (local relays, Mailhog).
type SMTPMailer struct {
	cfg Config
}

// NewSMTP builds an SMTP mailer; it validates but does not dial.
func NewSMTP(cfg Config) (*SMTPMailer, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("mailer: Host is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("mailer: invalid Port %d", cfg.Port)
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("mailer: From is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &SMTPMailer{cfg: cfg}, nil
}

// Send delivers one message. The body is multipart/alternative with a text
// part and, when htmlBody is non-empty, an HTML part.
func (m *SMTPMailer) Send(to, subject, textBody, htmlBody string) error {
	if !validAddress(to) {
		return fmt.Errorf("mailer: invalid recipient %q", to)
	}
	msg := buildMessage(m.cfg.From, to, subject, textBody, htmlBody)
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}
	done := make(chan error, 1)
	go func() { done <- smtp.SendMail(addr, auth, m.cfg.From, []string{to}, msg) }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("mailer: send to %s: %w", redact(to), err)
		}
		return nil
	case <-time.After(m.cfg.Timeout):
		return fmt.Errorf("mailer: send to %s timed out after %v", redact(to), m.cfg.Timeout)
	}
}

func buildMessage(from, to, subject, textBody, htmlBody string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	if htmlBody == "" {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
		b.WriteString(textBody)
		return []byte(b.String())
	}
	boundary := "identityhub-alternative"
	b.WriteString("Content-Type: multipart/alternative; boundary=" + boundary + "\r\n\r\n")
	b.WriteString("--" + boundary + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(textBody + "\r\n")
	b.WriteString("--" + boundary + "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n")
	b.WriteString(htmlBody + "\r\n")
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

// validAddress is a deliberately small sanity check: one @, non-empty
// local and domain parts, no whitespace or angle brackets (header
// injection), and no newlines.
func validAddress(addr string) bool {
	if strings.ContainsAny(addr, " \t\r\n<>") {
		return false
	}
	local, domain, found := strings.Cut(addr, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	if _, _, err := net.ParseCIDR(domain); err == nil {
		return false
	}
	return true
}

// redact keeps the domain for debugging while hiding the local part
// (no PII in logs, TECH_SPEC §8).
func redact(addr string) string {
	if _, domain, found := strings.Cut(addr, "@"); found {
		return "***@" + domain
	}
	return "***"
}

// LogMailer implements domain.Mailer by logging the message instead of
// delivering it. Production uses SMTPMailer; the log mailer exists so
// development and tests exercise the full password-reset flow with no
// SMTP server.
type LogMailer struct {
	log *slog.Logger
}

// NewLog builds a log mailer; a nil logger takes slog.Default().
func NewLog(log *slog.Logger) *LogMailer {
	if log == nil {
		log = slog.Default()
	}
	return &LogMailer{log: log}
}

// Send logs the message subject and redacted recipient plus the text body
// (reset links must be visible in development).
func (m *LogMailer) Send(to, subject, textBody, _ string) error {
	m.log.Info("mail (log backend)", "to", redact(to), "subject", subject, "body", textBody)
	return nil
}
