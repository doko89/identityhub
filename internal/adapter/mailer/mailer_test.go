package mailer

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestNewSMTPValidation(t *testing.T) {
	if _, err := NewSMTP(Config{Host: "mail.example.com", Port: 587, From: "idp@example.com"}); err != nil {
		t.Fatalf("NewSMTP(valid) = %v", err)
	}
	for i, cfg := range []Config{
		{},
		{Port: 587, From: "a@b.c"},
		{Host: "h", Port: 0, From: "a@b.c"},
		{Host: "h", Port: 99999, From: "a@b.c"},
		{Host: "h", Port: 587},
	} {
		if _, err := NewSMTP(cfg); err == nil {
			t.Errorf("case %d: NewSMTP = nil error, want failure", i)
		}
	}
}

func TestValidAddress(t *testing.T) {
	for _, addr := range []string{"ara@example.com", "a.b+tag@sub.example.co"} {
		if !validAddress(addr) {
			t.Errorf("validAddress(%q) = false, want true", addr)
		}
	}
	for _, addr := range []string{"", "no-at-sign", "@nodomain", "nolocal@", "two@@signs.com",
		"with space@x.com", "inject@x.com\r\nBcc:evil@x.com", "<ara@x.com>", "a@127.0.0.0/8"} {
		if validAddress(addr) {
			t.Errorf("validAddress(%q) = true, want false", addr)
		}
	}
}

func TestSendRejectsBadRecipientWithoutDialing(t *testing.T) {
	m, err := NewSMTP(Config{Host: "127.0.0.1", Port: 39999, From: "idp@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send("not-an-address", "s", "b", ""); err == nil {
		t.Fatal("Send(bad recipient) = nil, want error")
	}
}

func TestSendUnreachableFailsExplicitly(t *testing.T) {
	m, err := NewSMTP(Config{Host: "127.0.0.1", Port: 39999, From: "idp@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send("ara@example.com", "s", "b", ""); err == nil {
		t.Fatal("Send(closed port) = nil, want error")
	} else if strings.Contains(err.Error(), "ara@example.com") {
		t.Errorf("error leaks recipient PII: %v", err)
	}
}

func TestBuildMessage(t *testing.T) {
	raw := string(buildMessage("from@x.com", "to@x.com", "Hello", "text", ""))
	if !strings.Contains(raw, "Subject: Hello") || !strings.Contains(raw, "text/plain") || !strings.Contains(raw, "text") {
		t.Errorf("text message malformed:\n%s", raw)
	}
	raw = string(buildMessage("from@x.com", "to@x.com", "Hello", "text", "<b>text</b>"))
	if !strings.Contains(raw, "multipart/alternative") || !strings.Contains(raw, "<b>text</b>") {
		t.Errorf("html message malformed:\n%s", raw)
	}
}

func TestLogMailer(t *testing.T) {
	m := NewLog(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Send("ara@example.com", "Reset", "body", ""); err != nil {
		t.Fatalf("LogMailer.Send = %v", err)
	}
	if NewLog(nil) == nil {
		t.Fatal("NewLog(nil) = nil, want default logger")
	}
}
