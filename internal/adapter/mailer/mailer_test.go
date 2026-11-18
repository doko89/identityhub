package mailer

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
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

// fakeSMTP serves one scripted dialogue: greeting, EHLO (recorded),
// optional STARTTLS upgrade, MAIL/RCPT/DATA, QUIT. Protocol
// violations fail the test; helo/data/upgraded report what arrived.
type fakeSMTP struct {
	t        *testing.T
	listener net.Listener
	useTLS   bool
	certPEM  []byte
	key      *ecdsa.PrivateKey
	helo     chan string
	data     chan string
	upgraded chan bool
}

func startFakeSMTP(t *testing.T, advertiseTLS bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{
		t: t, listener: ln, useTLS: advertiseTLS,
		helo: make(chan string, 2), data: make(chan string, 1), upgraded: make(chan bool, 1),
	}
	if advertiseTLS {
		f.certPEM, f.key = selfSignedCert(t)
	}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) port() int { return f.listener.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve() {
	conn, err := f.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	write := func(s string) {
		if _, err := rw.WriteString(s + "\r\n"); err != nil {
			return
		}
		rw.Flush()
	}
	readLine := func() string {
		line, err := rw.ReadString('\n')
		if err != nil {
			return ""
		}
		return strings.TrimRight(line, "\r\n")
	}
	write("220 fake ESMTP")
	if line := readLine(); !strings.HasPrefix(line, "EHLO ") {
		f.t.Errorf("expected EHLO, got %q", line)
		return
	} else {
		f.helo <- strings.TrimPrefix(line, "EHLO ")
	}
	if f.useTLS {
		write("250-fake")
		write("250-STARTTLS")
		write("250 8BITMIME")
		if readLine() != "STARTTLS" {
			f.t.Error("expected STARTTLS")
			return
		}
		write("220 ready")
		cert, err := tls.X509KeyPair(f.certPEM, x509ECKeyPEM(f.t, f.key))
		if err != nil {
			f.t.Errorf("test cert: %v", err)
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			f.t.Errorf("server handshake: %v", err)
			return
		}
		f.upgraded <- true
		rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
		if line := readLine(); !strings.HasPrefix(line, "EHLO ") {
			f.t.Errorf("expected post-TLS EHLO, got %q", line)
			return
		} else {
			f.helo <- strings.TrimPrefix(line, "EHLO ")
		}
		write("250-fake")
		write("250 8BITMIME")
	} else {
		write("250-fake")
		write("250 8BITMIME")
	}
	if line := readLine(); !strings.HasPrefix(line, "MAIL FROM:") {
		f.t.Errorf("expected MAIL, got %q", line)
		return
	}
	write("250 OK")
	if line := readLine(); !strings.HasPrefix(line, "RCPT TO:") {
		f.t.Errorf("expected RCPT, got %q", line)
		return
	}
	write("250 OK")
	if readLine() != "DATA" {
		f.t.Error("expected DATA")
		return
	}
	write("354 end with .")
	var body strings.Builder
	for {
		line := readLine()
		if line == "." {
			break
		}
		body.WriteString(line + "\n")
	}
	f.data <- body.String()
	write("250 queued")
	readLine() // QUIT
	write("221 bye")
}

func selfSignedCert(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"127.0.0.1"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func x509ECKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestSendSaysHeloFQDN(t *testing.T) {
	fake := startFakeSMTP(t, false)
	m, err := NewSMTP(Config{
		Host: "127.0.0.1", Port: fake.port(), From: "idp@example.com", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send("ara@example.com", "Reset", "body", ""); err != nil {
		t.Fatalf("Send = %v", err)
	}
	select {
	case helo := <-fake.helo:
		if helo != "example.com" {
			t.Errorf("EHLO domain = %q, want From domain", helo)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EHLO observed")
	}
	select {
	case body := <-fake.data:
		if !strings.Contains(body, "Subject: Reset") {
			t.Errorf("delivered body misses subject:\n%s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no DATA observed")
	}
}

func TestSendHeloOverride(t *testing.T) {
	fake := startFakeSMTP(t, false)
	m, err := NewSMTP(Config{
		Host: "127.0.0.1", Port: fake.port(), From: "idp@example.com",
		HeloName: "mail.example.net", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send("ara@example.com", "s", "b", ""); err != nil {
		t.Fatalf("Send = %v", err)
	}
	select {
	case helo := <-fake.helo:
		if helo != "mail.example.net" {
			t.Errorf("EHLO domain = %q, want override", helo)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EHLO observed")
	}
}

func TestSendUpgradesSTARTTLS(t *testing.T) {
	fake := startFakeSMTP(t, true)
	m, err := NewSMTP(Config{
		Host: "127.0.0.1", Port: fake.port(), From: "idp@example.com",
		TLSClient: &tls.Config{InsecureSkipVerify: true}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send("ara@example.com", "s", "b", ""); err != nil {
		t.Fatalf("Send = %v", err)
	}
	select {
	case <-fake.upgraded:
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw the TLS upgrade")
	}
	select {
	case body := <-fake.data:
		if !strings.Contains(body, "Subject: s") {
			t.Errorf("delivered body misses subject:\n%s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no DATA observed")
	}
}

func TestImplicitTLSSelectedByPort(t *testing.T) {
	m465 := &SMTPMailer{cfg: Config{Port: 465}}
	m587 := &SMTPMailer{cfg: Config{Port: 587}}
	m25 := &SMTPMailer{cfg: Config{Port: 25}}
	if !m465.implicitTLS() || m587.implicitTLS() || m25.implicitTLS() {
		t.Error("implicit TLS must select port 465 only")
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
