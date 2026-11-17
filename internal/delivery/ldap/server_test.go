package ldap

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

type stubUsers struct{ domain.UserStore }

type stubGroups struct{ domain.GroupStore }

func testDeps() Deps {
	return Deps{Auth: &usecaseauth.Service{}, Users: stubUsers{}, Groups: stubGroups{}, Log: testLogger()}
}

func TestNewValidation(t *testing.T) {
	allow := []*net.IPNet{mustCIDR(t, "127.0.0.0/8")}

	cases := []struct {
		name string
		cfg  Config
		deps Deps
	}{
		{"bogus mode", Config{Mode: "ldapi", Addr: "127.0.0.1:0", AllowedCIDRs: allow}, testDeps()},
		{"empty addr", Config{Mode: ModePlain, AllowedCIDRs: allow}, testDeps()},
		{"plaintext without whitelist", Config{Mode: ModePlain, Addr: "127.0.0.1:0"}, testDeps()},
		{"ldaps without cert", Config{Mode: ModeLDAPS, Addr: "127.0.0.1:0"}, testDeps()},
		{"starttls without cert", Config{Mode: ModeStartTLS, Addr: "127.0.0.1:0"}, testDeps()},
		{"ldaps with missing files", Config{Mode: ModeLDAPS, Addr: "127.0.0.1:0", TLSCertFile: "/nonexistent/c.pem", TLSKeyFile: "/nonexistent/k.pem"}, testDeps()},
		{"missing auth", Config{Mode: ModePlain, Addr: "127.0.0.1:0", AllowedCIDRs: allow}, Deps{Users: stubUsers{}, Groups: stubGroups{}}},
		{"missing users", Config{Mode: ModePlain, Addr: "127.0.0.1:0", AllowedCIDRs: allow}, Deps{Auth: &usecaseauth.Service{}, Groups: stubGroups{}}},
		{"missing groups", Config{Mode: ModePlain, Addr: "127.0.0.1:0", AllowedCIDRs: allow}, Deps{Auth: &usecaseauth.Service{}, Users: stubUsers{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg, tc.deps); err == nil {
				t.Error("New = nil, want error")
			}
		})
	}
}

func TestNewPlainOK(t *testing.T) {
	s, err := New(Config{
		Mode: ModePlain, Addr: "127.0.0.1:0",
		AllowedCIDRs: []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
	}, testDeps())
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if s.Addr() != nil {
		t.Errorf("Addr before Serve = %v, want nil", s.Addr())
	}
	s.Stop() // safe before Serve and idempotent
	s.Stop()
}

// fakeConn is a minimal net.Conn for the whitelist hook.
type fakeConn struct {
	net.Conn
	remote string
}

func (f fakeConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", f.remote)
	return addr
}

func TestAllowConnWhitelist(t *testing.T) {
	hook := allowConn([]*net.IPNet{mustCIDR(t, "10.0.0.0/8"), mustCIDR(t, "192.168.1.50/32")}, testLogger())
	if err := hook(fakeConn{remote: "10.1.2.3:3890"}); err != nil {
		t.Errorf("whitelisted 10.1.2.3 rejected: %v", err)
	}
	if err := hook(fakeConn{remote: "192.168.1.50:9999"}); err != nil {
		t.Errorf("whitelisted bare IP rejected: %v", err)
	}
	if err := hook(fakeConn{remote: "11.0.0.1:3890"}); err == nil {
		t.Error("outside 11.0.0.1 allowed, want rejection")
	}
	if err := hook(nil); err == nil {
		t.Error("nil conn allowed, want rejection")
	}
}

func TestAllowConnEmptyMeansUnrestricted(t *testing.T) {
	hook := allowConn(nil, testLogger())
	if err := hook(fakeConn{remote: "203.0.113.7:3890"}); err != nil {
		t.Errorf("empty whitelist rejected: %v", err)
	}
}

func TestParseGroupDN(t *testing.T) {
	got, err := parseGroupDN("cn=eng,ou=groups,dc=identityhub")
	if err != nil || got != "eng" {
		t.Errorf("parseGroupDN = %q, %v", got, err)
	}
	for _, dn := range []string{"", "cn=eng", "cn=,ou=groups,dc=identityhub", "cn=eng,ou=users,dc=identityhub", "uid=x,ou=users,dc=identityhub"} {
		if _, err := parseGroupDN(dn); err == nil {
			t.Errorf("parseGroupDN(%q) = nil, want error", dn)
		}
	}
}

func TestUnescapeDNValue(t *testing.T) {
	if got := unescapeDNValue(`ara\,x`); got != "ara,x" {
		t.Errorf("unescape = %q", got)
	}
	if got := unescapeDNValue(`trailing\`); got != `trailing\` {
		t.Errorf("unescape trailing = %q", got)
	}
}

func TestInvertMembers(t *testing.T) {
	alice := domain.User{ID: uuid.New(), Username: "alice"}
	bob := domain.User{ID: uuid.New(), Username: "bob"}
	eng := domain.Group{ID: uuid.New(), Name: "eng"}
	ops := domain.Group{ID: uuid.New(), Name: "ops"}
	members := map[string][]string{
		eng.ID.String(): {UserDN("alice"), UserDN("ghost")},
		ops.ID.String(): {UserDN("alice"), UserDN("bob")},
	}
	got := invertMembers([]domain.User{alice, bob}, []domain.Group{eng, ops}, members)
	if len(got[alice.ID.String()]) != 2 {
		t.Errorf("alice groups = %v, want 2", got[alice.ID.String()])
	}
	if len(got[bob.ID.String()]) != 1 || got[bob.ID.String()][0] != GroupDN("ops") {
		t.Errorf("bob groups = %v, want [ops]", got[bob.ID.String()])
	}
}
