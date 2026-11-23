package ldap

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	ldapserver "github.com/vjeantet/ldapserver"

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

// fakeConn is a net.Pipe-backed conn with a spoofed remote address for
// the whitelist hook (the hook closes rejected connections, so the
// conn must be real).
type fakeConn struct {
	net.Conn
	peer   net.Conn
	remote string
}

func newFakeConn(t *testing.T, remote string) *fakeConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return &fakeConn{Conn: a, peer: b, remote: remote}
}

func (f *fakeConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", f.remote)
	return addr
}

// closedByHook reports whether the hook side was closed: the peer read
// hits EOF (a read timeout means the connection is still open).
func (f *fakeConn) closedByHook(t *testing.T) bool {
	t.Helper()
	_ = f.peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var one [1]byte
	_, err := f.peer.Read(one[:])
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true
}

func TestAllowConnWhitelist(t *testing.T) {
	hook := allowConn([]*net.IPNet{mustCIDR(t, "10.0.0.0/8"), mustCIDR(t, "192.168.1.50/32")}, testLogger())
	// Rejection closes the connection (the hook itself returns nil to
	// dodge the library's nil-channel panic on the error path).
	allowed := newFakeConn(t, "10.1.2.3:3890")
	if err := hook(allowed); err != nil {
		t.Errorf("whitelisted 10.1.2.3 hook = %v", err)
	}
	if allowed.closedByHook(t) {
		t.Error("whitelisted 10.1.2.3 connection closed, want open")
	}
	bare := newFakeConn(t, "192.168.1.50:9999")
	if err := hook(bare); err != nil {
		t.Errorf("whitelisted bare IP hook = %v", err)
	}
	if bare.closedByHook(t) {
		t.Error("whitelisted bare-IP connection closed, want open")
	}
	outside := newFakeConn(t, "11.0.0.1:3890")
	if err := hook(outside); err != nil {
		t.Errorf("outside hook = %v, want nil (close signals rejection)", err)
	}
	if !outside.closedByHook(t) {
		t.Error("outside 11.0.0.1 connection left open, want closed")
	}
	if err := hook(nil); err == nil {
		t.Error("nil conn hook = nil, want error")
	}
}

func TestAllowConnEmptyMeansUnrestricted(t *testing.T) {
	hook := allowConn(nil, testLogger())
	open := newFakeConn(t, "203.0.113.7:3890")
	if err := hook(open); err != nil {
		t.Errorf("empty whitelist hook = %v", err)
	}
	if open.closedByHook(t) {
		t.Error("empty-whitelist connection closed, want open")
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

// TestMalformedFirstByteDropsOnlyItsConnection replays the 21 Nov
// 2026 incident byte-for-byte: a client sent 0x0a where the BER
// sequence tag 0x30 belongs, and upstream v1.0.1 panicked the whole
// process. The hardened library must drop only that connection while
// the server keeps answering everyone else (proven by an anonymous
// root DSE search on a fresh connection — no DB needed).
func TestMalformedFirstByteDropsOnlyItsConnection(t *testing.T) {
	s, err := New(Config{
		Mode: ModePlain, Addr: "127.0.0.1:0",
		AllowedCIDRs: []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
	}, testDeps())
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve() }()
	t.Cleanup(s.Stop)
	select {
	case <-s.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("server never became ready")
	}
	addr := s.Addr().String()

	// The offending connection: one LF, then it must be dropped.
	bad, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial offender = %v", err)
	}
	if _, err := bad.Write([]byte("\n")); err != nil {
		t.Fatalf("write garbage = %v", err)
	}
	_ = bad.SetReadDeadline(time.Now().Add(5 * time.Second))
	var one [1]byte
	if _, err := bad.Read(one[:]); err == nil {
		t.Error("offending connection stayed open and answered, want dropped")
	}
	_ = bad.Close()

	// Everyone else is unaffected: root DSE on a fresh connection.
	var lastErr error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		lastErr = nil
		func() {
			c, err := goldap.DialURL("ldap://" + addr)
			if err != nil {
				lastErr = err
				return
			}
			defer c.Close()
			res, err := c.Search(goldap.NewSearchRequest("", goldap.ScopeBaseObject,
				goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil))
			if err != nil {
				lastErr = err
				return
			}
			if len(res.Entries) != 1 {
				lastErr = errors.New("root DSE returned no entry")
			}
		}()
		if lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server stopped answering after malformed input: %v", lastErr)
}

// TestOnPanicHookLogsPeerIP proves New wires the fork's per-connection
// panic hook to slog with the offender's address (the incident panic
// carried no client IP at all).
func TestOnPanicHookLogsPeerIP(t *testing.T) {
	prev := ldapserver.OnPanic
	t.Cleanup(func() { ldapserver.OnPanic = prev })
	var buf bytes.Buffer
	deps := testDeps()
	deps.Log = slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := New(Config{
		Mode: ModePlain, Addr: "127.0.0.1:0",
		AllowedCIDRs: []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
	}, deps); err != nil {
		t.Fatalf("New = %v", err)
	}
	if ldapserver.OnPanic == nil {
		t.Fatal("OnPanic hook not installed by New")
	}
	ldapserver.OnPanic("10.9.9.9:1234", "boom", nil)
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("10.9.9.9:1234")) || !bytes.Contains([]byte(out), []byte("boom")) {
		t.Errorf("hook log = %q, want peer IP and value", out)
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
	got := defaultTree.invertMembers([]domain.User{alice, bob}, []domain.Group{eng, ops}, members)
	if len(got[alice.ID.String()]) != 2 {
		t.Errorf("alice groups = %v, want 2", got[alice.ID.String()])
	}
	if len(got[bob.ID.String()]) != 1 || got[bob.ID.String()][0] != GroupDN("ops") {
		t.Errorf("bob groups = %v, want [ops]", got[bob.ID.String()])
	}
}
