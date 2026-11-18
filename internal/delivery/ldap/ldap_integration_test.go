//go:build integration

// LDAP provider end-to-end tests against real Postgres (TECH_SPEC §9):
// a real go-ldap client binds and searches against the in-process
// listener — handlers are never mocked.
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5434/identityhub \
//	  go test -tags=integration ./internal/delivery/ldap/
package ldap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	adaptercrypto "github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/adapter/postgres"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

type ldapFixture struct {
	t      *testing.T
	db     *postgres.DB
	auth   *usecaseauth.Service
	users  *postgres.UserRepository
	groups *postgres.GroupRepository
	attrs  *postgres.UserAttrRepository
	audits *postgres.AuditRepository
	dir    *fakeDirectory
	suffix string
	conns  []*goldap.Conn
}

type nullMailer struct{}

func (nullMailer) Send(_, _, _, _ string) error { return nil }

type fakeDirectory struct {
	passwords map[string]string
}

func (f *fakeDirectory) Authenticate(_ context.Context, username, password string) (domain.LDAPUser, error) {
	want, ok := f.passwords[username]
	if !ok {
		return domain.LDAPUser{}, domain.ErrNotFound
	}
	if password != want {
		return domain.LDAPUser{}, domain.ErrUnauthorized
	}
	return domain.LDAPUser{Username: username, Email: username + "@dir.example.com", DisplayName: username}, nil
}

func (f *fakeDirectory) Snapshot(_ context.Context) (domain.DirectorySnapshot, error) {
	return domain.DirectorySnapshot{}, nil
}

func (f *fakeDirectory) Ping(_ context.Context) error { return nil }

func setupFixture(t *testing.T) *ldapFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := postgres.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)

	users := postgres.NewUserRepository(db)
	groups := postgres.NewGroupRepository(db)
	passwords := postgres.NewPasswordRepository(db)
	registry := postgres.NewSessionRegistryRepository(db)
	auditRepo := postgres.NewAuditRepository(db)
	audits := usecaseaudit.New(auditRepo, nil)
	dir := &fakeDirectory{passwords: map[string]string{}}
	authSvc, err := usecaseauth.New(usecaseauth.Deps{
		Users: users, Groups: groups, Resets: passwords, History: passwords,
		Sessions: registry, Audit: audits, Hasher: adaptercrypto.Hasher{},
		Mailer: nullMailer{}, Directory: dir, BaseURL: "http://127.0.0.1:18080",
	})
	if err != nil {
		t.Fatalf("wire auth: %v", err)
	}
	return &ldapFixture{
		t: t, db: db, auth: authSvc, users: users, groups: groups,
		attrs:  postgres.NewUserAttrRepository(db),
		audits: auditRepo, dir: dir, suffix: uuid.NewString()[:8],
	}
}

func (fx *ldapFixture) createLocalUser(username, password string, active bool) domain.User {
	fx.t.Helper()
	hash, err := adaptercrypto.Hasher{}.Hash(password)
	if err != nil {
		fx.t.Fatalf("hash: %v", err)
	}
	u, err := fx.users.Create(context.Background(), domain.User{
		Username: username + "-" + fx.suffix, Email: username + "@example.com",
		DisplayName: username, PasswordHash: hash,
		Source: domain.SourceLocal, IsActive: active,
	})
	if err != nil {
		fx.t.Fatalf("create user: %v", err)
	}
	fx.t.Cleanup(func() {
		_, _ = fx.db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID)
	})
	return u
}

func (fx *ldapFixture) createLDAPUser(username string, dirPassword string) domain.User {
	fx.t.Helper()
	full := username + "-" + fx.suffix
	fx.dir.passwords[full] = dirPassword
	u, err := fx.users.Create(context.Background(), domain.User{
		Username: full, Email: full + "@dir.example.com", DisplayName: full,
		Source: domain.SourceLDAP, ExternalDN: "uid=" + full + ",ou=users,dc=example,dc=com",
		IsActive: true,
	})
	if err != nil {
		fx.t.Fatalf("create ldap user: %v", err)
	}
	fx.t.Cleanup(func() {
		_, _ = fx.db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID)
	})
	return u
}

func (fx *ldapFixture) makeAdmin(u domain.User) {
	fx.t.Helper()
	ctx := context.Background()
	admin, err := fx.groups.ByName(ctx, domain.AdminGroup)
	if err != nil {
		fx.t.Fatalf("ih_admin missing: %v", err)
	}
	if err := fx.groups.AddMember(ctx, u.ID, admin.ID); err != nil {
		fx.t.Fatalf("add admin: %v", err)
	}
	fx.t.Cleanup(func() {
		_, _ = fx.db.Pool.Exec(context.Background(),
			`DELETE FROM user_groups WHERE user_id=$1 AND group_id=$2`, u.ID, admin.ID)
	})
}

func (fx *ldapFixture) createGroup(name string, members ...domain.User) domain.Group {
	fx.t.Helper()
	ctx := context.Background()
	g, err := fx.groups.Create(ctx, domain.Group{Name: name + "-" + fx.suffix, Description: "test"})
	if err != nil {
		fx.t.Fatalf("create group: %v", err)
	}
	fx.t.Cleanup(func() {
		_, _ = fx.db.Pool.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, g.ID)
	})
	for _, m := range members {
		if err := fx.groups.AddMember(ctx, m.ID, g.ID); err != nil {
			fx.t.Fatalf("add member: %v", err)
		}
	}
	return g
}

// startServer boots the provider on an ephemeral loopback port with the
// given mode and whitelist. Extra server config (TLS) arrives via mut.
func (fx *ldapFixture) startServer(mode string, cidrs []string, mut func(*Config)) *Server {
	fx.t.Helper()
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			fx.t.Fatalf("parse cidr: %v", err)
		}
		nets = append(nets, n)
	}
	cfg := Config{Mode: mode, Addr: "127.0.0.1:0", AllowedCIDRs: nets}
	if mut != nil {
		mut(&cfg)
	}
	srv, err := New(cfg, Deps{
		Auth: fx.auth, Users: fx.users, Groups: fx.groups, Attrs: fx.attrs,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		fx.t.Fatalf("New: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	select {
	case err := <-errCh:
		fx.t.Fatalf("Serve exited: %v", err)
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		fx.t.Fatal("server never became ready")
	}
	fx.t.Cleanup(func() {
		// Stop before closing client connections: the library races
		// a disconnect against Stop (send on closed channel), so the
		// server goes down while every client is still connected.
		srv.Stop()
		if err := <-errCh; err != nil {
			fx.t.Errorf("Serve = %v, want nil after Stop", err)
		}
		for _, c := range fx.conns {
			_ = c.Close()
		}
	})
	return srv
}

func (fx *ldapFixture) dial(addr string) *goldap.Conn {
	fx.t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	c, err := goldap.DialURL("ldap://"+addr, goldap.DialWithDialer(dialer))
	if err != nil {
		fx.t.Fatalf("dial: %v", err)
	}
	fx.conns = append(fx.conns, c)
	return c
}

func ldapCode(t *testing.T, err error) uint16 {
	t.Helper()
	var lerr *goldap.Error
	if !errors.As(err, &lerr) {
		t.Fatalf("err = %v (%T), want *ldap.Error", err, err)
	}
	return lerr.ResultCode
}

// testTLSMaterial generates a self-signed loopback certificate (in
// memory — no fixture keys on disk).
func testTLSMaterial(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "identityhub-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pemCert(t, der), pemKey(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func pemCert(t *testing.T, der []byte) []byte {
	t.Helper()
	return pemEncode(t, "CERTIFICATE", der)
}

func pemKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncode(t, "EC PRIVATE KEY", der)
}

func pemEncode(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLDAPBindAndSearch(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	eng := fx.createGroup("eng", alice)
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err != nil {
		t.Fatalf("bind alice: %v", err)
	}
	// Users subtree filtered by uid.
	res, err := c.Search(goldap.NewSearchRequest(
		UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(uid="+alice.Username+")", []string{"uid", "cn", "mail", "memberOf"}, nil,
	))
	if err != nil {
		t.Fatalf("search users: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("user entries = %d, want 1", len(res.Entries))
	}
	e := res.Entries[0]
	if e.DN != UserDN(alice.Username) {
		t.Errorf("entry DN = %q", e.DN)
	}
	if e.GetAttributeValue("mail") != "alice@example.com" {
		t.Errorf("mail = %q", e.GetAttributeValue("mail"))
	}
	if got := e.GetAttributeValues("memberOf"); len(got) != 1 || got[0] != GroupDN(eng.Name) {
		t.Errorf("memberOf = %v, want [%s]", got, GroupDN(eng.Name))
	}
	// Groups subtree.
	gres, err := c.Search(goldap.NewSearchRequest(
		GroupsDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(cn="+eng.Name+")", []string{"cn", "member"}, nil,
	))
	if err != nil {
		t.Fatalf("search groups: %v", err)
	}
	if len(gres.Entries) != 1 {
		t.Fatalf("group entries = %d, want 1", len(gres.Entries))
	}
	if got := gres.Entries[0].GetAttributeValues("member"); len(got) != 1 || got[0] != UserDN(alice.Username) {
		t.Errorf("member = %v, want [%s]", got, UserDN(alice.Username))
	}
	// POSIX view for SSSD (rfc2307bis): posixAccount filter matches and
	// the numeric IDs round-trip from the assigned columns.
	pres, err := c.Search(goldap.NewSearchRequest(
		UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=posixAccount)(uid="+alice.Username+"))",
		[]string{"uidNumber", "gidNumber", "homeDirectory", "loginShell", "gecos"}, nil,
	))
	if err != nil {
		t.Fatalf("search posix users: %v", err)
	}
	if len(pres.Entries) != 1 {
		t.Fatalf("posix user entries = %d, want 1", len(pres.Entries))
	}
	pe := pres.Entries[0]
	if pe.GetAttributeValue("uidNumber") != strconv.Itoa(alice.UIDNumber) {
		t.Errorf("uidNumber = %q, want %d", pe.GetAttributeValue("uidNumber"), alice.UIDNumber)
	}
	if pe.GetAttributeValue("gidNumber") != strconv.Itoa(alice.UIDNumber) {
		t.Errorf("gidNumber = %q, want user-private-group %d", pe.GetAttributeValue("gidNumber"), alice.UIDNumber)
	}
	if pe.GetAttributeValue("homeDirectory") != "/home/"+alice.Username {
		t.Errorf("homeDirectory = %q", pe.GetAttributeValue("homeDirectory"))
	}
	gpres, err := c.Search(goldap.NewSearchRequest(
		GroupsDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=posixGroup)",
		[]string{"cn", "gidNumber"}, nil,
	))
	if err != nil {
		t.Fatalf("search posix groups: %v", err)
	}
	found := false
	for _, ge := range gpres.Entries {
		if ge.GetAttributeValue("cn") == eng.Name {
			found = true
			if ge.GetAttributeValue("gidNumber") != strconv.Itoa(eng.GIDNumber) {
				t.Errorf("gidNumber = %q, want %d", ge.GetAttributeValue("gidNumber"), eng.GIDNumber)
			}
		}
	}
	if !found {
		t.Errorf("posixGroup search missed %q", eng.Name)
	}
	// The bind was audited as a successful ldap login.
	entries, _, err := fx.audits.List(context.Background(), domain.AuditFilter{
		ActorUserID: &alice.ID, Method: domain.MethodLDAP, Result: domain.ResultSuccess, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IP != "127.0.0.1" {
		t.Errorf("audit entries = %+v, want one ldap success from 127.0.0.1", entries)
	}
}

func TestLDAPMemberFilterNormalizesDN(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	eng := fx.createGroup("eng", alice)
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err != nil {
		t.Fatalf("bind alice: %v", err)
	}
	// VPN boxes substitute their own DN templates into member= filters;
	// spacing and casing variants must still match (FortiGate case).
	dn := UserDN(alice.Username)
	for _, variant := range []string{
		dn,
		"uid=" + alice.Username + ", ou=users, dc=identityhub",
		"UID=" + alice.Username + ",OU=USERS,DC=IDENTITYHUB",
	} {
		res, err := c.Search(goldap.NewSearchRequest(
			GroupsDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=groupOfNames)(member="+variant+"))", []string{"cn"}, nil,
		))
		if err != nil {
			t.Fatalf("search %q: %v", variant, err)
		}
		if len(res.Entries) != 1 || res.Entries[0].DN != GroupDN(eng.Name) {
			t.Fatalf("search %q = %v, want [%s]", variant, res.Entries, GroupDN(eng.Name))
		}
	}
}

func TestLDAPBindCacheInvalidatesOnPasswordChange(t *testing.T) {
	fx := setupFixture(t)
	ctx := context.Background()
	alice := fx.createLocalUser("alice", "alice-password-1", true)

	// Wired by hand: the shared harness predates the version store.
	versions := postgres.NewDirectoryVersionRepository(fx.db)
	srv2, err := New(
		Config{Mode: ModePlain, Addr: "127.0.0.1:0", AllowedCIDRs: mustCIDRs(t, "127.0.0.0/8"), CacheTTL: time.Minute, BindCacheTTL: time.Minute},
		Deps{Auth: fx.auth, Users: fx.users, Groups: fx.groups, Attrs: fx.attrs, Version: versions,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv2.Serve() }()
	select {
	case <-srv2.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("server never became ready")
	}
	t.Cleanup(srv2.Stop)

	c := fx.dial(srv2.Addr().String())
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	// A password change bumps the directory version, so the remembered
	// bind must not authenticate anymore.
	hash, err := adaptercrypto.Hasher{}.Hash("alice-password-2")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := fx.users.SetPasswordHash(ctx, alice.ID, hash); err != nil {
		t.Fatalf("set hash: %v", err)
	}
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err == nil {
		t.Fatal("old password still binds after change, want rejection")
	}
	if err := c.Bind(UserDN(alice.Username), "alice-password-2"); err != nil {
		t.Fatalf("new password bind: %v", err)
	}
}

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse cidr: %v", err)
		}
		out = append(out, n)
	}
	return out
}

func TestLDAPCustomAttrs(t *testing.T) {
	fx := setupFixture(t)
	ctx := context.Background()
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	deptKey := "ldept-" + fx.suffix
	dept, err := fx.attrs.CreateDef(ctx, domain.UserAttrDef{Key: deptKey, Type: domain.UserAttrString})
	if err != nil {
		t.Fatalf("create def: %v", err)
	}
	t.Cleanup(func() {
		_ = fx.attrs.DeleteDef(context.Background(), deptKey)
	})
	if err := fx.attrs.SetValues(ctx, alice.ID,
		map[uuid.UUID][]string{dept.ID: {"eng"}}, domain.UserAttrAdmin); err != nil {
		t.Fatalf("set values: %v", err)
	}
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err != nil {
		t.Fatalf("bind alice: %v", err)
	}
	// Point lookup carries the custom attribute.
	res, err := c.Search(goldap.NewSearchRequest(
		UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(uid="+alice.Username+")", []string{"uid", deptKey}, nil,
	))
	if err != nil {
		t.Fatalf("point search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue(deptKey) != "eng" {
		t.Fatalf("point entries = %+v, want dept=eng", res.Entries)
	}
	// Custom attributes are searchable and the listing path agrees.
	res, err = c.Search(goldap.NewSearchRequest(
		UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"("+deptKey+"=eng)", []string{"uid", deptKey}, nil,
	))
	if err != nil {
		t.Fatalf("custom filter search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("uid") != alice.Username {
		t.Fatalf("custom filter entries = %+v", res.Entries)
	}
	// Base-scope leaf read carries it too.
	res, err = c.Search(goldap.NewSearchRequest(
		UserDN(alice.Username), goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{deptKey}, nil,
	))
	if err != nil {
		t.Fatalf("leaf search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue(deptKey) != "eng" {
		t.Fatalf("leaf entries = %+v, want dept=eng", res.Entries)
	}
}

func TestLDAPBindFailures(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	root := fx.createLocalUser("root", "root-password-0001", true)
	fx.makeAdmin(root)
	off := fx.createLocalUser("off", "off-password-00001", false)
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	bind := func(dn, password string) error {
		c := fx.dial(srv.Addr().String())
		return c.Bind(dn, password)
	}
	// Wrong password: generic invalid credentials (49).
	if err := bind(UserDN(alice.Username), "wrong-password"); ldapCode(t, err) != 49 {
		t.Errorf("bad password code = %v, want 49", err)
	}
	// Unknown user: same generic code (no enumeration).
	if err := bind(UserDN("ghost-"+fx.suffix), "whatever-00000"); ldapCode(t, err) != 49 {
		t.Errorf("unknown user code = %v, want 49", err)
	}
	// Malformed DN: rejected with a hint, not audited as a login.
	err := bind("cn="+alice.Username+","+UsersDN, "alice-password-1")
	if code := ldapCode(t, err); code != 49 {
		t.Errorf("malformed DN code = %d, want 49", code)
	} else if lerr := err.(*goldap.Error); !strings.Contains(lerr.Error(), "uid=<username>") {
		t.Errorf("malformed DN diagnostic = %q, want bind-DN hint", lerr.Error())
	}
	// Empty password never binds. (go-ldap's Bind refuses empty
	// passwords client-side, so UnauthenticatedBind carries the raw
	// empty bind to the server.)
	c := fx.dial(srv.Addr().String())
	if err := c.UnauthenticatedBind(UserDN(alice.Username)); ldapCode(t, err) != 49 {
		t.Errorf("empty password code = %v, want 49", err)
	}
	// Admin with a correct password is denied: MFA is mandatory and a
	// legacy bind cannot prompt for a second factor.
	err = bind(UserDN(root.Username), "root-password-0001")
	if code := ldapCode(t, err); code != 49 {
		t.Errorf("admin code = %d, want 49", code)
	} else if lerr := err.(*goldap.Error); !strings.Contains(lerr.Error(), "multi-factor") {
		t.Errorf("admin diagnostic = %q, want mfa explanation", lerr.Error())
	}
	// Disabled account.
	if err := bind(UserDN(off.Username), "off-password-00001"); ldapCode(t, err) != 49 {
		t.Errorf("disabled code = %v, want 49", err)
	}
	// Every credential check above was audited exactly once.
	entries, _, err := fx.audits.List(context.Background(), domain.AuditFilter{
		ActorUserID: &root.ID, Method: domain.MethodLDAP, Result: domain.ResultFailure, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Detail["reason"] != "mfa required" {
		t.Errorf("admin audit = %+v, want one mfa-required failure", entries)
	}
}

func TestLDAPSearchRequiresBind(t *testing.T) {
	fx := setupFixture(t)
	fx.createLocalUser("alice", "alice-password-1", true)
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	_, err := c.Search(goldap.NewSearchRequest(
		UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"uid"}, nil,
	))
	if ldapCode(t, err) != 50 {
		t.Errorf("anonymous search code = %v, want 50 (insufficient access)", err)
	}
}

func TestLDAPSearchScopesAndFilters(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	search := func(base string, scope int, filter string) *goldap.SearchResult {
		t.Helper()
		res, err := c.Search(goldap.NewSearchRequest(
			base, scope, goldap.NeverDerefAliases, 0, 0, false, filter, nil, nil,
		))
		if err != nil {
			t.Fatalf("search(%s %d %s) = %v", base, scope, filter, err)
		}
		return res
	}
	// Base DN single level: the two OUs.
	res := search(BaseDN, goldap.ScopeSingleLevel, "(objectClass=*)")
	if len(res.Entries) != 2 {
		t.Errorf("base single-level = %d entries, want 2 (ou=users, ou=groups)", len(res.Entries))
	}
	// Base scope on the user's own DN.
	res = search(UserDN(alice.Username), goldap.ScopeBaseObject, "(objectClass=*)")
	if len(res.Entries) != 1 || res.Entries[0].DN != UserDN(alice.Username) {
		t.Errorf("leaf base search = %+v, want the user entry", res.Entries)
	}
	// AND filter with an attribute that matches nothing.
	res = search(UsersDN, goldap.ScopeWholeSubtree, "(&(uid="+alice.Username+")(uid=nobody-here))")
	if len(res.Entries) != 0 {
		t.Errorf("no-match filter = %d entries, want 0", len(res.Entries))
	}
	// Unknown base DN.
	_, err := c.Search(goldap.NewSearchRequest(
		"ou=nowhere,"+BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil,
	))
	if ldapCode(t, err) != 32 {
		t.Errorf("unknown base code = %v, want 32 (no such object)", err)
	}
	// Root DSE answers without entries leaking.
	res = search("", goldap.ScopeBaseObject, "(objectClass=*)")
	if len(res.Entries) != 1 || len(res.Entries[0].GetAttributeValues("namingContexts")) != 1 {
		t.Errorf("root DSE = %+v", res.Entries)
	}
}

func TestLDAPDirectoryUserBind(t *testing.T) {
	fx := setupFixture(t)
	dave := fx.createLDAPUser("dave", "dir-password-01")
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	if err := c.Bind(UserDN(dave.Username), "dir-password-01"); err != nil {
		t.Fatalf("directory bind: %v", err)
	}
	if err := c.Bind(UserDN(dave.Username), "wrong-password"); ldapCode(t, err) != 49 {
		t.Errorf("directory bad password code = %v, want 49", err)
	}
}

func TestLDAPWhitelistRejects(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	// Loopback is outside 10/8: TCP accepts, then the hook closes the
	// connection before any LDAP bytes are parsed.
	srv := fx.startServer(ModePlain, []string{"10.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err == nil {
		t.Error("bind from non-whitelisted IP succeeded, want connection close")
	}
	// Nothing was verified, so nothing was audited.
	entries, _, err := fx.audits.List(context.Background(), domain.AuditFilter{
		ActorUserID: &alice.ID, Method: domain.MethodLDAP, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("audit entries = %d, want 0 (rejected pre-parse)", len(entries))
	}
}

func TestLDAPStartTLS(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	srv := fx.startServer(ModeStartTLS, nil, func(c *Config) {
		c.TLSConfig = testTLSMaterial(t)
	})

	c := fx.dial(srv.Addr().String())
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("starttls: %v", err)
	}
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err != nil {
		t.Fatalf("bind over starttls: %v", err)
	}
	res, err := c.Search(goldap.NewSearchRequest(
		UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false,
		"(uid="+alice.Username+")", []string{"uid"}, nil,
	))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("search over starttls = %+v, %v", res, err)
	}
}

func TestLDAPLDAPS(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createLocalUser("alice", "alice-password-1", true)
	srv := fx.startServer(ModeLDAPS, nil, func(c *Config) {
		c.TLSConfig = testTLSMaterial(t)
	})

	c, err := goldap.DialTLS("tcp", srv.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial ldaps: %v", err)
	}
	fx.conns = append(fx.conns, c)
	if err := c.Bind(UserDN(alice.Username), "alice-password-1"); err != nil {
		t.Fatalf("bind over ldaps: %v", err)
	}
	// StartTLS on an already-encrypted connection is refused.
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Error("starttls over ldaps succeeded, want refusal")
	}
}

func TestLDAPStartTLSRejectedWithoutTLS(t *testing.T) {
	fx := setupFixture(t)
	fx.createLocalUser("alice", "alice-password-1", true)
	srv := fx.startServer(ModePlain, []string{"127.0.0.0/8"}, nil)

	c := fx.dial(srv.Addr().String())
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Error("starttls in plaintext mode succeeded, want refusal")
	}
}
