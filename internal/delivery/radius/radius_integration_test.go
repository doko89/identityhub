//go:build integration

// RADIUS provider end-to-end tests against real Postgres (TECH_SPEC §9):
// a real layeh client exchanges PAP Access-Requests with the in-process
// listener — handlers are never mocked.
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5434/identityhub \
//	  go test -tags=integration ./internal/delivery/radius/
package radius

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	"github.com/google/uuid"

	adaptercrypto "github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/adapter/postgres"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

const nasSecret = "test-nas-secret-01"

type radiusFixture struct {
	t       *testing.T
	db      *postgres.DB
	auth    *usecaseauth.Service
	users   *postgres.UserRepository
	groups  *postgres.GroupRepository
	audits  *postgres.AuditRepository
	clients *postgres.RADIUSClientRepository
	encKey  [32]byte
	appID   uuid.UUID
	suffix  string
}

type nullMailer struct{}

func (nullMailer) Send(_, _, _, _ string) error { return nil }

func setupFixture(t *testing.T) *radiusFixture {
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
	authSvc, err := usecaseauth.New(usecaseauth.Deps{
		Users: users, Groups: groups, Resets: passwords, History: passwords,
		Sessions: registry, Audit: audits, Hasher: adaptercrypto.Hasher{},
		Mailer: nullMailer{}, BaseURL: "http://127.0.0.1:18080",
	})
	if err != nil {
		t.Fatalf("wire auth: %v", err)
	}
	var encKey [32]byte
	copy(encKey[:], "0123456789abcdef0123456789abcdef")
	fx := &radiusFixture{
		t: t, db: db, auth: authSvc, users: users, groups: groups,
		audits: auditRepo, clients: postgres.NewRADIUSClientRepository(db),
		encKey: encKey, suffix: uuid.NewString()[:8],
	}
	// One VPN application with the loopback registered as its NAS.
	fx.appID = uuid.New()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO applications (id, slug, name, provider_type)
		VALUES ($1, $2, 'radius test app', 'radius')`, fx.appID, "radius-fx-"+fx.suffix); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, fx.appID)
	})
	sealed, err := adaptercrypto.Seal(encKey, []byte(nasSecret))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	c, err := fx.clients.Create(ctx, domain.RADIUSClient{
		ApplicationID: fx.appID, NASIdentifier: "127.0.0.1", SharedSecretEnc: sealed,
	})
	if err != nil {
		t.Fatalf("seed NAS: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM radius_clients WHERE id=$1`, c.ID)
	})
	return fx
}

func (fx *radiusFixture) createUser(username, password string, active bool) domain.User {
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

func (fx *radiusFixture) makeAdmin(u domain.User) {
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

func (fx *radiusFixture) startServer() *Server {
	fx.t.Helper()
	srv, err := New(Config{Addr: "127.0.0.1:0", EncKey: fx.encKey}, Deps{
		Auth: fx.auth, Clients: fx.clients,
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			fx.t.Errorf("Shutdown = %v", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, ErrServerShutdown) {
			fx.t.Errorf("Serve = %v, want clean shutdown", err)
		}
	})
	return srv
}

// accessRequest sends one PAP request and returns the response code and
// Reply-Message.
func accessRequest(t *testing.T, addr, secret, username, password string) (radius.Code, string) {
	t.Helper()
	p := radius.New(radius.CodeAccessRequest, []byte(secret))
	if err := rfc2865.UserName_SetString(p, username); err != nil {
		t.Fatal(err)
	}
	if err := rfc2865.UserPassword_SetString(p, password); err != nil {
		t.Fatal(err)
	}
	client := &radius.Client{Retry: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Exchange(ctx, p, addr)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return resp.Code, rfc2865.ReplyMessage_GetString(resp)
}

func TestRADIUSAcceptAndAudit(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createUser("alice", "alice-password-1", true)
	srv := fx.startServer()

	code, _ := accessRequest(t, srv.Addr().String(), nasSecret, alice.Username, "alice-password-1")
	if code != radius.CodeAccessAccept {
		t.Fatalf("code = %v, want Access-Accept", code)
	}
	entries, _, err := fx.audits.List(context.Background(), domain.AuditFilter{
		ActorUserID: &alice.ID, Method: domain.MethodRADIUS, Result: domain.ResultSuccess, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1 radius success", len(entries))
	}
	if entries[0].ApplicationID == nil || *entries[0].ApplicationID != fx.appID {
		t.Errorf("audit app = %v, want %v (NAS application)", entries[0].ApplicationID, fx.appID)
	}
	if entries[0].IP != "127.0.0.1" {
		t.Errorf("audit ip = %q, want NAS source 127.0.0.1", entries[0].IP)
	}
}

func TestRADIUSRejects(t *testing.T) {
	fx := setupFixture(t)
	alice := fx.createUser("alice", "alice-password-1", true)
	root := fx.createUser("root", "root-password-0001", true)
	fx.makeAdmin(root)
	off := fx.createUser("off", "off-password-00001", false)
	srv := fx.startServer()
	addr := srv.Addr().String()

	cases := []struct {
		name     string
		username string
		password string
		message  string // Reply-Message substring; "" skips the check
	}{
		{"bad password", alice.Username, "wrong-password", "invalid credentials"},
		{"unknown user", "ghost-" + fx.suffix, "whatever-00000", "invalid credentials"},
		{"disabled", off.Username, "off-password-00001", "account disabled"},
		{"admin needs mfa", root.Username, "root-password-0001", "multi-factor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := accessRequest(t, addr, nasSecret, tc.username, tc.password)
			if code != radius.CodeAccessReject {
				t.Fatalf("code = %v, want Access-Reject", code)
			}
			if tc.message != "" && !strings.Contains(msg, tc.message) {
				t.Errorf("reply-message = %q, want substring %q", msg, tc.message)
			}
		})
	}
	entries, _, err := fx.audits.List(context.Background(), domain.AuditFilter{
		ActorUserID: &root.ID, Method: domain.MethodRADIUS, Result: domain.ResultFailure, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Detail["reason"] != "mfa required" {
		t.Errorf("admin audit = %+v, want one mfa-required failure", entries)
	}
}

func TestRADIUSRequiresPAP(t *testing.T) {
	fx := setupFixture(t)
	fx.createUser("alice", "alice-password-1", true)
	srv := fx.startServer()

	// User-Name without User-Password (CHAP-style or empty): rejected,
	// since v1 speaks PAP only.
	p := radius.New(radius.CodeAccessRequest, []byte(nasSecret))
	if err := rfc2865.UserName_SetString(p, "alice"); err != nil {
		t.Fatal(err)
	}
	client := &radius.Client{Retry: 200 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Exchange(ctx, p, srv.Addr().String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Code != radius.CodeAccessReject {
		t.Fatalf("code = %v, want Access-Reject", resp.Code)
	}
	if msg := rfc2865.ReplyMessage_GetString(resp); !strings.Contains(msg, "PAP") {
		t.Errorf("reply-message = %q, want PAP hint", msg)
	}
}

func TestRADIUSUnknownNASDropped(t *testing.T) {
	fx := setupFixture(t)
	// A server whose registry is empty drops loopback packets: no
	// shared secret exists to verify them, so there is no response.
	srv, err := New(Config{Addr: "127.0.0.1:0", EncKey: fx.encKey}, Deps{
		Auth: fx.auth, Clients: stubClients{},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv.Serve() }()
	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("server never became ready")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	p := radius.New(radius.CodeAccessRequest, []byte(nasSecret))
	if err := rfc2865.UserName_SetString(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := rfc2865.UserPassword_SetString(p, "alice-password-1"); err != nil {
		t.Fatal(err)
	}
	client := &radius.Client{Retry: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := client.Exchange(ctx, p, srv.Addr().String()); err == nil {
		t.Fatal("exchange with unknown NAS answered, want drop (timeout)")
	}
}

func TestRADIUSWrongSecretDropped(t *testing.T) {
	fx := setupFixture(t)
	fx.createUser("alice", "alice-password-1", true)
	srv := fx.startServer()

	// A packet sealed with the wrong secret fails verification and is
	// dropped, never answered.
	p := radius.New(radius.CodeAccessRequest, []byte("wrong-secret-000"))
	if err := rfc2865.UserName_SetString(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := rfc2865.UserPassword_SetString(p, "alice-password-1"); err != nil {
		t.Fatal(err)
	}
	client := &radius.Client{Retry: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := client.Exchange(ctx, p, srv.Addr().String()); err == nil {
		t.Fatal("exchange with wrong secret answered, want drop (timeout)")
	}
}
