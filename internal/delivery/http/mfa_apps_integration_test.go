//go:build integration

// MFA + dashboard + uploads end-to-end tests against real Postgres
// (TECH_SPEC §9): TOTP enroll/verify with atomic anti-replay, recovery
// codes, admin MFA policy + MFA-loss reset, app bindings, launch gates,
// and webp uploads.
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5434/identityhub \
//	  go test -tags=integration ./internal/delivery/http/ -run 'TestMFA|TestDashboard|TestUploads|TestPasswordChangeReAuth'
package http

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	adaptercrypto "github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/adapter/postgres"
	"github.com/identityhub/identityhub/internal/adapter/storage"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseapp "github.com/identityhub/identityhub/internal/usecase/app"
	usecaseasset "github.com/identityhub/identityhub/internal/usecase/asset"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
	usecasemfa "github.com/identityhub/identityhub/internal/usecase/mfa"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
)

type mfaFixture struct {
	t        *testing.T
	srv      *httptest.Server
	users    *postgres.UserRepository
	groups   *postgres.GroupRepository
	password string
	totp     adaptercrypto.TOTP
}

func setupMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}
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
	auditRepo := postgres.NewAuditRepository(db)
	passwords := postgres.NewPasswordRepository(db)
	registry := postgres.NewSessionRegistryRepository(db)
	mfaRepo := postgres.NewMFARepository(db)
	appRepo := postgres.NewApplicationRepository(db)
	bindingRepo := postgres.NewBindingRepository(db)
	assetRepo := postgres.NewAssetRepository(db)
	audits := usecaseaudit.New(auditRepo, nil)

	var encKey [32]byte
	copy(encKey[:], "0123456789abcdef0123456789abcdef")
	sealer := adaptercrypto.Sealer{Key: encKey}

	files, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("wire storage: %v", err)
	}
	appSvc, err := usecaseapp.New(usecaseapp.Deps{
		Apps: appRepo, Bindings: bindingRepo, Users: users, Groups: groups,
	})
	if err != nil {
		t.Fatalf("wire app: %v", err)
	}
	mfaSvc, err := usecasemfa.New(usecasemfa.Deps{
		Store: mfaRepo, Users: users, Groups: groups, Apps: appRepo,
		TOTP: adaptercrypto.TOTP{}, Sealer: sealer, Audit: audits, Mailer: nullMailer{},
	})
	if err != nil {
		t.Fatalf("wire mfa: %v", err)
	}
	assetSvc, err := usecaseasset.New(usecaseasset.Deps{Assets: assetRepo, Storage: files})
	if err != nil {
		t.Fatalf("wire asset: %v", err)
	}
	authSvc, err := usecaseauth.New(usecaseauth.Deps{
		Users: users, Groups: groups, Resets: passwords, History: passwords,
		Sessions: registry, Audit: audits, Hasher: adaptercrypto.Hasher{},
		Mailer: nullMailer{}, MFAPolicy: mfaSvc, BaseURL: testIssuer(),
	})
	if err != nil {
		t.Fatalf("wire auth: %v", err)
	}
	userSvc, err := usecaseuser.New(usecaseuser.Deps{
		Users: users, Groups: groups, Sessions: registry, Audit: audits, Hasher: adaptercrypto.Hasher{},
	})
	if err != nil {
		t.Fatalf("wire user: %v", err)
	}
	sessions := NewSessionManager(db.Pool, SessionConfig{
		IdleTimeout: 30 * time.Minute, Lifetime: 12 * time.Hour,
	})
	handlers := NewHandlers(HandlerDeps{
		Sessions: sessions, Registry: registry, Auth: authSvc, Users: userSvc,
		Audits: audits, Groups: groups,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MFA: mfaSvc, Apps: appSvc, Assets: assetSvc, Storage: files, Sealer: sealer,
	})
	srv := httptest.NewServer(NewRouter(Deps{Sessions: sessions, DB: db, Handlers: handlers}))
	t.Cleanup(srv.Close)
	return &mfaFixture{
		t: t, srv: srv, users: users, groups: groups,
		password: "integration-test-password-1", totp: adaptercrypto.TOTP{},
	}
}

func (fx *mfaFixture) browser() *http.Client {
	fx.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		fx.t.Fatal(err)
	}
	return noRedirectClient(jar)
}

func (fx *mfaFixture) mkuser(prefix string) domain.User {
	fx.t.Helper()
	tag := uuid.NewString()[:8]
	hash, err := adaptercrypto.Hasher{}.Hash(fx.password)
	if err != nil {
		fx.t.Fatal(err)
	}
	u, err := fx.users.Create(context.Background(), domain.User{
		Username: prefix + "-" + tag, Email: prefix + "-" + tag + "@example.com",
		DisplayName: prefix, PasswordHash: hash,
		Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		fx.t.Fatal(err)
	}
	return u
}

func (fx *mfaFixture) mkadmin(prefix string) domain.User {
	fx.t.Helper()
	u := fx.mkuser(prefix)
	admin, err := fx.groups.ByName(context.Background(), domain.AdminGroup)
	if err != nil {
		fx.t.Fatal(err)
	}
	if err := fx.groups.AddMember(context.Background(), u.ID, admin.ID); err != nil {
		fx.t.Fatal(err)
	}
	return u
}

func doJSON(t *testing.T, c *http.Client, method, url string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// login posts a password login and returns status + decoded body.
func (fx *mfaFixture) login(c *http.Client, username string) (int, map[string]any) {
	fx.t.Helper()
	return doJSON(fx.t, c, http.MethodPost, fx.srv.URL+"/api/auth/login", map[string]any{
		"username": username, "password": fx.password,
	})
}

// enroll runs start+confirm for the browser's subject and returns the
// recovery codes. The confirm code comes from the previous step so the
// current step stays fresh for the login verify that follows (no
// 30s-boundary waiting).
func (fx *mfaFixture) enroll(c *http.Client) []string {
	fx.t.Helper()
	fx.waitMidStep()
	code, body := doJSON(fx.t, c, http.MethodPost, fx.srv.URL+"/api/account/mfa/enroll", map[string]any{})
	if code != http.StatusOK {
		fx.t.Fatalf("enroll start = %d (%v)", code, body)
	}
	secret, _ := body["secret"].(string)
	if secret == "" || body["otpauth_url"] == "" || body["qr_png"] == "" {
		fx.t.Fatalf("enroll must return secret, otpauth_url and qr_png: %v", body)
	}
	step := time.Now().Unix() / 30
	confirm, confirmBody := doJSON(fx.t, c, http.MethodPost, fx.srv.URL+"/api/account/mfa/enroll/confirm", map[string]any{
		"code": fx.totpCode(secret, step-1),
	})
	if confirm != http.StatusOK {
		fx.t.Fatalf("enroll confirm = %d (%v)", confirm, confirmBody)
	}
	raw, _ := confirmBody["recovery_codes"].([]any)
	if len(raw) != usecasemfa.RecoveryCodeCount {
		fx.t.Fatalf("confirm must return %d recovery codes: %v", usecasemfa.RecoveryCodeCount, confirmBody)
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// waitMidStep sleeps until the TOTP step is safely away from a rollover
// boundary, so codes computed right after stay valid through the HTTP
// round trip (bounded ~8s).
func (fx *mfaFixture) waitMidStep() {
	fx.t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for {
		sec := time.Now().Unix() % 30
		if sec <= 22 {
			return
		}
		if time.Now().After(deadline) {
			fx.t.Fatal("timed out waiting for a fresh TOTP step")
		}
		time.Sleep(time.Duration(30-sec+1) * time.Second)
	}
}

// totpCode computes the code for an enroll secret at an absolute step.
func (fx *mfaFixture) totpCode(secretB32 string, step int64) string {
	fx.t.Helper()
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		fx.t.Fatal(err)
	}
	code, err := fx.totp.Code(seed, step)
	if err != nil {
		fx.t.Fatal(err)
	}
	return code
}

// secretOf grabs a fresh enroll secret for code computation. It starts
// (but does not finish) a second enrollment... instead it reuses the
// pending session seed: enroll start fails when already enrolled, so
// callers that need post-enroll codes must keep the secret from enroll().
func (fx *mfaFixture) currentCode(secretB32 string) string {
	fx.t.Helper()
	fx.waitMidStep()
	return fx.totpCode(secretB32, time.Now().Unix()/30)
}

func TestMFAEnrollVerifyE2E(t *testing.T) {
	fx := setupMFAFixture(t)
	bob := fx.mkuser("mfa-bob")
	b := fx.browser()

	// No factors yet: password login completes directly.
	code, body := fx.login(b, bob.Username)
	if code != 200 || body["mfa_required"] == true {
		t.Fatalf("unenrolled login = %d %v, want direct login", code, body)
	}
	// Enroll, then log out: the next login must stop at the second step.
	fx.enroll(b)
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/logout", nil); code != 204 {
		t.Fatalf("logout = %d, want 204", code)
	}
	code, body = fx.login(b, bob.Username)
	if code != 200 || body["mfa_required"] != true || body["setup_required"] == true {
		t.Fatalf("enrolled login = %d %v, want mfa_required without setup", code, body)
	}
	if _, ok := body["user"]; !ok {
		t.Fatal("pending login must name the user for the /mfa page")
	}
}

func TestMFALoginVerifyAndReplay(t *testing.T) {
	fx := setupMFAFixture(t)
	bob := fx.mkuser("mfa-verify")
	b := fx.browser()
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("login = %d", code)
	}
	// Capture the secret for post-enroll codes.
	fx.waitMidStep()
	code, body := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/account/mfa/enroll", map[string]any{})
	if code != 200 {
		t.Fatalf("enroll = %d (%v)", code, body)
	}
	secret, _ := body["secret"].(string)
	step := time.Now().Unix() / 30
	if code, body := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/account/mfa/enroll/confirm", map[string]any{
		"code": fx.totpCode(secret, step-1),
	}); code != 200 {
		t.Fatalf("confirm = %d (%v)", code, body)
	}
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/logout", nil); code != 204 {
		t.Fatalf("logout = %d", code)
	}
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("second login = %d", code)
	}
	// Wrong code first: 401, audited, and the session stays pending.
	if code, body := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/mfa/totp", map[string]any{
		"code": "000000",
	}); code != 401 {
		t.Fatalf("bad code = %d (%v), want 401", code, body)
	}
	// Fresh code completes the login.
	fresh := fx.currentCode(secret)
	if code, body := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/mfa/totp", map[string]any{
		"code": fresh,
	}); code != 200 || body["mfa_required"] == true {
		t.Fatalf("verify = %d (%v), want completed login", code, body)
	}
	// The same code can never verify twice (atomic anti-replay): log
	// out, pass the password again, and replay.
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/logout", nil); code != 204 {
		t.Fatalf("logout = %d", code)
	}
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("third login = %d", code)
	}
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/mfa/totp", map[string]any{
		"code": fresh,
	}); code != 401 {
		t.Fatalf("replayed code = %d, want 401", code)
	}
}

func TestMFARecoveryCodeE2E(t *testing.T) {
	fx := setupMFAFixture(t)
	bob := fx.mkuser("mfa-rec")
	b := fx.browser()
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("login = %d", code)
	}
	codes := fx.enroll(b)
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/logout", nil); code != 204 {
		t.Fatalf("logout = %d", code)
	}
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("second login = %d", code)
	}
	// Unknown recovery code: 401.
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/mfa/totp", map[string]any{
		"recovery_code": "AAAA-BBBB-CCCC-DDDD",
	}); code != 401 {
		t.Fatalf("unknown recovery code = %d, want 401", code)
	}
	// Real code completes the login exactly once.
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/mfa/totp", map[string]any{
		"recovery_code": codes[0],
	}); code != 200 {
		t.Fatalf("recovery login = %d, want 200", code)
	}
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/logout", nil); code != 204 {
		t.Fatalf("logout = %d", code)
	}
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("third login = %d", code)
	}
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/mfa/totp", map[string]any{
		"recovery_code": codes[0],
	}); code != 401 {
		t.Fatalf("reused recovery code = %d, want 401", code)
	}
	// Both fields set (or none) is a 400.
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/mfa/totp", map[string]any{
		"code": "123456", "recovery_code": codes[1],
	}); code != 400 {
		t.Fatalf("both codes = %d, want 400", code)
	}
}

func TestMFAAdminPolicyAndLoss(t *testing.T) {
	fx := setupMFAFixture(t)
	root := fx.mkadmin("mfa-root")
	r := fx.browser()

	// Unenrolled admin: password login parks at setup.
	code, body := fx.login(r, root.Username)
	if code != 200 || body["mfa_required"] != true || body["setup_required"] != true {
		t.Fatalf("admin login = %d %v, want mfa setup", code, body)
	}
	// Pending sessions reach neither the API nor the admin console.
	if code, _ := doJSON(t, r, http.MethodGet, fx.srv.URL+"/api/auth/me", nil); code != 401 {
		t.Fatalf("pending /me = %d, want 401", code)
	}
	if code, _ := doJSON(t, r, http.MethodGet, fx.srv.URL+"/api/admin/users", nil); code != 401 {
		t.Fatalf("pending /admin = %d, want 401", code)
	}
	// Enroll on the pending session: doubles as the second step and
	// promotes to a full admin session carrying fresh MFA.
	fx.enroll(r)
	if code, body := doJSON(t, r, http.MethodGet, fx.srv.URL+"/api/auth/me", nil); code != 200 {
		t.Fatalf("promoted /me = %d (%v)", code, body)
	} else if user, _ := body["user"].(map[string]any); user["is_admin"] != true {
		t.Fatalf("promoted user must be admin: %v", body)
	}
	if code, _ := doJSON(t, r, http.MethodGet, fx.srv.URL+"/api/admin/users?limit=1", nil); code != 200 {
		t.Fatalf("admin API with MFA = %d, want 200", code)
	}

	// MFA-loss flow (PRD §10): bob loses his factors, the admin resets
	// them, bob logs straight in and re-enrolls.
	bob := fx.mkuser("mfa-loss")
	b := fx.browser()
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("bob login = %d", code)
	}
	fx.enroll(b)
	resetURL := fx.srv.URL + "/api/admin/users/" + bob.ID.String() + "/mfa/reset"
	if code, _ := doJSON(t, b, http.MethodPost, resetURL, map[string]any{}); code != 403 {
		t.Fatalf("non-admin reset = %d, want 403", code)
	}
	if code, _ := doJSON(t, r, http.MethodPost, resetURL, map[string]any{}); code != 204 {
		t.Fatalf("admin reset = %d, want 204", code)
	}
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/logout", nil); code != 204 {
		t.Fatalf("logout = %d", code)
	}
	if code, body := fx.login(b, bob.Username); code != 200 || body["mfa_required"] == true {
		t.Fatalf("post-reset login = %d %v, want direct login", code, body)
	}
}

func TestMFASelfService(t *testing.T) {
	fx := setupMFAFixture(t)
	bob := fx.mkuser("mfa-self")
	b := fx.browser()
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("login = %d", code)
	}
	statusURL := fx.srv.URL + "/api/account/mfa/status"
	if code, body := doJSON(t, b, http.MethodGet, statusURL, nil); code != 200 || body["has_totp"] == true {
		t.Fatalf("unenrolled status = %d %v", code, body)
	}
	fx.enroll(b)
	if code, body := doJSON(t, b, http.MethodGet, statusURL, nil); code != 200 {
		t.Fatalf("status = %d", code)
	} else if body["has_totp"] != true || body["remaining_recovery_codes"] != float64(usecasemfa.RecoveryCodeCount) {
		t.Fatalf("enrolled status wrong: %v", body)
	}
	// Second enroll without disable conflicts.
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/account/mfa/enroll", map[string]any{}); code != 409 {
		t.Fatalf("second enroll = %d, want 409", code)
	}
	// Disable needs the old factor; a bad one fails.
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/account/mfa/disable", map[string]any{
		"code": "000000",
	}); code != 400 {
		t.Fatalf("disable with bad factor = %d, want 400", code)
	}
}

func TestDashboardBindingsE2E(t *testing.T) {
	fx := setupMFAFixture(t)
	ctx := context.Background()
	root := fx.mkadmin("dash-root")
	r := fx.browser()
	if code, _ := fx.login(r, root.Username); code != 200 {
		t.Fatalf("admin login = %d", code)
	}
	fx.enroll(r) // pending setup -> full MFA'd admin session

	alice := fx.mkuser("dash-alice")
	a := fx.browser()
	if code, _ := fx.login(a, alice.Username); code != 200 {
		t.Fatalf("alice login = %d", code)
	}

	tag := uuid.NewString()[:8]
	mkapp := func(slug, name string, visible bool) map[string]any {
		code, body := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/apps", map[string]any{
			"slug": slug, "name": name, "provider_type": "oidc",
			"launch_url": "https://" + slug + ".example.com", "is_visible": visible,
		})
		if code != 201 {
			t.Fatalf("create app %s = %d (%v)", slug, code, body)
		}
		app, _ := body["app"].(map[string]any)
		return app
	}
	openSlug, lockedSlug, teamSlug, hiddenSlug := "dash-open-"+tag, "dash-locked-"+tag, "dash-team-"+tag, "dash-hidden-"+tag
	mkapp(openSlug, "Open", true)
	locked := mkapp(lockedSlug, "Locked", true)
	teamApp := mkapp(teamSlug, "Team", true)
	mkapp(hiddenSlug, "Hidden", false)
	// Bad provider type is a 400.
	if code, _ := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/apps", map[string]any{
		"slug": "dash-bad", "name": "Bad", "provider_type": "oauth9",
	}); code != 400 {
		t.Fatalf("bad provider = %d, want 400", code)
	}

	// Lock one app to the admin, one to a group alice joins later.
	eng, err := fx.groups.Create(ctx, domain.Group{Name: "dash-eng-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatal(err)
	}
	bind := func(appID, payload string) {
		t.Helper()
		var p map[string]any
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			t.Fatal(err)
		}
		code, body := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/apps/"+appID+"/bindings", p)
		if code != 201 {
			t.Fatalf("create binding = %d (%v)", code, body)
		}
	}
	bind(locked["id"].(string), `{"binding_type":"user","user_id":"`+root.ID.String()+`"}`)
	bind(teamApp["id"].(string), `{"binding_type":"group","group_id":"`+eng.ID.String()+`"}`)

	slugs := func() []string {
		t.Helper()
		code, body := doJSON(t, a, http.MethodGet, fx.srv.URL+"/api/my-apps", nil)
		if code != 200 {
			t.Fatalf("my-apps = %d (%v)", code, body)
		}
		var out []string
		for _, v := range body["apps"].([]any) {
			out = append(out, v.(map[string]any)["slug"].(string))
		}
		return out
	}
	has := func(list []string, slug string) bool {
		for _, s := range list {
			if s == slug {
				return true
			}
		}
		return false
	}
	// Membership assertions (not exact counts): earlier runs leave
	// behind visible open apps, which must not break this run.
	if got := slugs(); !has(got, openSlug) || has(got, lockedSlug) || has(got, hiddenSlug) || has(got, teamSlug) {
		t.Fatalf("dashboard = %v, want open without locked/hidden/team", got)
	}
	if err := fx.groups.AddMember(ctx, alice.ID, eng.ID); err != nil {
		t.Fatal(err)
	}
	if got := slugs(); !has(got, teamSlug) {
		t.Fatalf("dashboard after join = %v, want team app", got)
	}
	// Launch: open works, locked is forbidden, hidden is invisible.
	if code, body := doJSON(t, a, http.MethodGet, fx.srv.URL+"/api/apps/"+openSlug+"/launch", nil); code != 200 {
		t.Fatalf("launch open = %d (%v)", code, body)
	} else if body["launch_url"] == "" {
		t.Fatalf("launch must carry the URL: %v", body)
	}
	if code, _ := doJSON(t, a, http.MethodGet, fx.srv.URL+"/api/apps/"+lockedSlug+"/launch", nil); code != 403 {
		t.Fatalf("launch locked = %d, want 403", code)
	}
	if code, _ := doJSON(t, a, http.MethodGet, fx.srv.URL+"/api/apps/"+hiddenSlug+"/launch", nil); code != 404 {
		t.Fatalf("launch hidden = %d, want 404", code)
	}
	if code, _ := doJSON(t, a, http.MethodGet, fx.srv.URL+"/api/apps/dash-nope-"+tag+"/launch", nil); code != 404 {
		t.Fatalf("launch missing = %d, want 404", code)
	}
	// Per-app MFA: flag the open app, and alice (no factors) is gated.
	// Paginated scan: other suites seed apps into the shared database.
	openID := ""
	for offset := 0; ; offset += 200 {
		url := fx.srv.URL + "/api/admin/apps?limit=200&offset=" + strconv.Itoa(offset)
		code, body := doJSON(t, r, http.MethodGet, url, nil)
		if code != 200 {
			t.Fatalf("admin list apps = %d", code)
		}
		list, _ := body["apps"].([]any)
		for _, v := range list {
			m := v.(map[string]any)
			if m["slug"] == openSlug {
				openID = m["id"].(string)
			}
		}
		if openID != "" || len(list) == 0 {
			break
		}
	}
	if openID == "" {
		t.Fatal("open app missing from admin list")
	}
	patch := map[string]any{
		"slug": openSlug, "name": "Open", "provider_type": "oidc",
		"launch_url": "https://" + openSlug + ".example.com", "mfa_required": true,
	}
	if code, _ := doJSON(t, r, http.MethodPatch, fx.srv.URL+"/api/admin/apps/"+openID, patch); code != 200 {
		t.Fatalf("flag mfa_required = %d, want 200", code)
	}
	if code, body := doJSON(t, a, http.MethodGet, fx.srv.URL+"/api/apps/"+openSlug+"/launch", nil); code != 403 || body["mfa_required"] != true {
		t.Fatalf("launch mfa-gated = %d (%v), want 403 + mfa_required", code, body)
	}
	// Binding list + delete round trip.
	if code, body := doJSON(t, r, http.MethodGet, fx.srv.URL+"/api/admin/apps/"+locked["id"].(string)+"/bindings", nil); code != 200 {
		t.Fatalf("list bindings = %d", code)
	} else if len(body["bindings"].([]any)) != 1 {
		t.Fatalf("bindings = %v, want 1", body)
	}
}

func TestUploadsE2E(t *testing.T) {
	fx := setupMFAFixture(t)
	alice := fx.mkuser("up-alice")
	a := fx.browser()
	if code, _ := fx.login(a, alice.Username); code != 200 {
		t.Fatalf("alice login = %d", code)
	}
	root := fx.mkadmin("up-root")
	r := fx.browser()
	if code, _ := fx.login(r, root.Username); code != 200 {
		t.Fatalf("admin login = %d", code)
	}
	fx.enroll(r)

	// 64x32 PNG gradient.
	img := image.NewRGBA(image.Rect(0, 0, 64, 32))
	for y := range 32 {
		for x := range 64 {
			img.Set(x, y, color.RGBA{uint8(x * 4), uint8(y * 8), 128, 255})
		}
	}
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		t.Fatal(err)
	}
	upload := func(c *http.Client, assetType string, content []byte) (int, map[string]any) {
		t.Helper()
		var form bytes.Buffer
		w := multipart.NewWriter(&form)
		if err := w.WriteField("asset_type", assetType); err != nil {
			t.Fatal(err)
		}
		fw, err := w.CreateFormFile("file", "avatar.png")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, fx.srv.URL+"/api/uploads", &form)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", w.FormDataContentType())
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		out := map[string]any{}
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}
	code, body := upload(a, "avatar", pngBuf.Bytes())
	if code != 201 {
		t.Fatalf("avatar upload = %d (%v)", code, body)
	}
	publicURL, _ := body["url"].(string)
	if !strings.HasPrefix(publicURL, "/uploads/avatar/") || !strings.HasSuffix(publicURL, ".webp") {
		t.Fatalf("public url = %q", publicURL)
	}
	// Public read: pinned webp type, immutable cache.
	resp, err := http.Get(fx.srv.URL + publicURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/webp" {
		t.Fatalf("serve = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("cache-control = %q, want immutable", cc)
	}
	if len(raw) < 12 || string(raw[:4]) != "RIFF" || string(raw[8:12]) != "WEBP" {
		t.Fatal("served bytes must be a webp container")
	}
	if body["width"] != float64(64) || body["height"] != float64(32) {
		t.Fatalf("dims = %v/%v, want 64/32", body["width"], body["height"])
	}
	// Non-images and bad types fail; logos are admin-only.
	if code, _ := upload(a, "avatar", []byte("not an image")); code != 400 {
		t.Fatalf("non-image = %d, want 400", code)
	}
	if code, _ := upload(a, "banner", pngBuf.Bytes()); code != 400 {
		t.Fatalf("bad type = %d, want 400", code)
	}
	if code, _ := upload(a, "app_logo", pngBuf.Bytes()); code != 403 {
		t.Fatalf("user app_logo = %d, want 403", code)
	}
	if code, body := upload(r, "app_logo", pngBuf.Bytes()); code != 201 {
		t.Fatalf("admin app_logo = %d (%v)", code, body)
	} else if !strings.HasPrefix(body["url"].(string), "/uploads/app_logo/") {
		t.Fatalf("logo url = %v", body)
	}
	if code, _ := upload(a, "avatar", make([]byte, (2<<20)+1)); code != 400 {
		t.Fatalf("oversize = %d, want 400", code)
	}
	// Unknown object is a 404, and so are malformed paths.
	if resp, err := http.Get(fx.srv.URL + "/uploads/avatar/" + uuid.NewString() + ".webp"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("missing object = %d, want 404", resp.StatusCode)
		}
	}
	if resp, err := http.Get(fx.srv.URL + "/uploads/avatar/not-a-uuid.webp"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("malformed path = %d, want 404", resp.StatusCode)
		}
	}
}

func TestPasswordChangeReAuthE2E(t *testing.T) {
	fx := setupMFAFixture(t)
	bob := fx.mkuser("mfa-pw")
	b := fx.browser()
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("login = %d", code)
	}
	change := func(current, fresh, code string) (int, map[string]any) {
		t.Helper()
		return doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/account/password/change", map[string]any{
			"current_password": current, "new_password": fresh,
			"new_password_confirm": fresh, "totp_code": code,
		})
	}
	// Without factors, no re-auth is needed.
	if code, _ := change(fx.password, "second-password-long-1", ""); code != 200 {
		t.Fatalf("change without MFA = %d, want 200", code)
	}
	// Enroll (full session stamps a fresh verification): the next
	// change rides the window without a code.
	fx.enroll(b)
	if code, _ := change("second-password-long-1", "third-password-long-2", ""); code != 200 {
		t.Fatalf("change in re-auth window = %d, want 200", code)
	}
	// A wrong code with a fresh session is ignored (window covers it);
	// nothing to assert beyond success.
	if code, _ := change("third-password-long-2", "fourth-password-long-3", "000000"); code != 200 {
		t.Fatalf("change in window with junk code = %d, want 200", code)
	}
}
