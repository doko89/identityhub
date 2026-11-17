package http

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseapikey "github.com/identityhub/identityhub/internal/usecase/apikey"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecasemfa "github.com/identityhub/identityhub/internal/usecase/mfa"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
)

// ---------- fakes ----------

type fakeAPIKeys struct {
	byID map[uuid.UUID]domain.APIKey
}

func newFakeAPIKeys() *fakeAPIKeys { return &fakeAPIKeys{byID: map[uuid.UUID]domain.APIKey{}} }

func (f *fakeAPIKeys) Create(_ context.Context, k domain.APIKey) (domain.APIKey, error) {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	k.CreatedAt = time.Now().UTC()
	f.byID[k.ID] = k
	return k, nil
}

func (f *fakeAPIKeys) ByHash(_ context.Context, hash []byte) (domain.APIKey, error) {
	for _, k := range f.byID {
		if string(k.KeyHash) == string(hash) {
			return k, nil
		}
	}
	return domain.APIKey{}, domain.ErrNotFound
}

func (f *fakeAPIKeys) ListByUser(_ context.Context, userID uuid.UUID) ([]domain.APIKey, error) {
	var out []domain.APIKey
	for _, k := range f.byID {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeAPIKeys) Revoke(_ context.Context, userID, id uuid.UUID, at time.Time) error {
	k, ok := f.byID[id]
	if !ok || k.UserID != userID || k.RevokedAt != nil {
		return domain.ErrNotFound
	}
	k.RevokedAt = &at
	f.byID[id] = k
	return nil
}

func (f *fakeAPIKeys) TouchLastUsed(_ context.Context, id uuid.UUID, at time.Time) error {
	k, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	k.LastUsedAt = &at
	f.byID[id] = k
	return nil
}

// stubMFAStore satisfies domain.MFAStore without behavior: the admin-gate
// test only needs a non-nil MFA service, never its methods.
type stubMFAStore struct{}

func (stubMFAStore) EnrollTOTP(_ context.Context, _ domain.TOTPCredential) error { return nil }
func (stubMFAStore) TOTPOfUser(_ context.Context, _ uuid.UUID) (domain.TOTPCredential, error) {
	return domain.TOTPCredential{}, domain.ErrNotFound
}
func (stubMFAStore) AcceptStep(_ context.Context, _ uuid.UUID, _ int64) error { return nil }
func (stubMFAStore) DisableTOTP(_ context.Context, _ uuid.UUID) error         { return nil }
func (stubMFAStore) AddRecoveryCodes(_ context.Context, _ uuid.UUID, _ [][]byte) error {
	return nil
}
func (stubMFAStore) ReplaceRecoveryCodes(_ context.Context, _ uuid.UUID, _ [][]byte) error {
	return nil
}
func (stubMFAStore) UseRecoveryCode(_ context.Context, _ uuid.UUID, _ []byte, _ time.Time) error {
	return nil
}
func (stubMFAStore) RemainingRecoveryCodes(_ context.Context, _ uuid.UUID) (int, error) {
	return 0, nil
}

// stubAppStore satisfies domain.ApplicationStore without behavior.
type stubAppStore struct{}

func (stubAppStore) Create(_ context.Context, a domain.Application) (domain.Application, error) {
	return a, nil
}
func (stubAppStore) ByID(_ context.Context, _ uuid.UUID) (domain.Application, error) {
	return domain.Application{}, domain.ErrNotFound
}
func (stubAppStore) BySlug(_ context.Context, _ string) (domain.Application, error) {
	return domain.Application{}, domain.ErrNotFound
}
func (stubAppStore) List(_ context.Context, _ domain.AppFilter) ([]domain.Application, int, error) {
	return nil, 0, nil
}
func (stubAppStore) Update(_ context.Context, a domain.Application) (domain.Application, error) {
	return a, nil
}
func (stubAppStore) Delete(_ context.Context, _ uuid.UUID) error { return nil }

// doAuth performs a request with an explicit client and Authorization
// header (empty auth sends none).
func (h *apiHarness) doAuth(t *testing.T, client *http.Client, method, path, auth string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.server.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s %s: non-JSON response %d: %q", method, path, resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, out
}

// ---------- CRUD ----------

func TestAPIKeyCRUD(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	h := newAPI(t, u)
	bare := &http.Client{}

	code, _ := h.doAuth(t, bare, http.MethodPost, "/api/account/api-keys", "", map[string]string{"name": "x"})
	if code != http.StatusUnauthorized {
		t.Fatalf("create without auth = %d, want 401", code)
	}

	h.login(t, "ara", "correct-horse-12")

	code, out := h.do(http.MethodPost, "/api/account/api-keys", map[string]string{"name": "cli"})
	if code != http.StatusCreated {
		t.Fatalf("create = %d, %v", code, out)
	}
	secret, _ := out["secret"].(string)
	key, _ := out["api_key"].(map[string]any)
	if len(secret) != 46 || !strings.HasPrefix(secret, "ih_") {
		t.Fatalf("bad secret shape %q", secret)
	}
	if key["prefix"] != secret[:12] {
		t.Fatalf("prefix %v does not match secret", key["prefix"])
	}
	if _, leaked := key["secret"]; leaked {
		t.Error("key JSON leaks secret")
	}
	if _, leaked := key["key_hash"]; leaked {
		t.Error("key JSON leaks key_hash")
	}
	id := key["id"].(string)

	code, out = h.do(http.MethodPost, "/api/account/api-keys", map[string]any{"name": "short", "expires_in_days": 30})
	if code != http.StatusCreated || out["api_key"].(map[string]any)["expires_at"] == nil {
		t.Fatalf("create with expiry = %d, %v", code, out)
	}
	for _, bad := range []map[string]any{{}, {"name": ""}, {"name": "x", "expires_in_days": 0}, {"name": "x", "expires_in_days": -1}} {
		if code, out := h.do(http.MethodPost, "/api/account/api-keys", bad); code != http.StatusBadRequest {
			t.Fatalf("create %v = %d, %v, want 400", bad, code, out)
		}
	}

	code, out = h.do(http.MethodGet, "/api/account/api-keys", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d, %v", code, out)
	}
	if keys := out["api_keys"].([]any); len(keys) != 2 {
		t.Fatalf("list has %d keys, want 2", len(keys))
	}

	code, _ = h.do(http.MethodDelete, "/api/account/api-keys/"+id, nil)
	if code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", code)
	}
	code, _ = h.do(http.MethodDelete, "/api/account/api-keys/"+id, nil)
	if code != http.StatusNotFound {
		t.Fatalf("revoke again = %d, want 404", code)
	}
	code, _ = h.do(http.MethodDelete, "/api/account/api-keys/"+uuid.NewString(), nil)
	if code != http.StatusNotFound {
		t.Fatalf("revoke unknown = %d, want 404", code)
	}
	code, _ = h.do(http.MethodDelete, "/api/account/api-keys/not-a-uuid", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("revoke malformed = %d, want 400", code)
	}
}

// ---------- Bearer auth ----------

func TestBearerAuth(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	h := newAPI(t, u)
	h.login(t, "ara", "correct-horse-12")

	_, out := h.do(http.MethodPost, "/api/account/api-keys", map[string]string{"name": "cli"})
	secret := out["secret"].(string)
	id := out["api_key"].(map[string]any)["id"].(string)
	bare := &http.Client{} // no cookies: pure Bearer client like the CLI

	code, out := h.doAuth(t, bare, http.MethodGet, "/api/auth/me", "Bearer "+secret, nil)
	if code != http.StatusOK || out["user"].(map[string]any)["username"] != "ara" {
		t.Fatalf("bearer me = %d, %v", code, out)
	}
	// Scheme match is case-insensitive.
	if code, _ := h.doAuth(t, bare, http.MethodGet, "/api/auth/me", "bearer "+secret, nil); code != http.StatusOK {
		t.Fatalf("lowercase bearer = %d, want 200", code)
	}
	for name, auth := range map[string]string{
		"none":         "",
		"basic":        "Basic abc",
		"bare scheme":  "Bearer",
		"empty token":  "Bearer ",
		"unknown":      "Bearer " + "ih_" + strings.Repeat("A", 43),
		"malformed":    "Bearer nope",
		"wrong scheme": "Token " + secret,
	} {
		if code, out := h.doAuth(t, bare, http.MethodGet, "/api/auth/me", auth, nil); code != http.StatusUnauthorized {
			t.Fatalf("%s = %d, %v, want 401", name, code, out)
		}
	}

	// A session identity wins over a bad Bearer token.
	if code, _ := h.doAuth(t, h.client, http.MethodGet, "/api/auth/me", "Bearer nope", nil); code != http.StatusOK {
		t.Fatalf("session+bad-bearer = %d, want 200", code)
	}

	// Revoked keys stop authenticating.
	if code, _ := h.do(http.MethodDelete, "/api/account/api-keys/"+id, nil); code != http.StatusNoContent {
		t.Fatalf("revoke = %d", code)
	}
	if code, _ := h.doAuth(t, bare, http.MethodGet, "/api/auth/me", "Bearer "+secret, nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer = %d, want 401", code)
	}

	// Disabled owners lose Bearer access too.
	_, out = h.do(http.MethodPost, "/api/account/api-keys", map[string]string{"name": "cli2"})
	secret2 := out["secret"].(string)
	if err := h.users.SetActive(context.Background(), u.ID, false); err != nil {
		t.Fatal(err)
	}
	if code, out := h.doAuth(t, bare, http.MethodGet, "/api/auth/me", "Bearer "+secret2, nil); code != http.StatusUnauthorized || out["error"] != "account disabled" {
		t.Fatalf("disabled bearer = %d, %v", code, out)
	}
}

// ---------- Bearer admin gate ----------

// strictServer rebuilds the harness server with MFA wired, so the Bearer
// admin gate (created_with_mfa) is enforced.
func (h *apiHarness) strictServer(t *testing.T) {
	t.Helper()
	audits := usecaseaudit.New(h.audits, nil)
	userSvc, err := usecaseuser.New(usecaseuser.Deps{
		Users: h.users, Groups: h.groups, Sessions: &fakeRegistry{},
		Audit: audits, Hasher: fakeHasher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	apiKeySvc, err := usecaseapikey.New(usecaseapikey.Deps{Keys: h.keys, Audit: audits})
	if err != nil {
		t.Fatal(err)
	}
	mfaSvc, err := usecasemfa.New(usecasemfa.Deps{
		Store: stubMFAStore{}, Users: h.users, Groups: h.groups, Apps: stubAppStore{},
		TOTP: crypto.TOTP{}, Sealer: crypto.Sealer{}, Audit: audits,
	})
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	handlers := NewHandlers(HandlerDeps{
		Sessions: sm, Registry: &fakeRegistry{}, Users: userSvc,
		Audits: audits, Groups: h.groups, MFA: mfaSvc, APIKeys: apiKeySvc,
		Limiter: NewLimiter(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	h.server.Close()
	h.server = httptest.NewServer(NewRouter(Deps{Sessions: sm, DB: stubDB{}, Handlers: handlers}))
}

func TestBearerAdminGate(t *testing.T) {
	admin := localUser("root", "correct-horse-12")
	member := localUser("ara", "correct-horse-12")
	h := newAPI(t, admin, member)
	if err := h.groups.AddMember(context.Background(), admin.ID, h.admin.ID); err != nil {
		t.Fatal(err)
	}
	h.strictServer(t)
	bare := &http.Client{}
	ctx := context.Background()
	apiKeySvc, err := usecaseapikey.New(usecaseapikey.Deps{Keys: h.keys, Audit: usecaseaudit.New(h.audits, nil)})
	if err != nil {
		t.Fatal(err)
	}

	// An admin key issued without MFA cannot touch /api/admin.
	_, weak, err := apiKeySvc.Create(ctx, admin.ID, "weak", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	code, out := h.doAuth(t, bare, http.MethodGet, "/api/admin/users", "Bearer "+weak, nil)
	if code != http.StatusForbidden || out["mfa_required"] != true {
		t.Fatalf("weak admin key = %d, %v, want 403 mfa_required", code, out)
	}
	// But it still works for the owner's own account routes.
	if code, _ := h.doAuth(t, bare, http.MethodGet, "/api/auth/me", "Bearer "+weak, nil); code != http.StatusOK {
		t.Fatalf("weak key me = %d, want 200", code)
	}

	// An admin key issued from an MFA-verified session passes.
	_, strong, err := apiKeySvc.Create(ctx, admin.ID, "strong", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := h.doAuth(t, bare, http.MethodGet, "/api/admin/users", "Bearer "+strong, nil); code != http.StatusOK {
		t.Fatalf("strong admin key = %d, %v, want 200", code, out)
	}

	// Non-admin keys never pass, however they were issued.
	_, plain, err := apiKeySvc.Create(ctx, member.ID, "plain", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	code, out = h.doAuth(t, bare, http.MethodGet, "/api/admin/users", "Bearer "+plain, nil)
	if code != http.StatusForbidden || out["error"] != "administrator access required" {
		t.Fatalf("member key = %d, %v", code, out)
	}
}

func TestBearerToken(t *testing.T) {
	for _, tc := range []struct {
		header string
		token  string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Basic abc", "", false},
		{"Token abc", "", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		token, ok := bearerToken(req)
		if token != tc.token || ok != tc.ok {
			t.Errorf("bearerToken(%q) = (%q, %v), want (%q, %v)", tc.header, token, ok, tc.token, tc.ok)
		}
	}
}
