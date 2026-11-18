package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/metrics"
	usecaseapikey "github.com/identityhub/identityhub/internal/usecase/apikey"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
)

// ---------- fakes ----------

type fakeUsers struct {
	byID       map[uuid.UUID]domain.User
	byUsername map[string]domain.User
	byEmail    map[string]domain.User
}

func newFakeUsers(us ...domain.User) *fakeUsers {
	f := &fakeUsers{byID: map[uuid.UUID]domain.User{}, byUsername: map[string]domain.User{}, byEmail: map[string]domain.User{}}
	for _, u := range us {
		f.put(u)
	}
	return f
}

func (f *fakeUsers) put(u domain.User) {
	f.byID[u.ID] = u
	f.byUsername[u.Username] = u
	if u.Email != "" {
		f.byEmail[u.Email] = u
	}
}

func (f *fakeUsers) Create(_ context.Context, u domain.User) (domain.User, error) {
	if _, ok := f.byUsername[u.Username]; ok {
		return domain.User{}, domain.ErrConflict
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	f.put(u)
	return u, nil
}

func (f *fakeUsers) ByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) ByUsername(_ context.Context, username string) (domain.User, error) {
	u, ok := f.byUsername[username]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) ByUsernameFold(_ context.Context, username string) (domain.User, error) {
	if u, ok := f.byUsername[username]; ok {
		return u, nil
	}
	for name, u := range f.byUsername {
		if strings.EqualFold(name, username) {
			return u, nil
		}
	}
	return domain.User{}, domain.ErrNotFound
}

func (f *fakeUsers) ByEmail(_ context.Context, email string) (domain.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) List(_ context.Context, flt domain.UserFilter) ([]domain.User, int, error) {
	var out []domain.User
	for _, u := range f.byID {
		if flt.Source != "" && u.Source != flt.Source {
			continue
		}
		if flt.Active != nil && u.IsActive != *flt.Active {
			continue
		}
		if flt.Query != "" && !strings.Contains(strings.ToLower(u.Username+" "+u.Email+" "+u.DisplayName), strings.ToLower(flt.Query)) {
			continue
		}
		out = append(out, u)
	}
	return out, len(out), nil
}

func (f *fakeUsers) AllActive(_ context.Context) ([]domain.User, error) {
	var out []domain.User
	for _, u := range f.byID {
		if u.IsActive {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *fakeUsers) Update(_ context.Context, u domain.User) (domain.User, error) {
	if _, ok := f.byID[u.ID]; !ok {
		return domain.User{}, domain.ErrNotFound
	}
	f.put(u)
	return u, nil
}

func (f *fakeUsers) SetActive(_ context.Context, id uuid.UUID, active bool) error {
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.IsActive = active
	f.put(u)
	return nil
}

func (f *fakeUsers) SetPasswordHash(_ context.Context, id uuid.UUID, hash []byte) error {
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.PasswordHash = hash
	f.put(u)
	return nil
}

type fakeGroups struct {
	byID    map[uuid.UUID]domain.Group
	byName  map[string]domain.Group
	members map[uuid.UUID]map[uuid.UUID]bool
}

func newFakeGroups(gs ...domain.Group) *fakeGroups {
	f := &fakeGroups{byID: map[uuid.UUID]domain.Group{}, byName: map[string]domain.Group{}, members: map[uuid.UUID]map[uuid.UUID]bool{}}
	for _, g := range gs {
		f.byID[g.ID] = g
		f.byName[g.Name] = g
	}
	return f
}

func (f *fakeGroups) Create(_ context.Context, g domain.Group) (domain.Group, error) {
	if _, ok := f.byName[g.Name]; ok {
		return domain.Group{}, domain.ErrConflict
	}
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	f.byID[g.ID] = g
	f.byName[g.Name] = g
	return g, nil
}

func (f *fakeGroups) ByID(_ context.Context, id uuid.UUID) (domain.Group, error) {
	g, ok := f.byID[id]
	if !ok {
		return domain.Group{}, domain.ErrNotFound
	}
	return g, nil
}

func (f *fakeGroups) ByName(_ context.Context, name string) (domain.Group, error) {
	g, ok := f.byName[name]
	if !ok {
		return domain.Group{}, domain.ErrNotFound
	}
	return g, nil
}

func (f *fakeGroups) List(_ context.Context, _, _ int) ([]domain.Group, int, error) {
	var out []domain.Group
	for _, g := range f.byID {
		out = append(out, g)
	}
	return out, len(out), nil
}

func (f *fakeGroups) All(_ context.Context) ([]domain.Group, error) {
	var out []domain.Group
	for _, g := range f.byID {
		out = append(out, g)
	}
	return out, nil
}

func (f *fakeGroups) Delete(_ context.Context, id uuid.UUID) error {
	g, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	if g.Name == domain.AdminGroup {
		return domain.ErrForbidden
	}
	delete(f.byID, id)
	delete(f.byName, g.Name)
	delete(f.members, id)
	return nil
}

func (f *fakeGroups) AddMember(_ context.Context, userID, groupID uuid.UUID) error {
	if f.members[groupID] == nil {
		f.members[groupID] = map[uuid.UUID]bool{}
	}
	f.members[groupID][userID] = true
	return nil
}

func (f *fakeGroups) RemoveMember(_ context.Context, userID, groupID uuid.UUID) error {
	delete(f.members[groupID], userID)
	return nil
}

func (f *fakeGroups) MemberIDs(_ context.Context, groupID uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for id := range f.members[groupID] {
		out = append(out, id)
	}
	return out, nil
}

func (f *fakeGroups) MemberUsernamesByGroup(_ context.Context) (map[uuid.UUID][]string, error) {
	return map[uuid.UUID][]string{}, nil
}

func (f *fakeGroups) GroupsOfUser(_ context.Context, userID uuid.UUID) ([]domain.Group, error) {
	var out []domain.Group
	for gid, set := range f.members {
		if set[userID] {
			out = append(out, f.byID[gid])
		}
	}
	return out, nil
}

func (f *fakeGroups) IsMember(_ context.Context, userID uuid.UUID, groupName string) (bool, error) {
	g, ok := f.byName[groupName]
	if !ok {
		return false, nil
	}
	return f.members[g.ID][userID], nil
}

type fakeAttrs struct {
	defs   map[string]domain.UserAttrDef
	byID   map[uuid.UUID]domain.UserAttrDef
	values map[uuid.UUID]map[uuid.UUID][]string
}

func newFakeAttrs() *fakeAttrs {
	return &fakeAttrs{
		defs: map[string]domain.UserAttrDef{}, byID: map[uuid.UUID]domain.UserAttrDef{},
		values: map[uuid.UUID]map[uuid.UUID][]string{},
	}
}

func (f *fakeAttrs) CreateDef(_ context.Context, d domain.UserAttrDef) (domain.UserAttrDef, error) {
	if err := d.Validate(); err != nil {
		return domain.UserAttrDef{}, err
	}
	if _, ok := f.defs[d.Key]; ok {
		return domain.UserAttrDef{}, domain.ErrConflict
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	f.defs[d.Key] = d
	f.byID[d.ID] = d
	return d, nil
}

func (f *fakeAttrs) ListDefs(_ context.Context) ([]domain.UserAttrDef, error) {
	var out []domain.UserAttrDef
	for _, d := range f.defs {
		out = append(out, d)
	}
	return out, nil
}

func (f *fakeAttrs) DeleteDef(_ context.Context, key string) error {
	d, ok := f.defs[key]
	if !ok {
		return domain.ErrNotFound
	}
	delete(f.defs, key)
	delete(f.byID, d.ID)
	for uid := range f.values {
		delete(f.values[uid], d.ID)
	}
	return nil
}

func (f *fakeAttrs) SetValues(_ context.Context, userID uuid.UUID, values map[uuid.UUID][]string, _ domain.UserAttrSource) error {
	if f.values[userID] == nil {
		f.values[userID] = map[uuid.UUID][]string{}
	}
	for id, vals := range values {
		if len(vals) == 0 {
			delete(f.values[userID], id)
			continue
		}
		f.values[userID][id] = append([]string(nil), vals...)
	}
	return nil
}

func (f *fakeAttrs) ApplyUpstreamValues(_ context.Context, userID uuid.UUID, values map[uuid.UUID][]string) error {
	if f.values[userID] == nil {
		f.values[userID] = map[uuid.UUID][]string{}
	}
	for id, vals := range values {
		f.values[userID][id] = vals
	}
	return nil
}

func (f *fakeAttrs) ValuesOfUser(_ context.Context, userID uuid.UUID) (map[string][]string, error) {
	out := map[string][]string{}
	for id, vals := range f.values[userID] {
		if d, ok := f.byID[id]; ok {
			out[d.Key] = append([]string(nil), vals...)
		}
	}
	return out, nil
}

func (f *fakeAttrs) ValuesForUsers(_ context.Context, userIDs []uuid.UUID) (map[uuid.UUID]map[string][]string, error) {
	out := map[uuid.UUID]map[string][]string{}
	for _, uid := range userIDs {
		m, _ := f.ValuesOfUser(context.Background(), uid)
		out[uid] = m
	}
	return out, nil
}

type fakeResets struct {
	byHash map[string]domain.PasswordResetToken
	byID   map[uuid.UUID]domain.PasswordResetToken
}

func (f *fakeResets) Create(_ context.Context, tok domain.PasswordResetToken) (domain.PasswordResetToken, error) {
	now := time.Now()
	for id, t := range f.byID {
		if t.UserID == tok.UserID && t.UsedAt == nil {
			t.UsedAt = &now
			f.byID[id] = t
			f.byHash[string(t.TokenHash)] = t
		}
	}
	if tok.ID == uuid.Nil {
		tok.ID = uuid.New()
	}
	f.byID[tok.ID] = tok
	f.byHash[string(tok.TokenHash)] = tok
	return tok, nil
}

func (f *fakeResets) ByHash(_ context.Context, hash []byte) (domain.PasswordResetToken, error) {
	t, ok := f.byHash[string(hash)]
	if !ok {
		return domain.PasswordResetToken{}, domain.ErrNotFound
	}
	return t, nil
}

func (f *fakeResets) MarkUsed(_ context.Context, id uuid.UUID, at time.Time) error {
	t, ok := f.byID[id]
	if !ok || t.UsedAt != nil {
		return domain.ErrNotFound
	}
	t.UsedAt = &at
	f.byID[id] = t
	f.byHash[string(t.TokenHash)] = t
	return nil
}

func (f *fakeResets) DeleteExpired(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

type fakeHistory struct {
	hashes map[uuid.UUID][][]byte
}

func (f *fakeHistory) Add(_ context.Context, userID uuid.UUID, hash []byte) error {
	if f.hashes == nil {
		f.hashes = map[uuid.UUID][][]byte{}
	}
	f.hashes[userID] = append([][]byte{hash}, f.hashes[userID]...)
	return nil
}

func (f *fakeHistory) Recent(_ context.Context, userID uuid.UUID, limit int) ([][]byte, error) {
	h := f.hashes[userID]
	if len(h) > limit {
		h = h[:limit]
	}
	return h, nil
}

type fakeRegistry struct {
	tokens map[uuid.UUID]map[string]bool
}

func (f *fakeRegistry) Register(_ context.Context, userID uuid.UUID, token string) error {
	if f.tokens == nil {
		f.tokens = map[uuid.UUID]map[string]bool{}
	}
	if f.tokens[userID] == nil {
		f.tokens[userID] = map[string]bool{}
	}
	f.tokens[userID][token] = true
	return nil
}

func (f *fakeRegistry) Unregister(_ context.Context, token string) error {
	for u, set := range f.tokens {
		delete(set, token)
		f.tokens[u] = set
	}
	return nil
}

func (f *fakeRegistry) RevokeOthers(_ context.Context, userID uuid.UUID, keep string) (int64, error) {
	var n int64
	for tok := range f.tokens[userID] {
		if tok != keep {
			delete(f.tokens[userID], tok)
			n++
		}
	}
	return n, nil
}

func (f *fakeRegistry) RevokeAll(_ context.Context, userID uuid.UUID) (int64, error) {
	n := int64(len(f.tokens[userID]))
	if f.tokens == nil {
		return n, nil
	}
	f.tokens[userID] = map[string]bool{}
	return n, nil
}

type fakeAuditStore struct {
	entries []domain.AuditEntry
}

func (f *fakeAuditStore) Append(_ context.Context, e domain.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeAuditStore) List(_ context.Context, flt domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	var out []domain.AuditEntry
	for _, e := range f.entries {
		if flt.Method != "" && e.Method != flt.Method {
			continue
		}
		if flt.Result != "" && e.Result != flt.Result {
			continue
		}
		out = append(out, e)
	}
	return out, len(out), nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(password string) ([]byte, error) { return []byte("hash:" + password), nil }
func (fakeHasher) Verify(password string, hash []byte) bool {
	return string(hash) == "hash:"+password
}

func (fakeHasher) NeedsRehash(_ []byte) bool { return false }

type fakeMailer struct {
	to     []string
	bodies []string
}

func (f *fakeMailer) Send(to, _, textBody, _ string) error {
	f.to = append(f.to, to)
	f.bodies = append(f.bodies, textBody)
	return nil
}

type fakeDirectory struct {
	passwords map[string]string
	err       error
}

func (f *fakeDirectory) Authenticate(_ context.Context, username, password string) (domain.LDAPUser, error) {
	if f.err != nil {
		return domain.LDAPUser{}, f.err
	}
	want, ok := f.passwords[username]
	if !ok {
		return domain.LDAPUser{}, domain.ErrNotFound
	}
	if password != want {
		return domain.LDAPUser{}, domain.ErrUnauthorized
	}
	return domain.LDAPUser{Username: username, Email: username + "@dir.example.com", DN: "uid=" + username + ",ou=users,dc=example,dc=com"}, nil
}

func (f *fakeDirectory) Snapshot(_ context.Context) (domain.DirectorySnapshot, error) {
	return domain.DirectorySnapshot{}, f.err
}

func (f *fakeDirectory) Ping(_ context.Context) error { return f.err }

// ---------- harness ----------

type apiHarness struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
	users  *fakeUsers
	groups *fakeGroups
	audits *fakeAuditStore
	mailer *fakeMailer
	dir    *fakeDirectory
	keys   *fakeAPIKeys
	attrs  *fakeAttrs
	admin  domain.Group
}

func newAPI(t *testing.T, users ...domain.User) *apiHarness {
	t.Helper()
	admin := domain.Group{ID: uuid.New(), Name: domain.AdminGroup}
	h := &apiHarness{
		t:      t,
		users:  newFakeUsers(users...),
		groups: newFakeGroups(admin),
		audits: &fakeAuditStore{},
		mailer: &fakeMailer{},
		dir:    &fakeDirectory{passwords: map[string]string{}},
		attrs:  newFakeAttrs(),
		admin:  admin,
	}
	audits := usecaseaudit.New(h.audits, nil)
	authSvc, err := usecaseauth.New(usecaseauth.Deps{
		Users: h.users, Groups: h.groups, Resets: &fakeResets{byHash: map[string]domain.PasswordResetToken{}, byID: map[uuid.UUID]domain.PasswordResetToken{}},
		History: &fakeHistory{}, Sessions: &fakeRegistry{}, Audit: audits,
		Hasher: fakeHasher{}, Mailer: h.mailer, Directory: h.dir, BaseURL: "https://idp.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	userSvc, err := usecaseuser.New(usecaseuser.Deps{
		Users: h.users, Groups: h.groups, Sessions: &fakeRegistry{},
		Audit: audits, Hasher: fakeHasher{}, Attrs: h.attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.keys = newFakeAPIKeys()
	apiKeySvc, err := usecaseapikey.New(usecaseapikey.Deps{Keys: h.keys, Audit: audits})
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	sm.Cookie.Name = "identityhub_session"
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode
	handlers := NewHandlers(HandlerDeps{
		Sessions: sm, Registry: &fakeRegistry{}, Auth: authSvc, Users: userSvc,
		Audits: audits, Groups: h.groups, Directory: h.dir,
		Limiter: NewLimiter(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		APIKeys: apiKeySvc,
	})
	h.server = httptest.NewServer(NewRouter(Deps{Sessions: sm, DB: stubDB{}, Handlers: handlers}))
	t.Cleanup(h.server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.client = &http.Client{Jar: jar}
	return h
}

// withoutDirectory disables the LDAP upstream (Directory nil in both the
// usecase and the handlers).
func (h *apiHarness) withoutDirectory(t *testing.T) {
	t.Helper()
	h.dir = nil
	audits := usecaseaudit.New(h.audits, nil)
	authSvc, err := usecaseauth.New(usecaseauth.Deps{
		Users: h.users, Groups: h.groups, Resets: &fakeResets{byHash: map[string]domain.PasswordResetToken{}, byID: map[uuid.UUID]domain.PasswordResetToken{}},
		History: &fakeHistory{}, Sessions: &fakeRegistry{}, Audit: audits,
		Hasher: fakeHasher{}, Mailer: h.mailer, BaseURL: "https://idp.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	userSvc, err := usecaseuser.New(usecaseuser.Deps{
		Users: h.users, Groups: h.groups, Sessions: &fakeRegistry{},
		Audit: audits, Hasher: fakeHasher{}, Attrs: h.attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	sm := scs.New()
	handlers := NewHandlers(HandlerDeps{
		Sessions: sm, Registry: &fakeRegistry{}, Auth: authSvc, Users: userSvc,
		Audits: audits, Groups: h.groups,
		Limiter: NewLimiter(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	h.server.Close()
	h.server = httptest.NewServer(NewRouter(Deps{Sessions: sm, DB: stubDB{}, Handlers: handlers}))
}

func (h *apiHarness) do(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var r io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			r = strings.NewReader(s)
		} else {
			raw, err := json.Marshal(body)
			if err != nil {
				h.t.Fatal(err)
			}
			r = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequest(method, h.server.URL+path, r)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			h.t.Fatalf("%s %s: non-JSON response %d: %q", method, path, resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, out
}

func localUser(username, password string) domain.User {
	return domain.User{ID: uuid.New(), Username: username, Email: username + "@example.com",
		PasswordHash: []byte("hash:" + password), Source: domain.SourceLocal, IsActive: true}
}

func ldapUser(username string) domain.User {
	return domain.User{ID: uuid.New(), Username: username, Email: username + "@dir.example.com",
		Source: domain.SourceLDAP, ExternalDN: "uid=" + username + ",ou=users,dc=example,dc=com", IsActive: true}
}

func (h *apiHarness) login(t *testing.T, username, password string) map[string]any {
	t.Helper()
	code, out := h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": username, "password": password})
	if code != http.StatusOK {
		t.Fatalf("login(%s) = %d, %v", username, code, out)
	}
	return out
}

// ---------- login / logout / me ----------

func TestLoginLogoutMe(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	h := newAPI(t, u)

	out := h.login(t, "ara", "correct-horse-12")
	user := out["user"].(map[string]any)
	if user["username"] != "ara" || user["is_admin"] != false {
		t.Errorf("login user = %v", user)
	}
	if _, leaked := user["password_hash"]; leaked {
		t.Error("user JSON leaks password_hash")
	}

	code, out := h.do(http.MethodGet, "/api/auth/me", nil)
	if code != http.StatusOK || out["user"].(map[string]any)["username"] != "ara" {
		t.Fatalf("me = %d, %v", code, out)
	}

	code, _ = h.do(http.MethodPost, "/api/auth/logout", nil)
	if code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", code)
	}
	code, _ = h.do(http.MethodGet, "/api/auth/me", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d, want 401", code)
	}
	if len(h.audits.entries) != 1 || h.audits.entries[0].Result != domain.ResultSuccess {
		t.Errorf("audit entries = %+v, want one success", h.audits.entries)
	}
}

func TestLoginFailures(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	disabled := localUser("zed", "correct-horse-12")
	disabled.IsActive = false
	h := newAPI(t, u, disabled)

	code, out := h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "ara", "password": "wrong-password"})
	if code != http.StatusUnauthorized || out["error"] != "invalid username or password" {
		t.Errorf("bad password = %d, %v", code, out)
	}
	code, out = h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "ghost", "password": "x"})
	if code != http.StatusUnauthorized || out["error"] != "invalid username or password" {
		t.Errorf("unknown user = %d, %v (must match bad-password response)", code, out)
	}
	code, out = h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "zed", "password": "correct-horse-12"})
	if code != http.StatusForbidden || out["error"] != "account disabled" {
		t.Errorf("disabled = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodPost, "/api/auth/login", "not json")
	if code != http.StatusBadRequest {
		t.Errorf("bad json = %d, want 400", code)
	}
	for _, e := range h.audits.entries {
		if e.Result != domain.ResultFailure {
			t.Errorf("audit entry = %+v, want failure", e)
		}
	}
	if len(h.audits.entries) != 3 {
		t.Errorf("audit entries = %d, want 3 (bad json never reaches login)", len(h.audits.entries))
	}
}

func TestLoginFailureObserved(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	h := newAPI(t, u)
	before := testutil.ToFloat64(metrics.AuthFailures.WithLabelValues("password", metrics.AppGlobal))
	code, _ := h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "ara", "password": "wrong-password"})
	if code != http.StatusUnauthorized {
		t.Fatalf("bad password = %d, want 401", code)
	}
	if got := testutil.ToFloat64(metrics.AuthFailures.WithLabelValues("password", metrics.AppGlobal)); got != before+1 {
		t.Errorf("auth failures = %v, want %v", got, before+1)
	}
}

func TestLoginRateLimited(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	h := newAPI(t, u)
	for i := 0; i < LoginPerUserLimit; i++ {
		h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "ara", "password": "wrong"})
	}
	code, out := h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "ara", "password": "correct-horse-12"})
	if code != http.StatusTooManyRequests {
		t.Fatalf("6th login = %d, want 429", code)
	}
	if out["error"] == nil {
		t.Errorf("429 body = %v", out)
	}
	last := h.audits.entries[len(h.audits.entries)-1]
	if last.Result != domain.ResultFailure || last.Detail["reason"] != "rate limited" {
		t.Errorf("rate-limited audit = %+v", last)
	}
}

func TestLoginLDAPAndDirectoryDown(t *testing.T) {
	u := ldapUser("dirara")
	h := newAPI(t, u)
	h.dir.passwords["dirara"] = "dir-secret-pw"

	out := h.login(t, "dirara", "dir-secret-pw")
	if out["user"].(map[string]any)["source"] != "ldap" {
		t.Errorf("login user = %v", out)
	}
	h.dir.err = errors.New("connection refused")
	code, out := h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "dirara", "password": "dir-secret-pw"})
	if code != http.StatusServiceUnavailable || out["error"] != "directory temporarily unavailable" {
		t.Errorf("directory down = %d, %v, want explicit 503", code, out)
	}
}

func TestMeUnauthenticated(t *testing.T) {
	h := newAPI(t)
	code, _ := h.do(http.MethodGet, "/api/auth/me", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("me = %d, want 401", code)
	}
}

// ---------- password management ----------

func TestChangePassword(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newAPI(t, u)
	h.login(t, "ara", "old-password-12")

	code, out := h.do(http.MethodPost, "/api/account/password/change", map[string]string{
		"current_password": "old-password-12", "new_password": "Brand-new-pass-1!", "new_password_confirm": "Brand-new-pass-1!",
	})
	if code != http.StatusOK {
		t.Fatalf("change = %d, %v", code, out)
	}
	// Session survives; old password dies, new password works.
	code, _ = h.do(http.MethodGet, "/api/auth/me", nil)
	if code != http.StatusOK {
		t.Fatalf("me after change = %d, want 200 (own session kept)", code)
	}
	code, _ = h.do(http.MethodPost, "/api/auth/logout", nil)
	if code != http.StatusNoContent {
		t.Fatal("logout")
	}
	code, _ = h.do(http.MethodPost, "/api/auth/login", map[string]string{"username": "ara", "password": "old-password-12"})
	if code != http.StatusUnauthorized {
		t.Fatalf("old password login = %d, want 401", code)
	}
	h.login(t, "ara", "Brand-new-pass-1!")
}

func TestChangePasswordFailures(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newAPI(t, u, ldapUser("dirara"))
	h.login(t, "ara", "old-password-12")

	code, out := h.do(http.MethodPost, "/api/account/password/change", map[string]string{
		"current_password": "not-the-password", "new_password": "Brand-new-pass-1!", "new_password_confirm": "Brand-new-pass-1!",
	})
	if code != http.StatusUnauthorized || out["error"] != "current password is incorrect" {
		t.Errorf("wrong current = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodPost, "/api/account/password/change", map[string]string{
		"current_password": "old-password-12", "new_password": "Brand-new-pass-1!", "new_password_confirm": "other-pass-word-1",
	})
	if code != http.StatusBadRequest {
		t.Errorf("mismatch = %d, want 400", code)
	}
	// LDAP user rejection.
	code, _ = h.do(http.MethodPost, "/api/auth/logout", nil)
	h.dir.passwords["dirara"] = "dir-secret-pw"
	h.login(t, "dirara", "dir-secret-pw")
	code, out = h.do(http.MethodPost, "/api/account/password/change", map[string]string{
		"current_password": "dir-secret-pw", "new_password": "Brand-new-pass-1!", "new_password_confirm": "Brand-new-pass-1!",
	})
	if code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "directory admin") {
		t.Errorf("ldap change = %d, %v, want explicit directory rejection", code, out)
	}
	// Unauthenticated.
	plain := newAPI(t, u)
	code, _ = plain.do(http.MethodPost, "/api/account/password/change", map[string]string{})
	if code != http.StatusUnauthorized {
		t.Errorf("unauthenticated change = %d, want 401", code)
	}
}

func TestUpdateAccountAvatar(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newAPI(t, u)
	h.login(t, "ara", "old-password-12")

	code, out := h.do(http.MethodPost, "/api/account/avatar", map[string]string{"avatar_url": "/uploads/avatar/9.webp"})
	if code != http.StatusOK {
		t.Fatalf("attach = %d, %v", code, out)
	}
	if out["user"].(map[string]any)["avatar_url"] != "/uploads/avatar/9.webp" {
		t.Fatalf("avatar_url = %v", out)
	}
	// Reflected by /api/auth/me.
	code, out = h.do(http.MethodGet, "/api/auth/me", nil)
	if code != http.StatusOK || out["user"].(map[string]any)["avatar_url"] != "/uploads/avatar/9.webp" {
		t.Fatalf("me = %d, %v", code, out)
	}
	// Rejections: empty, external, traversal, wrong prefix, bare prefix.
	for _, bad := range []string{"", "https://evil.example/x.png", "/uploads/../etc/passwd", "/other/x.png", "/uploads/"} {
		code, _ := h.do(http.MethodPost, "/api/account/avatar", map[string]string{"avatar_url": bad})
		if code != http.StatusBadRequest {
			t.Errorf("avatar_url %q = %d, want 400", bad, code)
		}
	}
	// Unauthenticated.
	plain := newAPI(t, u)
	code, _ = plain.do(http.MethodPost, "/api/account/avatar", map[string]string{"avatar_url": "/uploads/avatar/9.webp"})
	if code != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d, want 401", code)
	}
}

func TestForgotResetFlow(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newAPI(t, u, ldapUser("dirara"))

	code, out := h.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"login": "ara"})
	if code != http.StatusOK || out["message"] == nil {
		t.Fatalf("forgot = %d, %v", code, out)
	}
	// Unknown and LDAP identifiers get the identical generic message.
	code, ghost := h.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"login": "ghost"})
	if code != http.StatusOK || ghost["message"] != out["message"] {
		t.Fatalf("forgot(ghost) = %d, %v", code, ghost)
	}
	code, ld := h.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"login": "dirara"})
	if code != http.StatusOK || ld["message"] != out["message"] {
		t.Fatalf("forgot(ldap) = %d, %v", code, ld)
	}
	if len(h.mailer.to) != 1 {
		t.Fatalf("mails = %d, want 1", len(h.mailer.to))
	}
	// Redeem the token from the mail body.
	body := h.mailer.bodies[0]
	token := body[strings.Index(body, "token=")+len("token="):]
	token = strings.TrimSpace(strings.Split(token, "\n")[0])
	code, _ = h.do(http.MethodPost, "/api/auth/password/reset", map[string]string{
		"token": token, "new_password": "Reset-new-pass-1!", "new_password_confirm": "Reset-new-pass-1!",
	})
	if code != http.StatusOK {
		t.Fatalf("reset = %d", code)
	}
	h.login(t, "ara", "Reset-new-pass-1!")
	// Replay fails.
	code, _ = h.do(http.MethodPost, "/api/auth/password/reset", map[string]string{
		"token": token, "new_password": "Another-new-pass-1!", "new_password_confirm": "Another-new-pass-1!",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("replay = %d, want 400", code)
	}
}

func TestForgotRateLimited(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newAPI(t, u)
	for i := 0; i < ForgotPerLoginLimit; i++ {
		h.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"login": "ara"})
	}
	code, _ := h.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"login": "ara"})
	if code != http.StatusTooManyRequests {
		t.Fatalf("4th forgot = %d, want 429", code)
	}
}

// ---------- admin ----------

func TestAdminGuards(t *testing.T) {
	root := localUser("root", "root-password-12")
	bob := localUser("bob", "bob-password-12")
	h := newAPI(t, root, bob)
	ctx := context.Background()
	_ = h.groups.AddMember(ctx, root.ID, h.admin.ID)

	// Anonymous.
	code, _ := h.do(http.MethodGet, "/api/admin/users", nil)
	if code != http.StatusUnauthorized {
		t.Errorf("anonymous admin = %d, want 401", code)
	}
	// Non-admin.
	h.login(t, "bob", "bob-password-12")
	code, _ = h.do(http.MethodGet, "/api/admin/users", nil)
	if code != http.StatusForbidden {
		t.Errorf("non-admin = %d, want 403", code)
	}
	// Admin.
	h.do(http.MethodPost, "/api/auth/logout", nil)
	h.login(t, "root", "root-password-12")
	code, out := h.do(http.MethodGet, "/api/admin/users", nil)
	if code != http.StatusOK || out["total"] == nil {
		t.Errorf("admin list = %d, %v", code, out)
	}
}

func TestAdminUsers(t *testing.T) {
	root := localUser("root", "root-password-12")
	h := newAPI(t, root)
	_ = h.groups.AddMember(context.Background(), root.ID, h.admin.ID)
	h.login(t, "root", "root-password-12")

	code, out := h.do(http.MethodPost, "/api/admin/users", map[string]string{
		"username": "ara", "email": "ara@example.com", "password": "Long-password-1!",
	})
	if code != http.StatusCreated {
		t.Fatalf("create = %d, %v", code, out)
	}
	id := out["user"].(map[string]any)["id"].(string)

	code, out = h.do(http.MethodGet, "/api/admin/users/"+id, nil)
	if code != http.StatusOK {
		t.Fatalf("get = %d, %v", code, out)
	}
	code, out = h.do(http.MethodPatch, "/api/admin/users/"+id, map[string]string{"display_name": "Ara E"})
	if code != http.StatusOK || out["user"].(map[string]any)["display_name"] != "Ara E" {
		t.Fatalf("patch = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodPatch, "/api/admin/users/"+id, map[string]bool{"is_active": false})
	if code != http.StatusOK {
		t.Fatalf("deactivate = %d", code)
	}
	code, out = h.do(http.MethodGet, "/api/admin/users/"+id, nil)
	if code != http.StatusOK || out["user"].(map[string]any)["is_active"] != false {
		t.Fatalf("get after deactivate = %d, %v", code, out)
	}
	// Deactivating the last admin is refused.
	rootID := root.ID.String()
	code, out = h.do(http.MethodPatch, "/api/admin/users/"+rootID, map[string]bool{"is_active": false})
	if code != http.StatusForbidden {
		t.Fatalf("deactivate last admin = %d, %v, want 403", code, out)
	}
	code, _ = h.do(http.MethodGet, "/api/admin/users/not-a-uuid", nil)
	if code != http.StatusBadRequest {
		t.Errorf("bad uuid = %d, want 400", code)
	}
	code, _ = h.do(http.MethodGet, "/api/admin/users/"+uuid.NewString(), nil)
	if code != http.StatusNotFound {
		t.Errorf("unknown user = %d, want 404", code)
	}
}

func TestAdminUserAttrs(t *testing.T) {
	root := localUser("root", "root-password-12")
	ara := localUser("ara", "ara-password-123")
	h := newAPI(t, root, ara)
	_ = h.groups.AddMember(context.Background(), root.ID, h.admin.ID)
	h.login(t, "root", "root-password-12")
	araID := ara.ID.String()

	code, out := h.do(http.MethodPost, "/api/admin/user-attrs", map[string]any{
		"key": "dept", "type": "string", "multi": false,
	})
	if code != http.StatusCreated {
		t.Fatalf("create def = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodPost, "/api/admin/user-attrs", map[string]any{
		"key": "dept", "type": "string",
	})
	if code != http.StatusConflict {
		t.Fatalf("duplicate def = %d, want 409", code)
	}
	code, _ = h.do(http.MethodPost, "/api/admin/user-attrs", map[string]any{
		"key": "sub", "type": "string",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("reserved def = %d, want 400", code)
	}
	code, out = h.do(http.MethodGet, "/api/admin/user-attrs", nil)
	if code != http.StatusOK || len(out["defs"].([]any)) != 1 {
		t.Fatalf("list defs = %d, %v", code, out)
	}

	code, out = h.do(http.MethodPut, "/api/admin/users/"+araID+"/attrs", map[string]any{
		"dept": "eng",
	})
	if code != http.StatusOK || out["attrs"].(map[string]any)["dept"] != "eng" {
		t.Fatalf("set attrs = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodPut, "/api/admin/users/"+araID+"/attrs", map[string]any{
		"nosuch": "x",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("unknown key = %d, want 400", code)
	}
	code, out = h.do(http.MethodGet, "/api/admin/users/"+araID+"/attrs", nil)
	if code != http.StatusOK || out["attrs"].(map[string]any)["dept"] != "eng" {
		t.Fatalf("get attrs = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodGet, "/api/admin/users/"+uuid.NewString()+"/attrs", nil)
	if code != http.StatusNotFound {
		t.Fatalf("unknown user attrs = %d, want 404", code)
	}
	// Def delete cascades the values.
	code, _ = h.do(http.MethodDelete, "/api/admin/user-attrs/dept", nil)
	if code != http.StatusNoContent {
		t.Fatalf("delete def = %d", code)
	}
	code, out = h.do(http.MethodGet, "/api/admin/users/"+araID+"/attrs", nil)
	if code != http.StatusOK || len(out["attrs"].(map[string]any)) != 0 {
		t.Fatalf("attrs after def delete = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodDelete, "/api/admin/user-attrs/dept", nil)
	if code != http.StatusNotFound {
		t.Fatalf("second delete = %d, want 404", code)
	}
}

func TestAdminSetPassword(t *testing.T) {
	root := localUser("root", "root-password-12")
	ara := localUser("ara", "old-password-12")
	dir := ldapUser("dirara")
	h := newAPI(t, root, ara, dir)
	_ = h.groups.AddMember(context.Background(), root.ID, h.admin.ID)
	h.login(t, "root", "root-password-12")

	code, _ := h.do(http.MethodPost, "/api/admin/users/"+ara.ID.String()+"/password", map[string]string{"new_password": "Admin-set-pass-1!"})
	if code != http.StatusNoContent {
		t.Fatalf("admin set = %d, want 204", code)
	}
	h.do(http.MethodPost, "/api/auth/logout", nil)
	h.login(t, "ara", "Admin-set-pass-1!")

	h.do(http.MethodPost, "/api/auth/logout", nil)
	h.login(t, "root", "root-password-12")
	code, out := h.do(http.MethodPost, "/api/admin/users/"+dir.ID.String()+"/password", map[string]string{"new_password": "Admin-set-pass-1!"})
	if code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "directory admin") {
		t.Errorf("ldap target = %d, %v, want explicit rejection", code, out)
	}
}

func TestAdminInviteUser(t *testing.T) {
	root := localUser("root", "root-password-12")
	ara := localUser("ara", "old-password-12")
	h := newAPI(t, root, ara)
	_ = h.groups.AddMember(context.Background(), root.ID, h.admin.ID)
	h.login(t, "root", "root-password-12")

	code, out := h.do(http.MethodPost, "/api/admin/users/"+ara.ID.String()+"/invite", nil)
	if code != http.StatusOK || out["message"] != "Invitation sent." {
		t.Fatalf("invite = %d, %v", code, out)
	}
	if len(h.mailer.to) != 1 || h.mailer.to[0] != "ara@example.com" {
		t.Fatalf("invite sent to %v", h.mailer.to)
	}
	code, _ = h.do(http.MethodPost, "/api/admin/users/"+uuid.NewString()+"/invite", nil)
	if code != http.StatusNotFound {
		t.Fatalf("invite unknown = %d, want 404", code)
	}
	code, _ = h.do(http.MethodPost, "/api/admin/users/not-a-uuid/invite", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("invite malformed = %d, want 400", code)
	}

	// Non-admins are refused by the gate, before the usecase runs.
	h.do(http.MethodPost, "/api/auth/logout", nil)
	h.login(t, "ara", "old-password-12")
	code, _ = h.do(http.MethodPost, "/api/admin/users/"+ara.ID.String()+"/invite", nil)
	if code != http.StatusForbidden {
		t.Fatalf("member invite = %d, want 403", code)
	}
}

func TestAdminGroups(t *testing.T) {
	root := localUser("root", "root-password-12")
	ara := localUser("ara", "old-password-12")
	h := newAPI(t, root, ara)
	_ = h.groups.AddMember(context.Background(), root.ID, h.admin.ID)
	h.login(t, "root", "root-password-12")

	code, out := h.do(http.MethodPost, "/api/admin/groups", map[string]string{"name": "it"})
	if code != http.StatusCreated {
		t.Fatalf("create = %d, %v", code, out)
	}
	gid := out["group"].(map[string]any)["id"].(string)

	code, _ = h.do(http.MethodPost, "/api/admin/groups/"+gid+"/members", map[string]string{"user_id": ara.ID.String()})
	if code != http.StatusNoContent {
		t.Fatalf("add member = %d, want 204", code)
	}
	code, out = h.do(http.MethodGet, "/api/admin/groups/"+gid, nil)
	if code != http.StatusOK {
		t.Fatalf("get = %d, %v", code, out)
	}
	code, _ = h.do(http.MethodDelete, "/api/admin/groups/"+gid+"/members/"+ara.ID.String(), nil)
	if code != http.StatusNoContent {
		t.Fatalf("remove member = %d, want 204", code)
	}
	code, _ = h.do(http.MethodDelete, "/api/admin/groups/"+gid, nil)
	if code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", code)
	}
	// ih_admin is protected.
	code, _ = h.do(http.MethodDelete, "/api/admin/groups/"+h.admin.ID.String(), nil)
	if code != http.StatusForbidden {
		t.Errorf("delete ih_admin = %d, want 403", code)
	}
	code, _ = h.do(http.MethodDelete, "/api/admin/groups/"+h.admin.ID.String()+"/members/"+root.ID.String(), nil)
	if code != http.StatusForbidden {
		t.Errorf("self-remove from ih_admin = %d, want 403", code)
	}
}

func TestAdminAuditAndLDAPTest(t *testing.T) {
	root := localUser("root", "root-password-12")
	h := newAPI(t, root)
	_ = h.groups.AddMember(context.Background(), root.ID, h.admin.ID)
	h.login(t, "root", "root-password-12")

	code, out := h.do(http.MethodGet, "/api/admin/audit", nil)
	if code != http.StatusOK || out["total"] == nil {
		t.Fatalf("audit = %d, %v", code, out)
	}
	code, out = h.do(http.MethodGet, "/api/admin/audit?method=password&result=success", nil)
	if code != http.StatusOK {
		t.Fatalf("audit filter = %d", code)
	}
	code, _ = h.do(http.MethodGet, "/api/admin/audit?since=not-a-time", nil)
	if code != http.StatusBadRequest {
		t.Errorf("bad since = %d, want 400", code)
	}

	code, out = h.do(http.MethodPost, "/api/admin/ldap/test", nil)
	if code != http.StatusOK || out["configured"] != true || out["ok"] != true {
		t.Fatalf("ldap test = %d, %v", code, out)
	}
	h.dir.err = errors.New("connection refused")
	code, out = h.do(http.MethodPost, "/api/admin/ldap/test", nil)
	if code != http.StatusOK || out["ok"] != false {
		t.Fatalf("ldap test down = %d, %v", code, out)
	}

	h.withoutDirectory(t)
	h.login(t, "root", "root-password-12")
	code, out = h.do(http.MethodPost, "/api/admin/ldap/test", nil)
	if code != http.StatusOK || out["configured"] != false {
		t.Fatalf("ldap test disabled = %d, %v", code, out)
	}
}
