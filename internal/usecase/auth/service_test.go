package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

// ---------- fakes ----------

type fakeUsers struct {
	byID         map[uuid.UUID]domain.User
	byUsername   map[string]domain.User
	byEmail      map[string]domain.User
	err          error
	createErr    error
	setHashErr   error
	beforeCreate func()
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
	if f.err != nil {
		return domain.User{}, f.err
	}
	if f.createErr != nil {
		return domain.User{}, f.createErr
	}
	if f.beforeCreate != nil {
		f.beforeCreate()
	}
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
	if f.err != nil {
		return domain.User{}, f.err
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) ByUsername(_ context.Context, username string) (domain.User, error) {
	if f.err != nil {
		return domain.User{}, f.err
	}
	u, ok := f.byUsername[username]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) ByUsernameFold(_ context.Context, username string) (domain.User, error) {
	if f.err != nil {
		return domain.User{}, f.err
	}
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
	if f.err != nil {
		return domain.User{}, f.err
	}
	u, ok := f.byEmail[email]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) List(_ context.Context, _ domain.UserFilter) ([]domain.User, int, error) {
	return nil, 0, nil
}

func (f *fakeUsers) AllActive(_ context.Context) ([]domain.User, error) {
	if f.err != nil {
		return nil, f.err
	}
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
	if f.setHashErr != nil {
		return f.setHashErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.PasswordHash = hash
	f.put(u)
	return nil
}

type fakeGroups struct {
	members map[uuid.UUID]map[string]bool // user -> group names
	err     error
}

func (f *fakeGroups) IsMember(_ context.Context, userID uuid.UUID, groupName string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.members[userID][groupName], nil
}

func (f *fakeGroups) Create(_ context.Context, g domain.Group) (domain.Group, error) {
	return g, nil
}
func (f *fakeGroups) ByID(_ context.Context, id uuid.UUID) (domain.Group, error) {
	return domain.Group{}, domain.ErrNotFound
}
func (f *fakeGroups) ByName(_ context.Context, name string) (domain.Group, error) {
	return domain.Group{}, domain.ErrNotFound
}
func (f *fakeGroups) List(_ context.Context, _, _ int) ([]domain.Group, int, error) {
	return nil, 0, nil
}
func (f *fakeGroups) All(_ context.Context) ([]domain.Group, error) {
	return nil, nil
}
func (f *fakeGroups) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeGroups) AddMember(_ context.Context, userID, _ uuid.UUID) error {
	if f.members == nil {
		f.members = map[uuid.UUID]map[string]bool{}
	}
	return nil
}
func (f *fakeGroups) RemoveMember(_ context.Context, _, _ uuid.UUID) error { return nil }
func (f *fakeGroups) MemberIDs(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeGroups) MemberUsernamesByGroup(_ context.Context) (map[uuid.UUID][]string, error) {
	return map[uuid.UUID][]string{}, nil
}
func (f *fakeGroups) GroupsOfUser(_ context.Context, _ uuid.UUID) ([]domain.Group, error) {
	return nil, nil
}

type fakeResets struct {
	byHash map[string]domain.PasswordResetToken
	byID   map[uuid.UUID]domain.PasswordResetToken
	err    error
}

func newFakeResets() *fakeResets {
	return &fakeResets{byHash: map[string]domain.PasswordResetToken{}, byID: map[uuid.UUID]domain.PasswordResetToken{}}
}

func (f *fakeResets) Create(_ context.Context, tok domain.PasswordResetToken) (domain.PasswordResetToken, error) {
	if f.err != nil {
		return domain.PasswordResetToken{}, f.err
	}
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
	if f.err != nil {
		return domain.PasswordResetToken{}, f.err
	}
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
	err    error
	addErr error
}

func (f *fakeHistory) Add(_ context.Context, userID uuid.UUID, hash []byte) error {
	if f.addErr != nil {
		return f.addErr
	}
	if f.err != nil {
		return f.err
	}
	if f.hashes == nil {
		f.hashes = map[uuid.UUID][][]byte{}
	}
	f.hashes[userID] = append([][]byte{hash}, f.hashes[userID]...)
	if len(f.hashes[userID]) > HistoryDepth {
		f.hashes[userID] = f.hashes[userID][:HistoryDepth]
	}
	return nil
}

func (f *fakeHistory) Recent(_ context.Context, userID uuid.UUID, limit int) ([][]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	h := f.hashes[userID]
	if len(h) > limit {
		h = h[:limit]
	}
	return h, nil
}

type fakeSessions struct {
	tokens map[uuid.UUID]map[string]bool
	err    error
}

func (f *fakeSessions) Register(_ context.Context, userID uuid.UUID, token string) error {
	if f.tokens == nil {
		f.tokens = map[uuid.UUID]map[string]bool{}
	}
	if f.tokens[userID] == nil {
		f.tokens[userID] = map[string]bool{}
	}
	f.tokens[userID][token] = true
	return nil
}

func (f *fakeSessions) Unregister(_ context.Context, token string) error {
	for u, set := range f.tokens {
		delete(set, token)
		f.tokens[u] = set
	}
	return nil
}

func (f *fakeSessions) RevokeOthers(_ context.Context, userID uuid.UUID, keep string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	var n int64
	for tok := range f.tokens[userID] {
		if tok != keep {
			delete(f.tokens[userID], tok)
			n++
		}
	}
	return n, nil
}

func (f *fakeSessions) RevokeAll(_ context.Context, userID uuid.UUID) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	n := int64(len(f.tokens[userID]))
	f.tokens[userID] = map[string]bool{}
	return n, nil
}

type fakeAuditStore struct {
	entries []domain.AuditEntry
	err     error
}

func (f *fakeAuditStore) Append(_ context.Context, e domain.AuditEntry) error {
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeAuditStore) List(_ context.Context, _ domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	return f.entries, len(f.entries), nil
}

type fakeHasher struct{ err error }

func (h fakeHasher) Hash(password string) ([]byte, error) {
	if h.err != nil {
		return nil, h.err
	}
	return []byte("hash:" + password), nil
}
func (fakeHasher) Verify(password string, hash []byte) bool {
	return string(hash) == "hash:"+password
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeMailer struct {
	to      []string
	subject []string
	bodies  []string
	err     error
}

func (f *fakeMailer) Send(to, subject, textBody, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.to = append(f.to, to)
	f.subject = append(f.subject, subject)
	f.bodies = append(f.bodies, textBody)
	return nil
}

type fakeDirectory struct {
	passwords map[string]string // username -> password
	profiles  map[string]domain.LDAPUser
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
	if p, ok := f.profiles[username]; ok {
		return p, nil
	}
	return domain.LDAPUser{Username: username, Email: username + "@dir.example.com", DisplayName: username, DN: "uid=" + username + ",ou=users,dc=example,dc=com"}, nil
}

func (f *fakeDirectory) Snapshot(_ context.Context) (domain.DirectorySnapshot, error) {
	return domain.DirectorySnapshot{}, f.err
}

func (f *fakeDirectory) Ping(_ context.Context) error { return f.err }

type fakeAttrs struct {
	defs   map[string]domain.UserAttrDef
	byID   map[uuid.UUID]domain.UserAttrDef
	values map[uuid.UUID]map[uuid.UUID][]string
	err    error
}

func newFakeAttrs(defs ...domain.UserAttrDef) *fakeAttrs {
	f := &fakeAttrs{
		defs: map[string]domain.UserAttrDef{}, byID: map[uuid.UUID]domain.UserAttrDef{},
		values: map[uuid.UUID]map[uuid.UUID][]string{},
	}
	for _, d := range defs {
		if d.ID == uuid.Nil {
			d.ID = uuid.New()
		}
		f.defs[d.Key] = d
		f.byID[d.ID] = d
	}
	return f
}

func (f *fakeAttrs) CreateDef(_ context.Context, d domain.UserAttrDef) (domain.UserAttrDef, error) {
	if f.err != nil {
		return domain.UserAttrDef{}, f.err
	}
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
	if f.err != nil {
		return nil, f.err
	}
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
	return nil
}

func (f *fakeAttrs) SetValues(_ context.Context, userID uuid.UUID, values map[uuid.UUID][]string, _ domain.UserAttrSource) error {
	if f.values[userID] == nil {
		f.values[userID] = map[uuid.UUID][]string{}
	}
	for id, vals := range values {
		f.values[userID][id] = vals
	}
	return nil
}

func (f *fakeAttrs) ApplyUpstreamValues(_ context.Context, userID uuid.UUID, values map[uuid.UUID][]string) error {
	if f.err != nil {
		return f.err
	}
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
			out[d.Key] = vals
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

// ---------- harness ----------

type harness struct {
	users    *fakeUsers
	groups   *fakeGroups
	resets   *fakeResets
	history  *fakeHistory
	sessions *fakeSessions
	audits   *fakeAuditStore
	mailer   *fakeMailer
	dir      *fakeDirectory
	svc      *Service
	now      time.Time
}

func newHarness(t *testing.T, users ...domain.User) *harness {
	t.Helper()
	h := &harness{
		users:    newFakeUsers(users...),
		groups:   &fakeGroups{members: map[uuid.UUID]map[string]bool{}},
		resets:   newFakeResets(),
		history:  &fakeHistory{},
		sessions: &fakeSessions{},
		audits:   &fakeAuditStore{},
		mailer:   &fakeMailer{},
		dir:      &fakeDirectory{passwords: map[string]string{}, profiles: map[string]domain.LDAPUser{}},
		now:      time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
	}
	svc, err := New(Deps{
		Users: h.users, Groups: h.groups, Resets: h.resets, History: h.history,
		Sessions: h.sessions, Audit: audit.New(h.audits, fixedClock{now: h.now}),
		Hasher: fakeHasher{}, Clock: fixedClock{now: h.now}, Mailer: h.mailer,
		Directory: h.dir, BaseURL: "https://idp.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h
}

func (h *harness) withoutDirectory(t *testing.T) {
	t.Helper()
	svc, err := New(Deps{
		Users: h.users, Groups: h.groups, Resets: h.resets, History: h.history,
		Sessions: h.sessions, Audit: audit.New(h.audits, fixedClock{now: h.now}),
		Hasher: fakeHasher{}, Clock: fixedClock{now: h.now}, Mailer: h.mailer,
		BaseURL: "https://idp.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
}

func localUser(username, password string) domain.User {
	return domain.User{
		ID: uuid.New(), Username: username, Email: username + "@example.com",
		DisplayName: username, PasswordHash: []byte("hash:" + password),
		Source: domain.SourceLocal, IsActive: true,
	}
}

func ldapUser(username string, active bool) domain.User {
	return domain.User{
		ID: uuid.New(), Username: username, Email: username + "@dir.example.com",
		DisplayName: username, Source: domain.SourceLDAP,
		ExternalDN: "uid=" + username + ",ou=users,dc=example,dc=com", IsActive: active,
	}
}

func lastAudit(h *harness) domain.AuditEntry { return h.audits.entries[len(h.audits.entries)-1] }

// ---------- New ----------

func TestNewRequiresDeps(t *testing.T) {
	h := newHarness(t)
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New(empty) = nil, want error")
	}
	full := Deps{Users: h.users, Groups: h.groups, Resets: h.resets, History: h.history,
		Sessions: h.sessions, Audit: audit.New(h.audits, fixedClock{}), Hasher: fakeHasher{},
		Mailer: h.mailer}
	if _, err := New(full); err != nil {
		t.Fatalf("New(full, nil clock/dir) = %v", err)
	}
}

// ---------- Login ----------

func TestLoginLocalSuccess(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	h := newHarness(t, u)
	got, err := h.svc.Login(context.Background(), LoginInput{Username: "ara", Password: "correct-horse-12", IP: "10.0.0.1"})
	if err != nil {
		t.Fatalf("Login = %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("Login user = %v, want %v", got.ID, u.ID)
	}
	if len(h.audits.entries) != 1 {
		t.Fatalf("audit entries = %d, want exactly 1", len(h.audits.entries))
	}
	a := lastAudit(h)
	if a.Method != domain.MethodPassword || a.Result != domain.ResultSuccess || a.IP != "10.0.0.1" {
		t.Errorf("audit = %+v", a)
	}
	if a.ActorUserID == nil || *a.ActorUserID != u.ID {
		t.Errorf("audit actor = %v, want %v", a.ActorUserID, u.ID)
	}
}

func TestLoginFailuresAreGenericAndAudited(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	disabled := localUser("zed", "correct-horse-12")
	disabled.IsActive = false

	cases := []struct {
		name     string
		username string
		password string
		wantErr  error
	}{
		{"wrong password", "ara", "nope-nope-nope", domain.ErrUnauthorized},
		{"unknown user", "ghost", "whatever-pass", domain.ErrUnauthorized},
		{"empty username", "", "whatever-pass", domain.ErrUnauthorized},
		{"empty password", "ara", "", domain.ErrUnauthorized},
		{"disabled user", "zed", "correct-horse-12", domain.ErrForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, u, disabled)
			_, err := h.svc.Login(context.Background(), LoginInput{Username: tc.username, Password: tc.password, IP: "10.0.0.1"})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Login = %v, want %v", err, tc.wantErr)
			}
			if len(h.audits.entries) != 1 {
				t.Fatalf("audit entries = %d, want exactly 1", len(h.audits.entries))
			}
			if got := lastAudit(h); got.Result != domain.ResultFailure {
				t.Errorf("audit result = %q, want failure", got.Result)
			}
		})
	}
}

func TestLoginLDAPUser(t *testing.T) {
	u := ldapUser("dirara", true)
	h := newHarness(t, u)
	h.dir.passwords["dirara"] = "dir-secret-pw"

	got, err := h.svc.Login(context.Background(), LoginInput{Username: "dirara", Password: "dir-secret-pw"})
	if err != nil || got.ID != u.ID {
		t.Fatalf("Login = %v, %+v", err, got)
	}
	if a := lastAudit(h); a.Method != domain.MethodLDAP || a.Result != domain.ResultSuccess {
		t.Errorf("audit = %+v, want ldap/success", a)
	}

	if _, err := h.svc.Login(context.Background(), LoginInput{Username: "dirara", Password: "wrong-password"}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("bad directory password = %v, want ErrUnauthorized", err)
	}
	if a := lastAudit(h); a.Method != domain.MethodLDAP || a.Result != domain.ResultFailure {
		t.Errorf("audit = %+v, want ldap/failure", a)
	}
}

func TestLoginLDAPUserDisabled(t *testing.T) {
	u := ldapUser("gone", false)
	h := newHarness(t, u)
	h.dir.passwords["gone"] = "dir-secret-pw"
	if _, err := h.svc.Login(context.Background(), LoginInput{Username: "gone", Password: "dir-secret-pw"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("Login = %v, want ErrForbidden", err)
	}
}

func TestLoginLDAPUnavailableIsExplicit(t *testing.T) {
	u := ldapUser("dirara", true)
	h := newHarness(t, u)
	h.dir.err = errors.New("connection refused")
	_, err := h.svc.Login(context.Background(), LoginInput{Username: "dirara", Password: "x"})
	if errors.Is(err, domain.ErrUnauthorized) || err == nil {
		t.Fatalf("Login = %v, want explicit directory error", err)
	}
	if !strings.Contains(err.Error(), "directory unavailable") {
		t.Errorf("error = %q, want explicit directory message", err)
	}
	if a := lastAudit(h); a.Result != domain.ResultFailure {
		t.Errorf("audit result = %q, want failure", a.Result)
	}
}

func TestLoginLDAPUserWhenDirectoryDisabled(t *testing.T) {
	u := ldapUser("dirara", true)
	h := newHarness(t, u)
	h.withoutDirectory(t)
	if _, err := h.svc.Login(context.Background(), LoginInput{Username: "dirara", Password: "x"}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("Login = %v, want ErrUnauthorized", err)
	}
}

func TestLoginJITProvisionsUnknownDirectoryUser(t *testing.T) {
	h := newHarness(t)
	h.dir.passwords["fresh"] = "fresh-secret-pw"
	got, err := h.svc.Login(context.Background(), LoginInput{Username: "fresh", Password: "fresh-secret-pw"})
	if err != nil {
		t.Fatalf("Login = %v", err)
	}
	if got.Source != domain.SourceLDAP || got.ExternalDN == "" || !got.IsActive {
		t.Errorf("provisioned user = %+v", got)
	}
	if a := lastAudit(h); a.Method != domain.MethodLDAP || a.Result != domain.ResultSuccess {
		t.Errorf("audit = %+v", a)
	}
}

func TestLoginJITAppliesUpstreamAttrs(t *testing.T) {
	h := newHarness(t)
	attrs := newFakeAttrs(domain.UserAttrDef{Key: "dept", Type: domain.UserAttrString})
	svc, err := New(Deps{
		Users: h.users, Groups: h.groups, Resets: h.resets, History: h.history,
		Sessions: h.sessions, Audit: audit.New(h.audits, fixedClock{now: h.now}),
		Hasher: fakeHasher{}, Clock: fixedClock{now: h.now}, Mailer: h.mailer,
		Directory: h.dir, BaseURL: "https://idp.example.com", Attrs: attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.dir.passwords["fresh"] = "fresh-secret-pw"
	h.dir.profiles["fresh"] = domain.LDAPUser{
		Username: "fresh", Email: "fresh@dir.example.com", DisplayName: "fresh",
		DN:    "uid=fresh,ou=users,dc=example,dc=com",
		Attrs: map[string][]string{"dept": {"eng"}, "nosuch": {"x"}},
	}
	got, err := svc.Login(context.Background(), LoginInput{Username: "fresh", Password: "fresh-secret-pw"})
	if err != nil {
		t.Fatalf("Login = %v", err)
	}
	vals, err := attrs.ValuesOfUser(context.Background(), got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 1 || len(vals["dept"]) != 1 || vals["dept"][0] != "eng" {
		t.Fatalf("provisioned attrs = %v", vals)
	}
}

func TestLoginUnknownUserDirectoryRejects(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Login(context.Background(), LoginInput{Username: "ghost", Password: "x"}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("Login = %v, want ErrUnauthorized", err)
	}
	if a := lastAudit(h); a.Method != domain.MethodLDAP || a.Result != domain.ResultFailure {
		t.Errorf("audit = %+v, want ldap/failure", a)
	}
}

func TestLoginAuditFailureFailsClosed(t *testing.T) {
	u := localUser("ara", "correct-horse-12")
	h := newHarness(t, u)
	h.audits.err = errors.New("audit db down")
	if _, err := h.svc.Login(context.Background(), LoginInput{Username: "ara", Password: "correct-horse-12"}); err == nil {
		t.Fatal("Login with broken audit = nil, want failure (fail-closed)")
	}
	if _, err := h.svc.Login(context.Background(), LoginInput{Username: "ara", Password: "wrong-password"}); err == nil {
		t.Fatal("failed Login with broken audit = nil, want failure (fail-closed)")
	}
}

// ---------- ChangePassword ----------

func TestChangePassword(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newHarness(t, u)
	ctx := context.Background()
	_ = h.sessions.Register(ctx, u.ID, "current-token")
	_ = h.sessions.Register(ctx, u.ID, "other-token-1")
	_ = h.sessions.Register(ctx, u.ID, "other-token-2")

	revoked, err := h.svc.ChangePassword(ctx, u.ID, "old-password-12", "brand-new-pass-1", "brand-new-pass-1", "current-token")
	if err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
	if revoked != 2 {
		t.Errorf("revoked = %d, want 2", revoked)
	}
	got, _ := h.users.ByID(ctx, u.ID)
	if !(fakeHasher{}).Verify("brand-new-pass-1", got.PasswordHash) {
		t.Error("password hash was not updated")
	}
	if len(h.sessions.tokens[u.ID]) != 1 || !h.sessions.tokens[u.ID]["current-token"] {
		t.Errorf("remaining sessions = %v, want only current-token", h.sessions.tokens[u.ID])
	}
	if a := lastAudit(h); a.Detail["action"] != audit.ActionPasswordChange {
		t.Errorf("audit action = %v", a.Detail)
	}
	// Old password is now in history: changing back is rejected.
	if _, err := h.svc.ChangePassword(ctx, u.ID, "brand-new-pass-1", "old-password-12", "old-password-12", "current-token"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("reuse of previous password = %v, want ErrValidation", err)
	}
}

func TestChangePasswordFailures(t *testing.T) {
	u := localUser("ara", "old-password-12")
	ld := ldapUser("dirara", true)
	cases := []struct {
		name    string
		user    domain.User
		current string
		new1    string
		new2    string
		wantErr error
	}{
		{"mismatch", u, "old-password-12", "brand-new-pass-1", "brand-new-pass-2", domain.ErrValidation},
		{"wrong current", u, "not-the-password", "brand-new-pass-1", "brand-new-pass-1", domain.ErrUnauthorized},
		{"too short", u, "old-password-12", "short", "short", domain.ErrValidation},
		{"same as current", u, "old-password-12", "old-password-12", "old-password-12", domain.ErrValidation},
		{"ldap user rejected", ld, "whatever", "brand-new-pass-1", "brand-new-pass-1", domain.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, u, ld)
			_, err := h.svc.ChangePassword(context.Background(), tc.user.ID, tc.current, tc.new1, tc.new2, "tok")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ChangePassword = %v, want %v", err, tc.wantErr)
			}
			if tc.name == "ldap user rejected" && !strings.Contains(err.Error(), "directory admin") {
				t.Errorf("ldap rejection = %q, want explicit directory message", err)
			}
		})
	}
}

func TestChangePasswordUnknownUser(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ChangePassword(context.Background(), uuid.New(), "a", "brand-new-pass-1", "brand-new-pass-1", "t"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("ChangePassword = %v, want ErrNotFound", err)
	}
}

// ---------- ForgotPassword ----------

func TestForgotPasswordSendsLink(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newHarness(t, u)
	h.svc.tokenGen = func(n int) ([]byte, error) { return []byte(strings.Repeat("R", n)), nil }

	if err := h.svc.ForgotPassword(context.Background(), "ara", "10.0.0.2"); err != nil {
		t.Fatalf("ForgotPassword = %v", err)
	}
	if len(h.mailer.to) != 1 || h.mailer.to[0] != u.Email {
		t.Fatalf("mailed to %v, want [%s]", h.mailer.to, u.Email)
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("R", ResetTokenBytes)))
	if !strings.Contains(h.mailer.bodies[0], "https://idp.example.com/reset-password?token="+encoded) {
		t.Errorf("mail body lacks reset link:\n%s", h.mailer.bodies[0])
	}
	sum := sha256.Sum256([]byte(encoded))
	tok, err := h.resets.ByHash(context.Background(), sum[:])
	if err != nil {
		t.Fatalf("token not stored: %v", err)
	}
	if !tok.ExpiresAt.Equal(h.now.Add(ResetTokenTTL)) {
		t.Errorf("expiry = %v, want now+15m", tok.ExpiresAt)
	}
	// Lookup by email works too.
	if err := h.svc.ForgotPassword(context.Background(), u.Email, "10.0.0.2"); err != nil {
		t.Fatalf("ForgotPassword(email) = %v", err)
	}
	if len(h.mailer.to) != 2 {
		t.Errorf("second forgot sent %d mails, want 2 total", len(h.mailer.to))
	}
}

func TestForgotPasswordGenericForNonLocal(t *testing.T) {
	ld := ldapUser("dirara", true)
	ld.Email = "dirara@example.com"
	inactive := localUser("zed", "old-password-12")
	inactive.IsActive = false
	noMail := localUser("nomail", "old-password-12")
	noMail.Email = ""
	h := newHarness(t, ld, inactive, noMail)

	for _, key := range []string{"ghost", "ghost@example.com", "dirara", "zed", "nomail", "", "  "} {
		if err := h.svc.ForgotPassword(context.Background(), key, "10.0.0.2"); err != nil {
			t.Errorf("ForgotPassword(%q) = %v, want nil (generic)", key, err)
		}
	}
	if len(h.mailer.to) != 0 {
		t.Errorf("mails sent = %d, want 0", len(h.mailer.to))
	}
	if len(h.resets.byID) != 0 {
		t.Errorf("tokens stored = %d, want 0", len(h.resets.byID))
	}
}

func TestForgotPasswordOneActiveToken(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newHarness(t, u)
	h.svc.tokenGen = func(n int) ([]byte, error) { return []byte(strings.Repeat("R", n)), nil }
	ctx := context.Background()
	if err := h.svc.ForgotPassword(ctx, "ara", ""); err != nil {
		t.Fatal(err)
	}
	h.svc.tokenGen = func(n int) ([]byte, error) { return []byte(strings.Repeat("S", n)), nil }
	if err := h.svc.ForgotPassword(ctx, "ara", ""); err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, tok := range h.resets.byID {
		if tok.UsedAt == nil {
			active++
		}
	}
	if active != 1 {
		t.Errorf("active tokens = %d, want 1", active)
	}
}

func TestForgotPasswordMailFailureSurfaces(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newHarness(t, u)
	h.mailer.err = errors.New("smtp down")
	// The usecase reports the infra failure; the HTTP layer logs it and
	// still answers generically (anti-enumeration).
	if err := h.svc.ForgotPassword(context.Background(), "ara", ""); err == nil {
		t.Fatal("ForgotPassword(mail down) = nil, want error")
	}
}

// ---------- ResetPassword ----------

func issueToken(t *testing.T, h *harness, u domain.User, rawByte byte) string {
	t.Helper()
	h.svc.tokenGen = func(n int) ([]byte, error) { return []byte(strings.Repeat(string(rune(rawByte)), n)), nil }
	if err := h.svc.ForgotPassword(context.Background(), u.Username, ""); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(rune(rawByte)), ResetTokenBytes)))
}

func TestResetPassword(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newHarness(t, u)
	ctx := context.Background()
	_ = h.sessions.Register(ctx, u.ID, "sess-1")
	encoded := issueToken(t, h, u, 'R')

	if err := h.svc.ResetPassword(ctx, encoded, "reset-new-pass-1", "reset-new-pass-1"); err != nil {
		t.Fatalf("ResetPassword = %v", err)
	}
	got, _ := h.users.ByID(ctx, u.ID)
	if !(fakeHasher{}).Verify("reset-new-pass-1", got.PasswordHash) {
		t.Error("password hash was not updated")
	}
	if len(h.sessions.tokens[u.ID]) != 0 {
		t.Errorf("sessions after reset = %v, want all revoked", h.sessions.tokens[u.ID])
	}
	if a := lastAudit(h); a.Detail["action"] != audit.ActionPasswordReset {
		t.Errorf("audit action = %v", a.Detail)
	}
	// Single-use: replay fails.
	if err := h.svc.ResetPassword(ctx, encoded, "another-new-pass", "another-new-pass"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("replay = %v, want ErrValidation", err)
	}
}

func TestResetPasswordFailures(t *testing.T) {
	u := localUser("ara", "old-password-12")
	newHarnessWithToken := func(t *testing.T) (*harness, string) {
		h := newHarness(t, u)
		return h, issueToken(t, h, u, 'R')
	}
	t.Run("unknown token", func(t *testing.T) {
		h, _ := newHarnessWithToken(t)
		other := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("Z", ResetTokenBytes)))
		err := h.svc.ResetPassword(context.Background(), other, "reset-new-pass-1", "reset-new-pass-1")
		if !errors.Is(err, domain.ErrValidation) || !strings.Contains(err.Error(), "invalid or expired") {
			t.Fatalf("ResetPassword = %v, want generic invalid-or-expired", err)
		}
	})
	t.Run("malformed token", func(t *testing.T) {
		h, _ := newHarnessWithToken(t)
		for _, bad := range []string{"", "not-base64!!!", "dG9vLXNob3J0"} {
			if err := h.svc.ResetPassword(context.Background(), bad, "reset-new-pass-1", "reset-new-pass-1"); !errors.Is(err, domain.ErrValidation) {
				t.Errorf("ResetPassword(%q) = %v, want ErrValidation", bad, err)
			}
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		h, encoded := newHarnessWithToken(t)
		if err := h.svc.ResetPassword(context.Background(), encoded, "reset-new-pass-1", "reset-new-pass-2"); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("ResetPassword = %v, want ErrValidation", err)
		}
	})
	t.Run("too short", func(t *testing.T) {
		h, encoded := newHarnessWithToken(t)
		if err := h.svc.ResetPassword(context.Background(), encoded, "short", "short"); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("ResetPassword = %v, want ErrValidation", err)
		}
	})
	t.Run("same as current", func(t *testing.T) {
		h, encoded := newHarnessWithToken(t)
		if err := h.svc.ResetPassword(context.Background(), encoded, "old-password-12", "old-password-12"); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("ResetPassword = %v, want ErrValidation", err)
		}
	})
	t.Run("expired token", func(t *testing.T) {
		h := newHarness(t, u)
		// Store under the hash of a valid-shape token.
		raw := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("E", ResetTokenBytes)))
		s := sha256.Sum256([]byte(raw))
		id := uuid.New()
		tok := domain.PasswordResetToken{ID: id, UserID: u.ID, TokenHash: s[:], ExpiresAt: h.now.Add(-time.Minute)}
		h.resets.byID[id] = tok
		h.resets.byHash[string(s[:])] = tok
		if err := h.svc.ResetPassword(context.Background(), raw, "reset-new-pass-1", "reset-new-pass-1"); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("ResetPassword(expired) = %v, want ErrValidation", err)
		}
	})
	t.Run("ldap user rejected", func(t *testing.T) {
		ld := ldapUser("dirara", true)
		h := newHarness(t, ld)
		raw := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("L", ResetTokenBytes)))
		s := sha256.Sum256([]byte(raw))
		id := uuid.New()
		tok := domain.PasswordResetToken{ID: id, UserID: ld.ID, TokenHash: s[:], ExpiresAt: h.now.Add(time.Minute)}
		h.resets.byID[id] = tok
		h.resets.byHash[string(s[:])] = tok
		err := h.svc.ResetPassword(context.Background(), raw, "reset-new-pass-1", "reset-new-pass-1")
		if !errors.Is(err, domain.ErrValidation) || !strings.Contains(err.Error(), "directory admin") {
			t.Fatalf("ResetPassword(ldap) = %v, want explicit directory rejection", err)
		}
	})
}

// ---------- AdminSetPassword ----------

func TestAdminSetPassword(t *testing.T) {
	admin := localUser("root", "root-password-12")
	target := localUser("ara", "old-password-12")
	h := newHarness(t, admin, target)
	h.groups.members[admin.ID] = map[string]bool{domain.AdminGroup: true}
	ctx := context.Background()
	_ = h.sessions.Register(ctx, target.ID, "sess-1")

	if err := h.svc.AdminSetPassword(ctx, admin.ID, target.ID, "admin-set-pass-1"); err != nil {
		t.Fatalf("AdminSetPassword = %v", err)
	}
	got, _ := h.users.ByID(ctx, target.ID)
	if !(fakeHasher{}).Verify("admin-set-pass-1", got.PasswordHash) {
		t.Error("password hash was not updated")
	}
	if len(h.sessions.tokens[target.ID]) != 0 {
		t.Errorf("sessions = %v, want all revoked", h.sessions.tokens[target.ID])
	}
	a := lastAudit(h)
	if a.Detail["action"] != audit.ActionAdminPasswordReset || a.ActorUserID == nil || *a.ActorUserID != admin.ID {
		t.Errorf("audit = %+v, want admin action by %v", a, admin.ID)
	}
	if a.Detail["target_user_id"] != target.ID.String() {
		t.Errorf("audit target = %v", a.Detail)
	}
}

func TestAdminSetPasswordFailures(t *testing.T) {
	admin := localUser("root", "root-password-12")
	plain := localUser("bob", "bob-password-12")
	target := localUser("ara", "old-password-12")
	ld := ldapUser("dirara", true)

	setup := func(t *testing.T) *harness {
		h := newHarness(t, admin, plain, target, ld)
		h.groups.members[admin.ID] = map[string]bool{domain.AdminGroup: true}
		return h
	}
	t.Run("non-admin forbidden", func(t *testing.T) {
		h := setup(t)
		if err := h.svc.AdminSetPassword(context.Background(), plain.ID, target.ID, "admin-set-pass-1"); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("AdminSetPassword = %v, want ErrForbidden", err)
		}
	})
	t.Run("ldap target rejected", func(t *testing.T) {
		h := setup(t)
		err := h.svc.AdminSetPassword(context.Background(), admin.ID, ld.ID, "admin-set-pass-1")
		if !errors.Is(err, domain.ErrValidation) || !strings.Contains(err.Error(), "directory admin") {
			t.Fatalf("AdminSetPassword = %v, want explicit directory rejection", err)
		}
	})
	t.Run("too short", func(t *testing.T) {
		h := setup(t)
		if err := h.svc.AdminSetPassword(context.Background(), admin.ID, target.ID, "short"); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("AdminSetPassword = %v, want ErrValidation", err)
		}
	})
	t.Run("same as current", func(t *testing.T) {
		h := setup(t)
		if err := h.svc.AdminSetPassword(context.Background(), admin.ID, target.ID, "old-password-12"); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("AdminSetPassword = %v, want ErrValidation", err)
		}
	})
	t.Run("unknown target", func(t *testing.T) {
		h := setup(t)
		if err := h.svc.AdminSetPassword(context.Background(), admin.ID, uuid.New(), "admin-set-pass-1"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("AdminSetPassword = %v, want ErrNotFound", err)
		}
	})
}

func TestLoginInfraFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("user lookup failure", func(t *testing.T) {
		h := newHarness(t)
		h.users.err = errors.New("db down")
		if _, err := h.svc.Login(ctx, LoginInput{Username: "ara", Password: "x"}); err == nil {
			t.Fatal("Login = nil, want error")
		}
	})
	t.Run("unknown user without directory", func(t *testing.T) {
		h := newHarness(t)
		h.withoutDirectory(t)
		if _, err := h.svc.Login(ctx, LoginInput{Username: "ghost", Password: "x"}); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("Login = %v, want ErrUnauthorized", err)
		}
		if a := lastAudit(h); a.Method != domain.MethodPassword || a.Result != domain.ResultFailure {
			t.Errorf("audit = %+v", a)
		}
	})
	t.Run("unknown user directory outage", func(t *testing.T) {
		h := newHarness(t)
		h.dir.err = errors.New("connection refused")
		_, err := h.svc.Login(ctx, LoginInput{Username: "ghost", Password: "x"})
		if err == nil || !strings.Contains(err.Error(), "directory unavailable") {
			t.Fatalf("Login = %v, want explicit directory error", err)
		}
	})
	t.Run("jit provision failure", func(t *testing.T) {
		h := newHarness(t)
		h.dir.passwords["fresh"] = "pw"
		h.users.createErr = errors.New("db down")
		if _, err := h.svc.Login(ctx, LoginInput{Username: "fresh", Password: "pw"}); err == nil {
			t.Fatal("Login = nil, want error")
		}
	})
	t.Run("jit conflict rereads winner", func(t *testing.T) {
		h := newHarness(t)
		h.dir.passwords["racer"] = "pw"
		winner := ldapUser("racer", true)
		// The racing sync lands between our lookup miss and Create.
		h.users.beforeCreate = func() { h.users.put(winner) }
		got, err := h.svc.Login(ctx, LoginInput{Username: "racer", Password: "pw"})
		if err != nil || got.ID != winner.ID {
			t.Fatalf("Login = %v, %+v", err, got)
		}
	})
	t.Run("jit conflict rereads disabled winner", func(t *testing.T) {
		h := newHarness(t)
		h.dir.passwords["racer"] = "pw"
		winner := ldapUser("racer", false)
		h.users.beforeCreate = func() { h.users.put(winner) }
		if _, err := h.svc.Login(ctx, LoginInput{Username: "racer", Password: "pw"}); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("Login = %v, want ErrForbidden", err)
		}
	})
	t.Run("jit success audit failure", func(t *testing.T) {
		h := newHarness(t)
		h.dir.passwords["fresh"] = "pw"
		h.audits.err = errors.New("audit down")
		if _, err := h.svc.Login(ctx, LoginInput{Username: "fresh", Password: "pw"}); err == nil {
			t.Fatal("Login = nil, want fail-closed error")
		}
	})
	t.Run("bad password audit failure", func(t *testing.T) {
		h := newHarness(t, localUser("ara", "correct-horse-12"))
		h.audits.err = errors.New("audit down")
		if _, err := h.svc.Login(ctx, LoginInput{Username: "ara", Password: "wrong"}); err == nil {
			t.Fatal("Login = nil, want fail-closed error")
		}
	})
	t.Run("ldap rejected audit failure", func(t *testing.T) {
		u := ldapUser("dirara", true)
		h := newHarness(t, u)
		h.dir.passwords["dirara"] = "pw"
		h.audits.err = errors.New("audit down")
		if _, err := h.svc.Login(ctx, LoginInput{Username: "dirara", Password: "wrong"}); err == nil {
			t.Fatal("Login = nil, want fail-closed error")
		}
	})
	t.Run("ldap disabled audit failure", func(t *testing.T) {
		h := newHarness(t, ldapUser("dirara", true))
		h.withoutDirectory(t)
		h.audits.err = errors.New("audit down")
		if _, err := h.svc.Login(ctx, LoginInput{Username: "dirara", Password: "x"}); err == nil {
			t.Fatal("Login = nil, want fail-closed error")
		}
	})
}

func TestChangePasswordInfraFailures(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*harness, domain.User) {
		u := localUser("ara", "old-password-12")
		return newHarness(t, u), u
	}
	run := func(h *harness, u domain.User) error {
		_, err := h.svc.ChangePassword(ctx, u.ID, "old-password-12", "brand-new-pass-1", "brand-new-pass-1", "tok")
		return err
	}
	t.Run("history read failure", func(t *testing.T) {
		h, u := setup(t)
		h.history.err = errors.New("db down")
		if err := run(h, u); err == nil {
			t.Fatal("ChangePassword = nil, want error")
		}
	})
	t.Run("hash failure", func(t *testing.T) {
		h, u := setup(t)
		svc, err := New(Deps{Users: h.users, Groups: h.groups, Resets: h.resets, History: h.history,
			Sessions: h.sessions, Audit: audit.New(h.audits, fixedClock{}),
			Hasher: fakeHasher{err: errors.New("no entropy")}, Clock: fixedClock{},
			Mailer: h.mailer})
		if err != nil {
			t.Fatal(err)
		}
		h.svc = svc
		if err := run(h, u); err == nil {
			t.Fatal("ChangePassword = nil, want error")
		}
	})
	t.Run("set hash failure", func(t *testing.T) {
		h, u := setup(t)
		h.users.setHashErr = errors.New("db down")
		if err := run(h, u); err == nil {
			t.Fatal("ChangePassword = nil, want error")
		}
	})
	t.Run("history write failure", func(t *testing.T) {
		h, u := setup(t)
		h.history.addErr = errors.New("db down")
		if err := run(h, u); err == nil {
			t.Fatal("ChangePassword = nil, want error")
		}
	})
	t.Run("revoke failure", func(t *testing.T) {
		h, u := setup(t)
		h.sessions.err = errors.New("db down")
		if err := run(h, u); err == nil {
			t.Fatal("ChangePassword = nil, want error")
		}
	})
}

func TestForgotPasswordInfraFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("lookup failure", func(t *testing.T) {
		h := newHarness(t)
		h.users.err = errors.New("db down")
		if err := h.svc.ForgotPassword(ctx, "ara", ""); err == nil {
			t.Fatal("ForgotPassword = nil, want error")
		}
	})
	t.Run("entropy failure", func(t *testing.T) {
		h := newHarness(t, localUser("ara", "old-password-12"))
		h.svc.tokenGen = func(int) ([]byte, error) { return nil, errors.New("no entropy") }
		if err := h.svc.ForgotPassword(ctx, "ara", ""); err == nil {
			t.Fatal("ForgotPassword = nil, want error")
		}
	})
	t.Run("store failure", func(t *testing.T) {
		h := newHarness(t, localUser("ara", "old-password-12"))
		h.resets.err = errors.New("db down")
		if err := h.svc.ForgotPassword(ctx, "ara", ""); err == nil {
			t.Fatal("ForgotPassword = nil, want error")
		}
	})
}

func TestResetPasswordInfraFailures(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*harness, domain.User, string) {
		u := localUser("ara", "old-password-12")
		h := newHarness(t, u)
		return h, u, issueToken(t, h, u, 'R')
	}
	t.Run("lookup failure", func(t *testing.T) {
		h, _, encoded := setup(t)
		h.resets.err = errors.New("db down")
		if err := h.svc.ResetPassword(ctx, encoded, "reset-new-pass-1", "reset-new-pass-1"); err == nil {
			t.Fatal("ResetPassword = nil, want error")
		}
	})
	t.Run("user gone", func(t *testing.T) {
		h, u, encoded := setup(t)
		delete(h.users.byID, u.ID)
		delete(h.users.byUsername, u.Username)
		if err := h.svc.ResetPassword(ctx, encoded, "reset-new-pass-1", "reset-new-pass-1"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("ResetPassword = %v, want ErrNotFound", err)
		}
	})
	t.Run("history read failure", func(t *testing.T) {
		h, _, encoded := setup(t)
		h.history.err = errors.New("db down")
		if err := h.svc.ResetPassword(ctx, encoded, "reset-new-pass-1", "reset-new-pass-1"); err == nil {
			t.Fatal("ResetPassword = nil, want error")
		}
	})
	t.Run("concurrent redemption loses", func(t *testing.T) {
		h, _, encoded := setup(t)
		// Pre-consume the token as a racing request would.
		sum := sha256.Sum256([]byte(encoded))
		tok, err := h.resets.ByHash(ctx, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := h.resets.MarkUsed(ctx, tok.ID, h.now); err != nil {
			t.Fatal(err)
		}
		err = h.svc.ResetPassword(ctx, encoded, "reset-new-pass-1", "reset-new-pass-1")
		if !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("ResetPassword = %v, want ErrValidation", err)
		}
	})
	t.Run("set hash failure", func(t *testing.T) {
		h, _, encoded := setup(t)
		h.users.setHashErr = errors.New("db down")
		if err := h.svc.ResetPassword(ctx, encoded, "reset-new-pass-1", "reset-new-pass-1"); err == nil {
			t.Fatal("ResetPassword = nil, want error")
		}
	})
	t.Run("revoke failure", func(t *testing.T) {
		h, _, encoded := setup(t)
		h.sessions.err = errors.New("db down")
		if err := h.svc.ResetPassword(ctx, encoded, "reset-new-pass-1", "reset-new-pass-1"); err == nil {
			t.Fatal("ResetPassword = nil, want error")
		}
	})
}

func TestAdminSetPasswordInfraFailures(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*harness, domain.User, domain.User) {
		admin := localUser("root", "root-password-12")
		target := localUser("ara", "old-password-12")
		h := newHarness(t, admin, target)
		h.groups.members[admin.ID] = map[string]bool{domain.AdminGroup: true}
		return h, admin, target
	}
	t.Run("admin check failure", func(t *testing.T) {
		h, admin, target := setup(t)
		h.groups.err = errors.New("db down")
		if err := h.svc.AdminSetPassword(ctx, admin.ID, target.ID, "admin-set-pass-1"); err == nil {
			t.Fatal("AdminSetPassword = nil, want error")
		}
	})
	t.Run("history read failure", func(t *testing.T) {
		h, admin, target := setup(t)
		h.history.err = errors.New("db down")
		if err := h.svc.AdminSetPassword(ctx, admin.ID, target.ID, "admin-set-pass-1"); err == nil {
			t.Fatal("AdminSetPassword = nil, want error")
		}
	})
	t.Run("set hash failure", func(t *testing.T) {
		h, admin, target := setup(t)
		h.users.setHashErr = errors.New("db down")
		if err := h.svc.AdminSetPassword(ctx, admin.ID, target.ID, "admin-set-pass-1"); err == nil {
			t.Fatal("AdminSetPassword = nil, want error")
		}
	})
	t.Run("revoke failure", func(t *testing.T) {
		h, admin, target := setup(t)
		h.sessions.err = errors.New("db down")
		if err := h.svc.AdminSetPassword(ctx, admin.ID, target.ID, "admin-set-pass-1"); err == nil {
			t.Fatal("AdminSetPassword = nil, want error")
		}
	})
}

func TestDefaultTokenGen(t *testing.T) {
	u := localUser("ara", "old-password-12")
	h := newHarness(t, u)
	svc, err := New(Deps{
		Users: h.users, Groups: h.groups, Resets: h.resets, History: h.history,
		Sessions: h.sessions, Audit: audit.New(h.audits, fixedClock{}),
		Hasher: fakeHasher{}, Mailer: h.mailer, BaseURL: "https://x.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Default crypto/rand generator: 256-bit tokens, distinct each call.
	if err := svc.ForgotPassword(context.Background(), "ara", ""); err != nil {
		t.Fatalf("ForgotPassword = %v", err)
	}
	if len(h.resets.byID) != 1 {
		t.Fatalf("tokens = %d, want 1", len(h.resets.byID))
	}
	for _, tok := range h.resets.byID {
		if len(tok.TokenHash) != sha256.Size {
			t.Errorf("token hash len = %d, want %d", len(tok.TokenHash), sha256.Size)
		}
	}
}

// ---------- ConfirmCachedBind ----------

func TestConfirmCachedBind(t *testing.T) {
	ctx := context.Background()
	u := localUser("vpn-ara", "vpn-password-1")
	admin := localUser("root", "root-password-1")
	off := localUser("zed", "zed-password-12")
	off.IsActive = false
	h := newHarness(t, u, admin, off)
	h.groups.members[admin.ID] = map[string]bool{domain.AdminGroup: true}

	got, err := h.svc.ConfirmCachedBind(ctx, u.ID, domain.MethodLDAP, "10.9.0.2")
	if err != nil {
		t.Fatalf("ConfirmCachedBind = %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("user = %v, want %v", got.ID, u.ID)
	}
	if len(h.audits.entries) != 1 || h.audits.entries[0].Result != domain.ResultSuccess ||
		h.audits.entries[0].Method != domain.MethodLDAP {
		t.Fatalf("audit = %+v, want one ldap success", h.audits.entries)
	}

	if _, err := h.svc.ConfirmCachedBind(ctx, uuid.New(), domain.MethodLDAP, "10.9.0.2"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("unknown user = %v, want unauthorized", err)
	}
	if _, err := h.svc.ConfirmCachedBind(ctx, off.ID, domain.MethodLDAP, "10.9.0.2"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("disabled user = %v, want forbidden", err)
	}
	if _, err := h.svc.ConfirmCachedBind(ctx, admin.ID, domain.MethodLDAP, "10.9.0.2"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("admin = %v, want ErrMFARequired", err)
	}
	if _, err := h.svc.ConfirmCachedBind(ctx, u.ID, "password", "10.9.0.2"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad method = %v, want validation", err)
	}
	for _, e := range h.audits.entries[1:] {
		if e.Result != domain.ResultFailure {
			t.Errorf("audit entry = %+v, want failure", e)
		}
	}
	if len(h.audits.entries) != 4 {
		t.Errorf("audit entries = %d, want 4 (bad method never audits)", len(h.audits.entries))
	}
}

// ---------- LoginLegacy ----------

func TestLoginLegacyLocalSuccessAuditsProtocolMethod(t *testing.T) {
	u := localUser("vpn-ara", "vpn-password-1")
	h := newHarness(t, u)
	appID := uuid.New()

	got, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "vpn-ara", Password: "vpn-password-1", IP: "10.9.0.2",
		Method: domain.MethodRADIUS, ApplicationID: &appID,
	})
	if err != nil {
		t.Fatalf("LoginLegacy = %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("user = %v, want %v", got.ID, u.ID)
	}
	a := lastAudit(h)
	if a.Method != domain.MethodRADIUS || a.Result != domain.ResultSuccess {
		t.Errorf("audit = %s/%s, want radius/success", a.Method, a.Result)
	}
	if a.ApplicationID == nil || *a.ApplicationID != appID {
		t.Errorf("audit app = %v, want %v", a.ApplicationID, appID)
	}
	if a.ActorUserID == nil || *a.ActorUserID != u.ID {
		t.Errorf("audit actor = %v, want %v", a.ActorUserID, u.ID)
	}
	if a.IP != "10.9.0.2" {
		t.Errorf("audit ip = %q", a.IP)
	}
}

func TestLoginLegacyLDAPUserViaDirectory(t *testing.T) {
	u := ldapUser("dir-ara", true)
	h := newHarness(t, u)
	h.dir.passwords["dir-ara"] = "dir-pass-0001"

	got, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "dir-ara", Password: "dir-pass-0001", IP: "10.9.0.3",
		Method: domain.MethodLDAP,
	})
	if err != nil {
		t.Fatalf("LoginLegacy = %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("user = %v, want %v", got.ID, u.ID)
	}
	// The protocol method (ldap) wins over the backend (directory) in
	// the audit log; the LDAP tree is global so no app is attached.
	a := lastAudit(h)
	if a.Method != domain.MethodLDAP || a.Result != domain.ResultSuccess {
		t.Errorf("audit = %s/%s, want ldap/success", a.Method, a.Result)
	}
	if a.ApplicationID != nil {
		t.Errorf("audit app = %v, want nil", a.ApplicationID)
	}
}

func TestLoginLegacyDeniesAdminsWhenMFARequired(t *testing.T) {
	admin := localUser("root", "root-password-1")
	plain := localUser("ara", "ara-password-12")
	h := newHarness(t, admin, plain)
	h.groups.members[admin.ID] = map[string]bool{domain.AdminGroup: true}

	_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "root", Password: "root-password-1", IP: "10.9.0.4",
		Method: domain.MethodLDAP,
	})
	if !errors.Is(err, ErrMFARequired) {
		t.Fatalf("admin LoginLegacy = %v, want ErrMFARequired", err)
	}
	a := lastAudit(h)
	if a.Method != domain.MethodLDAP || a.Result != domain.ResultFailure {
		t.Errorf("audit = %s/%s, want ldap/failure", a.Method, a.Result)
	}
	if a.Detail["reason"] != "mfa required" {
		t.Errorf("audit reason = %v, want 'mfa required'", a.Detail["reason"])
	}
	// A correct password still verifies for non-admins on the same box.
	if _, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "ara", Password: "ara-password-12", Method: domain.MethodLDAP,
	}); err != nil {
		t.Errorf("non-admin LoginLegacy = %v, want success", err)
	}
}

func TestLoginLegacyDeniesAdminEvenWhenDirectoryVerifies(t *testing.T) {
	admin := ldapUser("dir-root", true)
	h := newHarness(t, admin)
	h.dir.passwords["dir-root"] = "dir-pass-0002"
	h.groups.members[admin.ID] = map[string]bool{domain.AdminGroup: true}

	_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "dir-root", Password: "dir-pass-0002", Method: domain.MethodRADIUS,
	})
	if !errors.Is(err, ErrMFARequired) {
		t.Fatalf("LDAP admin LoginLegacy = %v, want ErrMFARequired", err)
	}
}

func TestLoginLegacyCredentialFailures(t *testing.T) {
	u := localUser("ara", "ara-password-12")
	off := localUser("off", "off-password-12")
	off.IsActive = false
	h := newHarness(t, u, off)
	h.withoutDirectory(t)

	cases := []struct {
		name     string
		username string
		password string
		reason   string
	}{
		{"bad password", "ara", "wrong-password", "bad password"},
		{"unknown user", "ghost", "whatever-00000", "unknown user"},
		{"disabled", "off", "off-password-12", "account disabled"},
		{"missing", "", "", "missing credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.audits.entries)
			_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
				Username: tc.username, Password: tc.password, Method: domain.MethodRADIUS,
			})
			if tc.name == "disabled" {
				if !errors.Is(err, domain.ErrForbidden) {
					t.Fatalf("err = %v, want ErrForbidden", err)
				}
			} else if !errors.Is(err, domain.ErrUnauthorized) {
				t.Fatalf("err = %v, want ErrUnauthorized", err)
			}
			if len(h.audits.entries) != before+1 {
				t.Fatalf("audits = %d, want one new entry", len(h.audits.entries)-before)
			}
			a := lastAudit(h)
			if a.Method != domain.MethodRADIUS || a.Result != domain.ResultFailure {
				t.Errorf("audit = %s/%s, want radius/failure", a.Method, a.Result)
			}
			if a.Detail["reason"] != tc.reason {
				t.Errorf("reason = %v, want %q", a.Detail["reason"], tc.reason)
			}
		})
	}
}

func TestLoginLegacyDirectoryOutageIsExplicit(t *testing.T) {
	u := ldapUser("dir-ara", true)
	h := newHarness(t, u)
	h.dir.err = errors.New("connection refused")

	_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "dir-ara", Password: "whatever-00000", Method: domain.MethodLDAP,
	})
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("err = %v, want ErrDirectoryUnavailable", err)
	}
	a := lastAudit(h)
	if a.Method != domain.MethodLDAP || a.Detail["reason"] != "directory unavailable" {
		t.Errorf("audit = %+v, want ldap/directory-unavailable", a)
	}
}

func TestLoginLegacyRejectsBadMethod(t *testing.T) {
	h := newHarness(t)
	for _, method := range []string{"", "password", "oidc", "saml"} {
		_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
			Username: "ara", Password: "x", Method: method,
		})
		if !errors.Is(err, domain.ErrValidation) {
			t.Errorf("method %q: err = %v, want ErrValidation", method, err)
		}
	}
	if len(h.audits.entries) != 0 {
		t.Errorf("audits = %d, want 0 (caller bug, not a login attempt)", len(h.audits.entries))
	}
}

func TestLoginLegacyInfraFailures(t *testing.T) {
	u := localUser("ara", "ara-password-12")

	t.Run("user lookup error skips audit", func(t *testing.T) {
		h := newHarness(t, u)
		h.users.err = errors.New("db down")
		_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
			Username: "ara", Password: "ara-password-12", Method: domain.MethodLDAP,
		})
		if err == nil || errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("err = %v, want wrapped infra error", err)
		}
		if len(h.audits.entries) != 0 {
			t.Errorf("audits = %d, want 0", len(h.audits.entries))
		}
	})

	t.Run("mfa policy check error", func(t *testing.T) {
		h := newHarness(t, u)
		h.groups.err = errors.New("db down")
		_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
			Username: "ara", Password: "ara-password-12", Method: domain.MethodLDAP,
		})
		if err == nil || !strings.Contains(err.Error(), "mfa policy check") {
			t.Fatalf("err = %v, want mfa policy check failure", err)
		}
	})

	t.Run("audit failure fails closed", func(t *testing.T) {
		h := newHarness(t, u)
		h.audits.err = errors.New("audit down")
		_, err := h.svc.LoginLegacy(context.Background(), LegacyLoginInput{
			Username: "ara", Password: "ara-password-12", Method: domain.MethodLDAP,
		})
		if err == nil {
			t.Fatal("LoginLegacy = nil, want audit fail-closed")
		}
	})
}

type stubMFAPolicy struct {
	required map[uuid.UUID]bool
	err      error
}

func (s stubMFAPolicy) RequiredForApp(_ context.Context, _ uuid.UUID, appID uuid.UUID) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.required[appID], nil
}

func TestLoginLegacyPerAppMFAPolicy(t *testing.T) {
	u := localUser("ara", "ara-password-12")
	h := newHarness(t, u)
	mfaApp := uuid.New()
	plainApp := uuid.New()
	svc, err := New(Deps{
		Users: h.users, Groups: h.groups, Resets: h.resets, History: h.history,
		Sessions: h.sessions, Audit: audit.New(h.audits, fixedClock{now: h.now}),
		Hasher: fakeHasher{}, Clock: fixedClock{now: h.now}, Mailer: h.mailer,
		Directory: h.dir, BaseURL: "https://idp.example.com",
		MFAPolicy: stubMFAPolicy{required: map[uuid.UUID]bool{mfaApp: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Regular user on an MFA-required app is denied with the sentinel.
	_, err = svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "ara", Password: "ara-password-12", Method: domain.MethodRADIUS,
		ApplicationID: &mfaApp,
	})
	if !errors.Is(err, ErrMFARequired) {
		t.Fatalf("MFA-app LoginLegacy = %v, want ErrMFARequired", err)
	}
	// Same user on a plain app passes.
	if _, err := svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "ara", Password: "ara-password-12", Method: domain.MethodRADIUS,
		ApplicationID: &plainApp,
	}); err != nil {
		t.Fatalf("plain-app LoginLegacy = %v, want success", err)
	}
	// Policy errors surface instead of silently allowing.
	svc.mfa = stubMFAPolicy{err: errors.New("policy down")}
	if _, err := svc.LoginLegacy(context.Background(), LegacyLoginInput{
		Username: "ara", Password: "ara-password-12", Method: domain.MethodRADIUS,
		ApplicationID: &plainApp,
	}); err == nil {
		t.Fatal("policy error must fail the bind")
	}
}
