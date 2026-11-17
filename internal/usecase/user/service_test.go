package user

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

type fakeUsers struct {
	byID       map[uuid.UUID]domain.User
	byUsername map[string]domain.User
	err        error
	createErr  error
	updateErr  error
	setErr     error
	listErr    error
	byIDErr    map[uuid.UUID]error
	// usernameErr fails ByUsername only (sync re-read path).
	usernameErr error
	// afterCreate runs at the end of a successful Create (race hooks).
	afterCreate func()
	// listFailOnCall fails the Nth List call (1-based, 0 = never).
	listFailOnCall int
	listCalls      int
}

func newFakeUsers(us ...domain.User) *fakeUsers {
	f := &fakeUsers{byID: map[uuid.UUID]domain.User{}, byUsername: map[string]domain.User{}, byIDErr: map[uuid.UUID]error{}}
	for _, u := range us {
		f.put(u)
	}
	return f
}

func (f *fakeUsers) put(u domain.User) {
	f.byID[u.ID] = u
	f.byUsername[u.Username] = u
}

func (f *fakeUsers) Create(_ context.Context, u domain.User) (domain.User, error) {
	if f.err != nil {
		return domain.User{}, f.err
	}
	if f.createErr != nil {
		return domain.User{}, f.createErr
	}
	if _, ok := f.byUsername[u.Username]; ok {
		return domain.User{}, domain.ErrConflict
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	f.put(u)
	if f.afterCreate != nil {
		f.afterCreate()
	}
	return u, nil
}

func (f *fakeUsers) ByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	if e, ok := f.byIDErr[id]; ok {
		return domain.User{}, e
	}
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
	if f.usernameErr != nil {
		return domain.User{}, f.usernameErr
	}
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

func (f *fakeUsers) ByEmail(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}

func (f *fakeUsers) List(_ context.Context, flt domain.UserFilter) ([]domain.User, int, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	if f.listFailOnCall > 0 && f.listCalls == f.listFailOnCall {
		return nil, 0, errors.New("db down")
	}
	var out []domain.User
	for _, u := range f.byID {
		if flt.Source != "" && u.Source != flt.Source {
			continue
		}
		out = append(out, u)
	}
	// Honor offset/limit like the repository.
	if flt.Offset > len(out) {
		return nil, len(out), nil
	}
	out = out[flt.Offset:]
	if flt.Limit > 0 && flt.Limit < len(out) {
		out = out[:flt.Limit]
	}
	return out, len(f.byID), nil
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
	if f.updateErr != nil {
		return domain.User{}, f.updateErr
	}
	if _, ok := f.byID[u.ID]; !ok {
		return domain.User{}, domain.ErrNotFound
	}
	f.put(u)
	return u, nil
}

func (f *fakeUsers) SetActive(_ context.Context, id uuid.UUID, active bool) error {
	if f.setErr != nil {
		return f.setErr
	}
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
	byID         map[uuid.UUID]domain.Group
	byName       map[string]domain.Group
	members      map[uuid.UUID]map[uuid.UUID]bool // group -> users
	err          error
	addErr       error
	removeErr    error
	byNameErr    error
	memberIDsErr error
	createErr    error
	// beforeCreate runs before the conflict check (race hooks).
	beforeCreate func()
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
	if f.err != nil {
		return domain.Group{}, f.err
	}
	if f.createErr != nil {
		return domain.Group{}, f.createErr
	}
	if f.beforeCreate != nil {
		f.beforeCreate()
	}
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
	if f.err != nil {
		return domain.Group{}, f.err
	}
	g, ok := f.byID[id]
	if !ok {
		return domain.Group{}, domain.ErrNotFound
	}
	return g, nil
}

func (f *fakeGroups) ByName(_ context.Context, name string) (domain.Group, error) {
	if f.byNameErr != nil {
		return domain.Group{}, f.byNameErr
	}
	if f.err != nil {
		return domain.Group{}, f.err
	}
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
	return out, len(out), f.err
}

func (f *fakeGroups) All(_ context.Context) ([]domain.Group, error) {
	var out []domain.Group
	for _, g := range f.byID {
		out = append(out, g)
	}
	return out, f.err
}

func (f *fakeGroups) Delete(_ context.Context, id uuid.UUID) error {
	if f.err != nil {
		return f.err
	}
	g, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	delete(f.byID, id)
	delete(f.byName, g.Name)
	delete(f.members, id)
	return nil
}

func (f *fakeGroups) AddMember(_ context.Context, userID, groupID uuid.UUID) error {
	if f.addErr != nil {
		return f.addErr
	}
	if f.err != nil {
		return f.err
	}
	if f.members[groupID] == nil {
		f.members[groupID] = map[uuid.UUID]bool{}
	}
	f.members[groupID][userID] = true
	return nil
}

func (f *fakeGroups) RemoveMember(_ context.Context, userID, groupID uuid.UUID) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.members[groupID], userID)
	return nil
}

func (f *fakeGroups) MemberIDs(_ context.Context, groupID uuid.UUID) ([]uuid.UUID, error) {
	if f.memberIDsErr != nil {
		return nil, f.memberIDsErr
	}
	if f.err != nil {
		return nil, f.err
	}
	var out []uuid.UUID
	for id := range f.members[groupID] {
		out = append(out, id)
	}
	return out, nil
}

func (f *fakeGroups) MemberUsernamesByGroup(_ context.Context) (map[uuid.UUID][]string, error) {
	if f.memberIDsErr != nil {
		return nil, f.memberIDsErr
	}
	if f.err != nil {
		return nil, f.err
	}
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
	if f.err != nil {
		return false, f.err
	}
	g, ok := f.byName[groupName]
	if !ok {
		return false, nil
	}
	return f.members[g.ID][userID], nil
}

type fakeAttrs struct {
	defs    map[string]domain.UserAttrDef
	byID    map[uuid.UUID]domain.UserAttrDef
	values  map[uuid.UUID]map[uuid.UUID][]string
	sources map[uuid.UUID]map[uuid.UUID]domain.UserAttrSource
	err     error
}

func newFakeAttrs(defs ...domain.UserAttrDef) *fakeAttrs {
	f := &fakeAttrs{
		defs: map[string]domain.UserAttrDef{}, byID: map[uuid.UUID]domain.UserAttrDef{},
		values:  map[uuid.UUID]map[uuid.UUID][]string{},
		sources: map[uuid.UUID]map[uuid.UUID]domain.UserAttrSource{},
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
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (f *fakeAttrs) DeleteDef(_ context.Context, key string) error {
	if f.err != nil {
		return f.err
	}
	d, ok := f.defs[key]
	if !ok {
		return domain.ErrNotFound
	}
	delete(f.defs, key)
	delete(f.byID, d.ID)
	for uid := range f.values {
		delete(f.values[uid], d.ID)
		delete(f.sources[uid], d.ID)
	}
	return nil
}

func (f *fakeAttrs) SetValues(_ context.Context, userID uuid.UUID, values map[uuid.UUID][]string, source domain.UserAttrSource) error {
	if f.err != nil {
		return f.err
	}
	if f.values[userID] == nil {
		f.values[userID] = map[uuid.UUID][]string{}
		f.sources[userID] = map[uuid.UUID]domain.UserAttrSource{}
	}
	for id, vals := range values {
		if len(vals) == 0 {
			delete(f.values[userID], id)
			delete(f.sources[userID], id)
			continue
		}
		f.values[userID][id] = append([]string(nil), vals...)
		f.sources[userID][id] = source
	}
	return nil
}

func (f *fakeAttrs) ApplyUpstreamValues(_ context.Context, userID uuid.UUID, values map[uuid.UUID][]string) error {
	if f.err != nil {
		return f.err
	}
	if f.values[userID] == nil {
		f.values[userID] = map[uuid.UUID][]string{}
		f.sources[userID] = map[uuid.UUID]domain.UserAttrSource{}
	}
	for id, src := range f.sources[userID] {
		if src == domain.UserAttrLDAP {
			if _, keep := values[id]; !keep {
				delete(f.values[userID], id)
				delete(f.sources[userID], id)
			}
		}
	}
	for id, vals := range values {
		if len(vals) == 0 {
			delete(f.values[userID], id)
			delete(f.sources[userID], id)
			continue
		}
		f.values[userID][id] = append([]string(nil), vals...)
		f.sources[userID][id] = domain.UserAttrLDAP
	}
	return nil
}

func (f *fakeAttrs) ValuesOfUser(_ context.Context, userID uuid.UUID) (map[string][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string][]string{}
	for id, vals := range f.values[userID] {
		if d, ok := f.byID[id]; ok {
			out[d.Key] = append([]string(nil), vals...)
		}
	}
	return out, nil
}

func (f *fakeAttrs) ValuesForUsers(_ context.Context, userIDs []uuid.UUID) (map[uuid.UUID]map[string][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[uuid.UUID]map[string][]string{}
	for _, uid := range userIDs {
		if vals, ok := f.values[uid]; ok {
			m := map[string][]string{}
			for id, v := range vals {
				if d, ok := f.byID[id]; ok {
					m[d.Key] = append([]string(nil), v...)
				}
			}
			out[uid] = m
		}
	}
	return out, nil
}

type fakeSessions struct {
	revokedAll []uuid.UUID
	err        error
}

func (f *fakeSessions) Register(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (f *fakeSessions) Unregister(_ context.Context, _ string) error            { return nil }
func (f *fakeSessions) RevokeOthers(_ context.Context, _ uuid.UUID, _ string) (int64, error) {
	return 0, nil
}
func (f *fakeSessions) RevokeAll(_ context.Context, userID uuid.UUID) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.revokedAll = append(f.revokedAll, userID)
	return 1, nil
}

type fakeAuditStore struct {
	entries []domain.AuditEntry
}

func (f *fakeAuditStore) Append(_ context.Context, e domain.AuditEntry) error {
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
func (fakeHasher) Verify(password string, hash []byte) bool { return string(hash) == "hash:"+password }

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type harness struct {
	users    *fakeUsers
	groups   *fakeGroups
	sessions *fakeSessions
	audits   *fakeAuditStore
	svc      *Service
	admin    domain.Group
}

func newHarness(t *testing.T, users ...domain.User) *harness {
	t.Helper()
	admin := domain.Group{ID: uuid.New(), Name: domain.AdminGroup}
	h := &harness{
		users:    newFakeUsers(users...),
		groups:   newFakeGroups(admin),
		sessions: &fakeSessions{},
		audits:   &fakeAuditStore{},
		admin:    admin,
	}
	svc, err := New(Deps{
		Users: h.users, Groups: h.groups, Sessions: h.sessions,
		Audit: audit.New(h.audits, fixedClock{now: time.Now()}), Hasher: fakeHasher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h
}

func localUser(username string) domain.User {
	return domain.User{ID: uuid.New(), Username: username, Email: username + "@example.com",
		PasswordHash: []byte("hash:x"), Source: domain.SourceLocal, IsActive: true}
}

func ldapUser(username string) domain.User {
	return domain.User{ID: uuid.New(), Username: username, Email: username + "@dir.example.com",
		Source: domain.SourceLDAP, ExternalDN: "uid=" + username + ",ou=users,dc=example,dc=com", IsActive: true}
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New(empty) = nil, want error")
	}
}

func TestCreateUser(t *testing.T) {
	h := newHarness(t)
	actor := uuid.New()
	u, err := h.svc.CreateUser(context.Background(), actor, NewUser{Username: "ara", Email: "ara@example.com", Password: "long-password-1"})
	if err != nil {
		t.Fatalf("CreateUser = %v", err)
	}
	if u.Source != domain.SourceLocal || !u.IsActive {
		t.Errorf("user = %+v", u)
	}
	if len(h.audits.entries) != 1 || h.audits.entries[0].Detail["action"] != audit.ActionUserCreate {
		t.Errorf("audit = %+v", h.audits.entries)
	}
	// Pre-provisioned LDAP user.
	lu, err := h.svc.CreateUser(context.Background(), actor, NewUser{Username: "dirara", Source: domain.SourceLDAP, ExternalDN: "uid=dirara,ou=users,dc=x"})
	if err != nil {
		t.Fatalf("CreateUser(ldap) = %v", err)
	}
	if lu.Source != domain.SourceLDAP || len(lu.PasswordHash) != 0 {
		t.Errorf("ldap user = %+v", lu)
	}
}

func TestCreateUserFailures(t *testing.T) {
	h := newHarness(t)
	actor := uuid.New()
	for name, in := range map[string]NewUser{
		"empty username":   {Password: "long-password-1"},
		"short password":   {Username: "ara", Password: "short"},
		"ldap with passwd": {Username: "d", Source: domain.SourceLDAP, Password: "long-password-1"},
	} {
		if _, err := h.svc.CreateUser(context.Background(), actor, in); err == nil {
			t.Errorf("%s: CreateUser = nil, want error", name)
		}
	}
	if _, err := h.svc.CreateUser(context.Background(), actor, NewUser{Username: "ara", Password: "long-password-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.CreateUser(context.Background(), actor, NewUser{Username: "ara", Password: "long-password-1"}); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("duplicate = %v, want ErrConflict", err)
	}
}

func TestCreateUserHashFailure(t *testing.T) {
	h := newHarness(t)
	svc, err := New(Deps{Users: h.users, Groups: h.groups, Sessions: h.sessions,
		Audit: audit.New(h.audits, fixedClock{}), Hasher: fakeHasher{err: errors.New("no entropy")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(context.Background(), uuid.New(), NewUser{Username: "ara", Password: "long-password-1"}); err == nil {
		t.Fatal("CreateUser = nil, want error")
	}
}

func TestUpdateProfile(t *testing.T) {
	u := localUser("ara")
	h := newHarness(t, u)
	got, err := h.svc.UpdateProfile(context.Background(), u.ID, "Ara E", "ara2@example.com", "/uploads/avatar/x.webp")
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Ara E" || got.Email != "ara2@example.com" || got.AvatarURL == "" {
		t.Errorf("profile = %+v", got)
	}
	if _, err := h.svc.UpdateProfile(context.Background(), uuid.New(), "x", "x@y.z", ""); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown = %v, want ErrNotFound", err)
	}
}

func TestSetActive(t *testing.T) {
	u := localUser("ara")
	h := newHarness(t, u)
	ctx := context.Background()
	actor := uuid.New()
	if err := h.svc.SetActive(ctx, actor, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.users.ByID(ctx, u.ID); got.IsActive {
		t.Error("user still active")
	}
	if len(h.sessions.revokedAll) != 1 {
		t.Errorf("revoked = %v, want one RevokeAll", h.sessions.revokedAll)
	}
	if h.audits.entries[0].Detail["action"] != audit.ActionUserDeactivate {
		t.Errorf("audit = %+v", h.audits.entries)
	}
	if err := h.svc.SetActive(ctx, actor, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.SetActive(ctx, actor, uuid.New(), false); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown = %v, want ErrNotFound", err)
	}
}

func TestSetActiveLastAdminRefused(t *testing.T) {
	root := localUser("root")
	other := localUser("other")
	h := newHarness(t, root, other)
	ctx := context.Background()
	_ = h.groups.AddMember(ctx, root.ID, h.admin.ID)
	_ = h.groups.AddMember(ctx, other.ID, h.admin.ID)

	// Other admin is active: deactivating root is allowed.
	if err := h.svc.SetActive(ctx, root.ID, root.ID, false); err != nil {
		t.Fatalf("SetActive with fellow admin = %v", err)
	}
	// Now other is the last active admin: refused.
	if err := h.svc.SetActive(ctx, root.ID, other.ID, false); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("SetActive last admin = %v, want ErrForbidden", err)
	}
}

func TestSetActiveGuardErrors(t *testing.T) {
	u := localUser("ara")
	h := newHarness(t, u)
	ctx := context.Background()
	_ = h.groups.AddMember(ctx, u.ID, h.admin.ID)
	h.groups.err = errors.New("db down")
	if err := h.svc.SetActive(ctx, uuid.New(), u.ID, false); err == nil {
		t.Fatal("SetActive = nil, want error")
	}

	h2 := newHarness(t, u)
	fellow := localUser("fellow")
	h2.users.put(fellow)
	_ = h2.groups.AddMember(ctx, u.ID, h2.admin.ID)
	_ = h2.groups.AddMember(ctx, fellow.ID, h2.admin.ID)
	h2.users.setErr = errors.New("db down")
	if err := h2.svc.SetActive(ctx, uuid.New(), u.ID, false); err == nil {
		t.Fatal("SetActive = nil, want error")
	}

	h3 := newHarness(t, u)
	h3.sessions.err = errors.New("db down")
	if err := h3.svc.SetActive(ctx, uuid.New(), u.ID, false); err == nil {
		t.Fatal("SetActive = nil, want error")
	}

	// Admin-group lookup failure inside the last-admin guard.
	h4 := newHarness(t, u)
	_ = h4.groups.AddMember(ctx, u.ID, h4.admin.ID)
	h4.groups.byNameErr = errors.New("db down")
	if err := h4.svc.SetActive(ctx, uuid.New(), u.ID, false); err == nil {
		t.Fatal("SetActive = nil, want error")
	}

	// Member listing failure inside the last-admin guard.
	h5 := newHarness(t, u)
	_ = h5.groups.AddMember(ctx, u.ID, h5.admin.ID)
	h5.groups.memberIDsErr = errors.New("db down")
	if err := h5.svc.SetActive(ctx, uuid.New(), u.ID, false); err == nil {
		t.Fatal("SetActive = nil, want error")
	}

	// A fellow member that fails to load counts as inactive (fail-safe:
	// deactivation is refused rather than risking lockout).
	h6 := newHarness(t, u)
	mate := localUser("mate")
	h6.users.put(mate)
	_ = h6.groups.AddMember(ctx, u.ID, h6.admin.ID)
	_ = h6.groups.AddMember(ctx, mate.ID, h6.admin.ID)
	h6.users.byIDErr[mate.ID] = errors.New("row gone")
	if err := h6.svc.SetActive(ctx, uuid.New(), u.ID, false); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("SetActive = %v, want ErrForbidden", err)
	}
}

func TestListAndGet(t *testing.T) {
	u := localUser("ara")
	h := newHarness(t, u)
	if _, _, err := h.svc.ListUsers(context.Background(), domain.UserFilter{Query: "ara"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.GetUser(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.GetUser(context.Background(), uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("GetUser = %v, want ErrNotFound", err)
	}
}

func TestGroups(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	g, err := h.svc.CreateGroup(ctx, "it", "IT dept")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.CreateGroup(ctx, "  ", ""); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := h.svc.CreateGroup(ctx, domain.AdminGroup, ""); err == nil {
		t.Error("reserved name accepted")
	}
	if _, _, err := h.svc.ListGroups(ctx, 10, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.DeleteGroup(ctx, h.admin.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("DeleteGroup(ih_admin) = %v, want ErrForbidden", err)
	}
	if err := h.svc.DeleteGroup(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("DeleteGroup(unknown) = %v, want ErrNotFound", err)
	}
}

func TestMembers(t *testing.T) {
	root := localUser("root")
	ara := localUser("ara")
	h := newHarness(t, root, ara)
	ctx := context.Background()
	it, err := h.svc.CreateGroup(ctx, "it", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.AddMember(ctx, root.ID, ara.ID, it.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.AddMember(ctx, root.ID, uuid.New(), it.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("AddMember unknown user = %v", err)
	}
	if err := h.svc.AddMember(ctx, root.ID, ara.ID, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("AddMember unknown group = %v", err)
	}
	if err := h.svc.RemoveMember(ctx, root.ID, ara.ID, it.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.RemoveMember(ctx, root.ID, ara.ID, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("RemoveMember unknown group = %v", err)
	}
	// Store failures propagate.
	h.groups.addErr = errors.New("db down")
	if err := h.svc.AddMember(ctx, root.ID, ara.ID, it.ID); err == nil {
		t.Error("AddMember = nil, want error")
	}
	h.groups.addErr = nil
	h.groups.removeErr = errors.New("db down")
	if err := h.svc.RemoveMember(ctx, root.ID, ara.ID, it.ID); err == nil {
		t.Error("RemoveMember = nil, want error")
	}
	h.groups.removeErr = nil
	h.groups.memberIDsErr = errors.New("db down")
	_ = h.groups.AddMember(ctx, root.ID, h.admin.ID)
	if err := h.svc.RemoveMember(ctx, ara.ID, root.ID, h.admin.ID); err == nil {
		t.Error("RemoveMember(ih_admin) = nil, want error")
	}
}

func TestRemoveMemberAdminGuards(t *testing.T) {
	root := localUser("root")
	ara := localUser("ara")
	h := newHarness(t, root, ara)
	ctx := context.Background()
	_ = h.groups.AddMember(ctx, root.ID, h.admin.ID)

	// Self-removal refused.
	if err := h.svc.RemoveMember(ctx, root.ID, root.ID, h.admin.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self-remove = %v, want ErrForbidden", err)
	}
	// Last-member removal refused (actor differs so only the last-guard fires).
	if err := h.svc.RemoveMember(ctx, ara.ID, root.ID, h.admin.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("last-remove = %v, want ErrForbidden", err)
	}
	// Non-member removal is a no-op success (actor differs from target).
	if err := h.svc.RemoveMember(ctx, root.ID, ara.ID, h.admin.ID); err != nil {
		t.Fatalf("non-member remove = %v", err)
	}
	// With two members, removing the other works.
	_ = h.groups.AddMember(ctx, ara.ID, h.admin.ID)
	if err := h.svc.RemoveMember(ctx, ara.ID, root.ID, h.admin.ID); err != nil {
		t.Fatalf("remove fellow admin = %v", err)
	}
}

// ---------- sync ----------

const adminDN = "cn=admins,ou=groups,dc=example,dc=com"

func TestSyncCreatesUpdatesDisables(t *testing.T) {
	stale := ldapUser("stale")
	local := localUser("ara")
	h := newHarness(t, stale, local)
	ctx := context.Background()
	snap := domain.DirectorySnapshot{
		Users: []domain.LDAPUser{
			{Username: "fresh", Email: "fresh@dir.example.com", DisplayName: "Fresh", DN: "uid=fresh,ou=users,dc=example,dc=com"},
			{Username: "ara", Email: "ara@dir.example.com", DisplayName: "Ara Dir", DN: "uid=ara,ou=users,dc=example,dc=com"},
			{Username: ""}, // skipped
		},
	}
	rep, err := h.svc.SyncFromDirectory(ctx, snap, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Created != 1 || len(rep.Conflicts) != 1 || rep.Conflicts[0] != "ara" || rep.Disabled != 1 {
		t.Errorf("report = %+v", rep)
	}
	// Conflict never overwrites the local row.
	if got, _ := h.users.ByUsername(ctx, "ara"); got.Source != domain.SourceLocal || got.Email != "ara@example.com" {
		t.Errorf("local row overwritten: %+v", got)
	}
	if got, _ := h.users.ByUsername(ctx, "stale"); got.IsActive {
		t.Error("stale ldap user still active")
	}
	if got, _ := h.users.ByUsername(ctx, "fresh"); !got.IsActive || got.Source != domain.SourceLDAP {
		t.Errorf("fresh = %+v", got)
	}
}

func TestSyncUpdatesAndReenables(t *testing.T) {
	u := ldapUser("dirara")
	u.IsActive = false
	u.DisplayName = "Old"
	h := newHarness(t, u)
	snap := domain.DirectorySnapshot{Users: []domain.LDAPUser{
		{Username: "dirara", Email: "new@dir.example.com", DisplayName: "New", DN: u.ExternalDN},
	}}
	rep, err := h.svc.SyncFromDirectory(context.Background(), snap, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Updated != 1 || rep.Reenabled != 1 {
		t.Errorf("report = %+v", rep)
	}
	got, _ := h.users.ByUsername(context.Background(), "dirara")
	if !got.IsActive || got.DisplayName != "New" || got.Email != "new@dir.example.com" {
		t.Errorf("updated = %+v", got)
	}
}

func TestSyncAdminMapping(t *testing.T) {
	u := ldapUser("dirara")
	h := newHarness(t, u)
	ctx := context.Background()
	snap := domain.DirectorySnapshot{Users: []domain.LDAPUser{
		{Username: "dirara", DN: u.ExternalDN, MemberOf: []string{"CN=ADMINS,ou=groups,dc=example,dc=com"}},
	}}
	rep, err := h.svc.SyncFromDirectory(ctx, snap, adminDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.AdminAdded) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if member, _ := h.groups.IsMember(ctx, u.ID, domain.AdminGroup); !member {
		t.Error("admin mapping not applied")
	}
	// Second sync is idempotent (already a member).
	rep, err = h.svc.SyncFromDirectory(ctx, snap, adminDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.AdminAdded) != 0 {
		t.Errorf("second sync added %+v, want none", rep.AdminAdded)
	}
}

func TestSyncAdminMappingOff(t *testing.T) {
	u := ldapUser("dirara")
	h := newHarness(t, u)
	snap := domain.DirectorySnapshot{Users: []domain.LDAPUser{
		{Username: "dirara", DN: u.ExternalDN, MemberOf: []string{adminDN}},
		{Username: "plain", DN: "uid=plain,ou=users,dc=example,dc=com"},
	}}
	// Empty admin DN disables mapping; a user without memberOf never maps.
	rep, err := h.svc.SyncFromDirectory(context.Background(), snap, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.AdminAdded) != 0 {
		t.Errorf("report = %+v", rep)
	}
	rep, err = h.svc.SyncFromDirectory(context.Background(), snap, adminDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.AdminAdded) != 1 || rep.AdminAdded[0] != "dirara" {
		t.Errorf("report = %+v", rep)
	}
}

func TestSyncGroups(t *testing.T) {
	a := ldapUser("anna")
	b := ldapUser("bob")
	h := newHarness(t, a, b)
	ctx := context.Background()
	it, _ := h.groups.Create(ctx, domain.Group{Name: "it"})
	_ = h.groups.AddMember(ctx, b.ID, it.ID) // bob will be removed (not in dir listing)

	snap := domain.DirectorySnapshot{
		Users: []domain.LDAPUser{
			{Username: "anna", DN: a.ExternalDN},
			{Username: "bob", DN: b.ExternalDN},
		},
		Groups: []domain.LDAPGroup{
			{Name: "it", DN: "cn=it,ou=groups,dc=example,dc=com", Members: []string{a.ExternalDN, "uid=ghost,ou=users,dc=example,dc=com"}},
			{Name: "newteam", DN: "cn=newteam,ou=groups,dc=example,dc=com", Members: []string{b.ExternalDN}},
			{Name: domain.AdminGroup, Members: []string{a.ExternalDN}}, // never touched
			{Name: ""}, // skipped
		},
	}
	if _, err := h.svc.SyncFromDirectory(ctx, snap, ""); err != nil {
		t.Fatal(err)
	}
	members, _ := h.groups.MemberIDs(ctx, it.ID)
	if len(members) != 1 || members[0] != a.ID {
		t.Errorf("it members = %v, want [anna]", members)
	}
	nt, err := h.groups.ByName(ctx, "newteam")
	if err != nil {
		t.Fatalf("newteam missing: %v", err)
	}
	nm, _ := h.groups.MemberIDs(ctx, nt.ID)
	if len(nm) != 1 || nm[0] != b.ID {
		t.Errorf("newteam members = %v, want [bob]", nm)
	}
	if member, _ := h.groups.IsMember(ctx, a.ID, domain.AdminGroup); member {
		t.Error("directory group must never grant ih_admin")
	}
}

func TestSyncErrorPaths(t *testing.T) {
	mkSnap := func() domain.DirectorySnapshot {
		return domain.DirectorySnapshot{Users: []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"}}}
	}
	t.Run("lookup failure", func(t *testing.T) {
		h := newHarness(t)
		h.users.err = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), mkSnap(), ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("create failure", func(t *testing.T) {
		h := newHarness(t)
		h.users.createErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), mkSnap(), ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("create conflict recorded", func(t *testing.T) {
		h := newHarness(t)
		h.users.createErr = domain.ErrConflict
		rep, err := h.svc.SyncFromDirectory(context.Background(), mkSnap(), "")
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Conflicts) != 1 {
			t.Errorf("report = %+v", rep)
		}
	})
	t.Run("update failure", func(t *testing.T) {
		h := newHarness(t, ldapUser("x"))
		h.users.updateErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), mkSnap(), ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("disable failure", func(t *testing.T) {
		h := newHarness(t, ldapUser("gone"))
		h.users.setErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), mkSnap(), ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("list failure", func(t *testing.T) {
		h := newHarness(t)
		h.users.listErr = errors.New("db down")
		// List fails during soft-disable scan (user x is created first).
		if _, err := h.svc.SyncFromDirectory(context.Background(), mkSnap(), ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("admin check failure", func(t *testing.T) {
		h := newHarness(t, ldapUser("x"))
		h.groups.err = errors.New("db down")
		snap := domain.DirectorySnapshot{Users: []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com", MemberOf: []string{adminDN}}}}
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, adminDN); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("admin group missing", func(t *testing.T) {
		h := newHarness(t, ldapUser("x"))
		delete(h.groups.byName, domain.AdminGroup)
		snap := domain.DirectorySnapshot{Users: []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com", MemberOf: []string{adminDN}}}}
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, adminDN); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("admin add failure", func(t *testing.T) {
		h := newHarness(t, ldapUser("x"))
		h.groups.addErr = errors.New("db down")
		snap := domain.DirectorySnapshot{Users: []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com", MemberOf: []string{adminDN}}}}
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, adminDN); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("group lookup failure", func(t *testing.T) {
		h := newHarness(t, ldapUser("x"))
		snap := domain.DirectorySnapshot{
			Users:  []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"}},
			Groups: []domain.LDAPGroup{{Name: "g", Members: []string{"uid=x,ou=users,dc=example,dc=com"}}},
		}
		h.groups.byNameErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("group add failure", func(t *testing.T) {
		h := newHarness(t, ldapUser("x"))
		snap := domain.DirectorySnapshot{
			Users:  []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"}},
			Groups: []domain.LDAPGroup{{Name: "g", Members: []string{"uid=x,ou=users,dc=example,dc=com"}}},
		}
		h.groups.addErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("re-read failure", func(t *testing.T) {
		h := newHarness(t)
		h.users.afterCreate = func() { h.users.usernameErr = errors.New("db down") }
		if _, err := h.svc.SyncFromDirectory(context.Background(), mkSnap(), ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("group create conflict converges", func(t *testing.T) {
		h := newHarness(t)
		snap := domain.DirectorySnapshot{
			Users:  []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"}},
			Groups: []domain.LDAPGroup{{Name: "g", Members: []string{"uid=x,ou=users,dc=example,dc=com"}}},
		}
		// A racing admin create lands between ByName miss and Create.
		h.groups.beforeCreate = func() {
			h.groups.byName["g"] = domain.Group{ID: uuid.New(), Name: "g"}
		}
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, ""); err != nil {
			t.Fatalf("Sync = %v, want nil (conflict converges next sync)", err)
		}
	})
	t.Run("group create failure", func(t *testing.T) {
		h := newHarness(t)
		snap := domain.DirectorySnapshot{
			Users:  []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"}},
			Groups: []domain.LDAPGroup{{Name: "g"}},
		}
		h.groups.createErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("group members failure", func(t *testing.T) {
		h := newHarness(t)
		snap := domain.DirectorySnapshot{
			Users:  []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"}},
			Groups: []domain.LDAPGroup{{Name: "g"}},
		}
		h.groups.memberIDsErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("member resolve failure aborts", func(t *testing.T) {
		h := newHarness(t)
		snap := domain.DirectorySnapshot{
			Users:  []domain.LDAPUser{{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"}},
			Groups: []domain.LDAPGroup{{Name: "g", Members: []string{"uid=x,ou=users,dc=example,dc=com"}}},
		}
		// First List (soft-disable scan) succeeds; the resolve fails.
		h.users.listFailOnCall = 2
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
	t.Run("group remove failure", func(t *testing.T) {
		x := ldapUser("x")
		y := ldapUser("y")
		h := newHarness(t, x, y)
		g, _ := h.groups.Create(context.Background(), domain.Group{Name: "g"})
		_ = h.groups.AddMember(context.Background(), y.ID, g.ID)
		snap := domain.DirectorySnapshot{
			Users: []domain.LDAPUser{
				{Username: "x", DN: "uid=x,ou=users,dc=example,dc=com"},
				{Username: "y", DN: "uid=y,ou=users,dc=example,dc=com"},
			},
			Groups: []domain.LDAPGroup{{Name: "g", Members: []string{"uid=x,ou=users,dc=example,dc=com"}}},
		}
		h.groups.removeErr = errors.New("db down")
		if _, err := h.svc.SyncFromDirectory(context.Background(), snap, ""); err == nil {
			t.Fatal("Sync = nil, want error")
		}
	})
}

func newAttrHarness(t *testing.T) (*harness, *fakeAttrs) {
	t.Helper()
	h := newHarness(t)
	attrs := newFakeAttrs()
	svc, err := New(Deps{
		Users: h.users, Groups: h.groups, Sessions: h.sessions,
		Audit: audit.New(h.audits, fixedClock{now: time.Now()}), Hasher: fakeHasher{},
		Attrs: attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h, attrs
}

func TestAttrDefCRUD(t *testing.T) {
	h, _ := newAttrHarness(t)
	ctx := context.Background()
	actor := uuid.New()

	d, err := h.svc.CreateAttrDef(ctx, actor, "dept", domain.UserAttrString, false)
	if err != nil {
		t.Fatalf("CreateAttrDef: %v", err)
	}
	if d.Key != "dept" || d.Type != domain.UserAttrString || d.Multi {
		t.Fatalf("def = %+v", d)
	}
	if _, err := h.svc.CreateAttrDef(ctx, actor, "dept", domain.UserAttrString, false); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate err = %v, want ErrConflict", err)
	}
	if _, err := h.svc.CreateAttrDef(ctx, actor, "sub", domain.UserAttrString, false); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("reserved err = %v, want ErrValidation", err)
	}
	if _, err := h.svc.CreateAttrDef(ctx, actor, "Bad Key", domain.UserAttrString, false); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad key err = %v, want ErrValidation", err)
	}
	defs, err := h.svc.ListAttrDefs(ctx)
	if err != nil || len(defs) != 1 || defs[0].Key != "dept" {
		t.Fatalf("ListDefs = %v, %v", defs, err)
	}
	if err := h.svc.DeleteAttrDef(ctx, actor, "dept"); err != nil {
		t.Fatalf("DeleteAttrDef: %v", err)
	}
	if err := h.svc.DeleteAttrDef(ctx, actor, "dept"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second delete err = %v, want ErrNotFound", err)
	}
}

func TestSetGetUserAttrs(t *testing.T) {
	u := localUser("ara")
	h, attrs := newAttrHarness(t)
	h.users.put(u)
	ctx := context.Background()
	actor := uuid.New()
	for _, d := range []domain.UserAttrDef{
		{Key: "dept", Type: domain.UserAttrString},
		{Key: "level", Type: domain.UserAttrNumber},
		{Key: "vip", Type: domain.UserAttrBoolean},
		{Key: "tags", Type: domain.UserAttrString, Multi: true},
	} {
		if _, err := attrs.CreateDef(ctx, d); err != nil {
			t.Fatal(err)
		}
	}

	got, err := h.svc.SetUserAttrs(ctx, actor, u.ID, map[string]any{
		"dept": "eng", "level": 3.0, "vip": true, "tags": []any{"a", "b"},
	})
	if err != nil {
		t.Fatalf("SetUserAttrs: %v", err)
	}
	want := map[string]any{"dept": "eng", "level": 3.0, "vip": true, "tags": []any{"a", "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SetUserAttrs = %v, want %v", got, want)
	}
	if got, err := h.svc.GetUserAttrs(ctx, u.ID); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("GetUserAttrs = %v, %v", got, err)
	}
	// Null clears one key; unmentioned keys are untouched.
	got, err = h.svc.SetUserAttrs(ctx, actor, u.ID, map[string]any{"tags": nil})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok := got["tags"]; ok {
		t.Fatalf("tags not cleared: %v", got)
	}
	if got["dept"] != "eng" {
		t.Fatalf("unmentioned key touched: %v", got)
	}
	// Whole-write failures.
	for name, input := range map[string]map[string]any{
		"unknown key":     {"nosuch": "x"},
		"bad number":      {"level": "abc"},
		"bad bool":        {"vip": "yes"},
		"multi on single": {"dept": []any{"a", "b"}},
		"nested object":   {"dept": map[string]any{"x": 1}},
	} {
		if _, err := h.svc.SetUserAttrs(ctx, actor, u.ID, input); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
	if _, err := h.svc.GetUserAttrs(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown user GetUserAttrs err = %v, want ErrNotFound", err)
	}
	if _, err := h.svc.SetUserAttrs(ctx, actor, uuid.New(), map[string]any{"dept": "x"}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown user SetUserAttrs err = %v, want ErrNotFound", err)
	}
	// Def delete cascades values.
	if err := h.svc.DeleteAttrDef(ctx, actor, "dept"); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.svc.GetUserAttrs(ctx, u.ID); len(got) != 2 {
		t.Fatalf("after def delete = %v, want 2 keys", got)
	}
}

func TestSyncAppliesUpstreamAttrs(t *testing.T) {
	u := ldapUser("dirara")
	h, attrs := newAttrHarness(t)
	h.users.put(u)
	ctx := context.Background()
	for _, d := range []domain.UserAttrDef{
		{Key: "dept", Type: domain.UserAttrString},
		{Key: "level", Type: domain.UserAttrNumber},
		{Key: "note", Type: domain.UserAttrString},
	} {
		if _, err := attrs.CreateDef(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	// Admin-sourced value the sync must not touch.
	byKey := func() map[string]domain.UserAttrDef {
		defs, _ := attrs.ListDefs(ctx)
		m := map[string]domain.UserAttrDef{}
		for _, d := range defs {
			m[d.Key] = d
		}
		return m
	}
	ids := byKey()
	if err := attrs.SetValues(ctx, u.ID, map[uuid.UUID][]string{ids["note"].ID: {"keep"}}, domain.UserAttrAdmin); err != nil {
		t.Fatal(err)
	}

	snap := domain.DirectorySnapshot{
		Users: []domain.LDAPUser{{
			Username: "dirara", Email: "dirara@dir.example.com", DisplayName: "Dir",
			DN:    "uid=dirara,ou=users,dc=example,dc=com",
			Attrs: map[string][]string{"dept": {"eng"}, "level": {"abc"}, "nosuch": {"x"}},
		}},
	}
	if _, err := h.svc.SyncFromDirectory(ctx, snap, ""); err != nil {
		t.Fatal(err)
	}
	got, err := h.svc.GetUserAttrs(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Valid value applied, garbage number dropped, unknown key skipped,
	// admin-sourced key untouched.
	want := map[string]any{"dept": "eng", "note": "keep"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after sync = %v, want %v", got, want)
	}
	// Empty snapshot map clears ldap-sourced keys only.
	snap.Users[0].Attrs = map[string][]string{}
	if _, err := h.svc.SyncFromDirectory(ctx, snap, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.svc.GetUserAttrs(ctx, u.ID); !reflect.DeepEqual(got, map[string]any{"note": "keep"}) {
		t.Fatalf("after empty sync = %v", got)
	}
	// Nil map (no mapping configured) applies nothing.
	snap.Users[0].Attrs = nil
	if err := attrs.ApplyUpstreamValues(ctx, u.ID, map[uuid.UUID][]string{ids["dept"].ID: {"x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.SyncFromDirectory(ctx, snap, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.svc.GetUserAttrs(ctx, u.ID); got["dept"] != "x" {
		t.Fatalf("nil snapshot cleared ldap values: %v", got)
	}
}
