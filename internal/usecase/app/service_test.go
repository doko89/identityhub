package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// ---------- fakes ----------

type fakeApps struct {
	byID   map[uuid.UUID]domain.Application
	bySlug map[string]domain.Application
}

func (f *fakeApps) Create(_ context.Context, a domain.Application) (domain.Application, error) {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if _, ok := f.bySlug[a.Slug]; ok {
		return domain.Application{}, domain.ErrConflict
	}
	f.byID[a.ID] = a
	f.bySlug[a.Slug] = a
	return a, nil
}
func (f *fakeApps) ByID(_ context.Context, id uuid.UUID) (domain.Application, error) {
	a, ok := f.byID[id]
	if !ok {
		return domain.Application{}, domain.ErrNotFound
	}
	return a, nil
}
func (f *fakeApps) BySlug(_ context.Context, slug string) (domain.Application, error) {
	a, ok := f.bySlug[slug]
	if !ok {
		return domain.Application{}, domain.ErrNotFound
	}
	return a, nil
}
func (f *fakeApps) List(_ context.Context, flt domain.AppFilter) ([]domain.Application, int, error) {
	var all []domain.Application
	for _, a := range f.byID {
		if flt.Group != "" && !strings.Contains(strings.ToLower(a.GroupLabel), strings.ToLower(flt.Group)) {
			continue
		}
		all = append(all, a)
	}
	if flt.Offset >= len(all) {
		return nil, len(all), nil
	}
	end := flt.Offset + flt.Limit
	if end > len(all) {
		end = len(all)
	}
	return all[flt.Offset:end], len(all), nil
}
func (f *fakeApps) Update(_ context.Context, a domain.Application) (domain.Application, error) {
	if _, ok := f.byID[a.ID]; !ok {
		return domain.Application{}, domain.ErrNotFound
	}
	f.byID[a.ID] = a
	f.bySlug[a.Slug] = a
	return a, nil
}
func (f *fakeApps) Delete(_ context.Context, id uuid.UUID) error {
	a, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	delete(f.byID, id)
	delete(f.bySlug, a.Slug)
	return nil
}

type fakeBindings struct {
	byApp map[uuid.UUID][]domain.AppBinding
}

func (f *fakeBindings) Create(_ context.Context, b domain.AppBinding) (domain.AppBinding, error) {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	f.byApp[b.ApplicationID] = append(f.byApp[b.ApplicationID], b)
	return b, nil
}
func (f *fakeBindings) ForApplication(_ context.Context, appID uuid.UUID) ([]domain.AppBinding, error) {
	return f.byApp[appID], nil
}
func (f *fakeBindings) Delete(_ context.Context, id uuid.UUID) error {
	for appID, list := range f.byApp {
		for i, b := range list {
			if b.ID == id {
				f.byApp[appID] = append(list[:i], list[i+1:]...)
				return nil
			}
		}
	}
	return domain.ErrNotFound
}

type fakeUsers struct {
	byID map[uuid.UUID]domain.User
}

func (f *fakeUsers) Create(_ context.Context, u domain.User) (domain.User, error) {
	f.byID[u.ID] = u
	return u, nil
}
func (f *fakeUsers) ByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}
func (f *fakeUsers) ByUsername(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (f *fakeUsers) ByUsernameFold(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (f *fakeUsers) ByEmail(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (f *fakeUsers) List(_ context.Context, _ domain.UserFilter) ([]domain.User, int, error) {
	return nil, 0, nil
}
func (f *fakeUsers) AllActive(_ context.Context) ([]domain.User, error) {
	return nil, nil
}
func (f *fakeUsers) Update(_ context.Context, u domain.User) (domain.User, error) {
	f.byID[u.ID] = u
	return u, nil
}
func (f *fakeUsers) SetActive(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}
func (f *fakeUsers) SetPasswordHash(_ context.Context, _ uuid.UUID, _ []byte) error {
	return nil
}

type fakeGroups struct {
	byID    map[uuid.UUID]domain.Group
	members map[string]map[uuid.UUID]bool // group name -> user ids
}

func (f *fakeGroups) Create(_ context.Context, g domain.Group) (domain.Group, error) {
	f.byID[g.ID] = g
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
	return domain.Group{Name: name}, nil
}
func (f *fakeGroups) List(_ context.Context, _, _ int) ([]domain.Group, int, error) {
	return nil, 0, nil
}
func (f *fakeGroups) All(_ context.Context) ([]domain.Group, error) {
	return nil, nil
}
func (f *fakeGroups) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeGroups) AddMember(_ context.Context, _, _ uuid.UUID) error {
	return nil
}
func (f *fakeGroups) RemoveMember(_ context.Context, _, _ uuid.UUID) error {
	return nil
}
func (f *fakeGroups) MemberIDs(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeGroups) MemberUsernamesByGroup(_ context.Context) (map[uuid.UUID][]string, error) {
	return map[uuid.UUID][]string{}, nil
}
func (f *fakeGroups) GroupsOfUser(_ context.Context, _ uuid.UUID) ([]domain.Group, error) {
	return nil, nil
}
func (f *fakeGroups) IsMember(_ context.Context, id uuid.UUID, name string) (bool, error) {
	return f.members[name][id], nil
}

func newTestService() (*Service, *fakeApps, *fakeBindings, *fakeUsers, *fakeGroups, domain.User, domain.Group) {
	u := domain.User{ID: uuid.New(), Username: "alice", Email: "alice@example.com", IsActive: true}
	g := domain.Group{ID: uuid.New(), Name: "engineering"}
	users := &fakeUsers{byID: map[uuid.UUID]domain.User{u.ID: u}}
	groups := &fakeGroups{byID: map[uuid.UUID]domain.Group{g.ID: g}, members: map[string]map[uuid.UUID]bool{}}
	svc, err := New(Deps{
		Apps:     &fakeApps{byID: map[uuid.UUID]domain.Application{}, bySlug: map[string]domain.Application{}},
		Bindings: &fakeBindings{byApp: map[uuid.UUID][]domain.AppBinding{}},
		Users:    users,
		Groups:   groups,
	})
	if err != nil {
		panic(err)
	}
	return svc, svc.apps.(*fakeApps), svc.bindings.(*fakeBindings), users, groups, u, g
}

func mkapp(slug string) domain.Application {
	return domain.Application{
		Slug: slug, Name: slug, ProviderType: domain.ProviderOIDC,
		LaunchURL: "https://" + slug + ".example.com", IsVisible: true,
	}
}

// ---------- tests ----------

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("empty deps must fail")
	}
}

func TestNoBindingsAllowsAll(t *testing.T) {
	svc, apps, _, _, _, u, _ := newTestService()
	ctx := context.Background()
	a, err := svc.CreateApp(ctx, mkapp("wiki"))
	if err != nil {
		t.Fatal(err)
	}
	_ = apps
	ok, err := svc.CanAccess(ctx, u, a.ID)
	if err != nil || !ok {
		t.Fatalf("no bindings must allow all, got %v %v", ok, err)
	}
	got, err := svc.Launch(ctx, u.ID, "wiki")
	if err != nil || got.ID != a.ID {
		t.Fatalf("launch must resolve: %v", err)
	}
}

func TestUserBinding(t *testing.T) {
	svc, _, _, _, _, u, _ := newTestService()
	ctx := context.Background()
	a, _ := svc.CreateApp(ctx, mkapp("hr"))
	other := uuid.New()
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: a.ID, BindingType: domain.BindingUser, UserID: &other,
	}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("binding to unknown user must fail, got %v", err)
	}
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: a.ID, BindingType: domain.BindingUser, UserID: &u.ID,
	}); err != nil {
		t.Fatal(err)
	}
	ok, _ := svc.CanAccess(ctx, u, a.ID)
	if !ok {
		t.Fatal("bound user must have access")
	}
	stranger := domain.User{ID: uuid.New(), Username: "mallory", IsActive: true}
	ok, _ = svc.CanAccess(ctx, stranger, a.ID)
	if ok {
		t.Fatal("unbound user must not have access")
	}
}

func TestGroupBindingAnyAll(t *testing.T) {
	svc, _, _, _, groups, u, g := newTestService()
	ctx := context.Background()
	a, _ := svc.CreateApp(ctx, mkapp("ci"))
	other := domain.Group{ID: uuid.New(), Name: "contractors"}
	groups.byID[other.ID] = other
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: a.ID, BindingType: domain.BindingGroup, GroupID: &g.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: a.ID, BindingType: domain.BindingGroup, GroupID: &other.ID,
	}); err != nil {
		t.Fatal(err)
	}
	// Any-mode: one membership suffices.
	groups.members["engineering"] = map[uuid.UUID]bool{u.ID: true}
	if ok, _ := svc.CanAccess(ctx, u, a.ID); !ok {
		t.Fatal("any-mode: member must have access")
	}
	// All-mode: every binding must match.
	svc2apps := svc.bindings.(*fakeBindings).byApp[a.ID]
	for i := range svc2apps {
		svc2apps[i].EvalMode = domain.EvalAll
	}
	if ok, _ := svc.CanAccess(ctx, u, a.ID); ok {
		t.Fatal("all-mode: partial membership must not have access")
	}
	groups.members["contractors"] = map[uuid.UUID]bool{u.ID: true}
	if ok, _ := svc.CanAccess(ctx, u, a.ID); !ok {
		t.Fatal("all-mode: full membership must have access")
	}
}

func TestPolicyBinding(t *testing.T) {
	svc, _, _, _, groups, u, _ := newTestService()
	ctx := context.Background()
	a, _ := svc.CreateApp(ctx, mkapp("vpn"))
	for _, bad := range []string{"", "nogroup", "team:x", "group:", "group:eng|bogus"} {
		if _, err := svc.CreateBinding(ctx, domain.AppBinding{
			ApplicationID: a.ID, BindingType: domain.BindingPolicy, PolicyExpr: bad,
		}); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("policy %q must fail validation, got %v", bad, err)
		}
	}
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: a.ID, BindingType: domain.BindingPolicy,
		PolicyExpr: "group:engineering|email_domain:example.com",
	}); err != nil {
		t.Fatal(err)
	}
	// Email domain matches even without the group.
	if ok, _ := svc.CanAccess(ctx, u, a.ID); !ok {
		t.Fatal("email_domain clause must grant access")
	}
	outsider := domain.User{ID: uuid.New(), Username: "bob", Email: "bob@other.tld", IsActive: true}
	if ok, _ := svc.CanAccess(ctx, outsider, a.ID); ok {
		t.Fatal("outsider must not have access")
	}
	groups.members["engineering"] = map[uuid.UUID]bool{outsider.ID: true}
	if ok, _ := svc.CanAccess(ctx, outsider, a.ID); !ok {
		t.Fatal("group clause must grant access")
	}
}

func TestMyAppsFiltersInvisibleAndDenied(t *testing.T) {
	svc, _, _, users, _, u, _ := newTestService()
	ctx := context.Background()
	if _, err := svc.CreateApp(ctx, mkapp("open")); err != nil {
		t.Fatal(err)
	}
	hidden := mkapp("hidden")
	hidden.IsVisible = false
	if _, err := svc.CreateApp(ctx, hidden); err != nil {
		t.Fatal(err)
	}
	locked, _ := svc.CreateApp(ctx, mkapp("locked"))
	stranger := uuid.New()
	users.byID[stranger] = domain.User{ID: stranger, Username: "z", IsActive: true}
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: locked.ID, BindingType: domain.BindingUser, UserID: &stranger,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.MyApps(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Slug != "open" {
		t.Fatalf("dashboard must show only the open app, got %+v", got)
	}
	if _, err := svc.Launch(ctx, u.ID, "hidden"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("invisible app must be not-found, got %v", err)
	}
	if _, err := svc.Launch(ctx, u.ID, "locked"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("denied app must be forbidden, got %v", err)
	}
	if _, err := svc.Launch(ctx, u.ID, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing app must be not-found, got %v", err)
	}
}

func TestDisabledUserDenied(t *testing.T) {
	svc, _, _, users, _, u, _ := newTestService()
	u.IsActive = false
	users.byID[u.ID] = u
	if _, err := svc.MyApps(context.Background(), u.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("disabled user must be forbidden, got %v", err)
	}
	if _, err := svc.Launch(context.Background(), u.ID, "x"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("disabled user must be forbidden, got %v", err)
	}
}

func TestAppCRUDValidation(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService()
	ctx := context.Background()
	bad := mkapp("bad")
	bad.LaunchURL = "ftp://x/y"
	if _, err := svc.CreateApp(ctx, bad); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad launch URL must fail, got %v", err)
	}
	rel := mkapp("saml-app")
	rel.ProviderType = domain.ProviderSAML
	rel.LaunchURL = "/saml/sso?sp=urn:example"
	a, err := svc.CreateApp(ctx, rel)
	if err != nil {
		t.Fatal(err)
	}
	a.Name = "Renamed"
	if _, err := svc.UpdateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	a.IconURL = "javascript:alert(1)"
	if _, err := svc.UpdateApp(ctx, a); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad icon URL must fail, got %v", err)
	}
	list, total, err := svc.ListApps(ctx, domain.AppFilter{Limit: 10})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("list must return the app: %+v %d %v", list, total, err)
	}
	if _, err := svc.GetApp(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteApp(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteApp(ctx, a.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second delete must be not-found, got %v", err)
	}
}

func TestListAppsFiltersByGroup(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService()
	ctx := context.Background()
	tools := mkapp("wiki")
	tools.GroupLabel = "Tools"
	if _, err := svc.CreateApp(ctx, tools); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateApp(ctx, mkapp("crm")); err != nil {
		t.Fatal(err)
	}
	list, total, err := svc.ListApps(ctx, domain.AppFilter{Group: "tool", Limit: 10})
	if err != nil || total != 1 || len(list) != 1 || list[0].Slug != "wiki" {
		t.Fatalf("group filter must match wiki only: %+v %d %v", list, total, err)
	}
	list, total, err = svc.ListApps(ctx, domain.AppFilter{Limit: 10})
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("empty filter must return all: %+v %d %v", list, total, err)
	}
}

func TestBindingValidation(t *testing.T) {
	svc, _, _, _, _, u, g := newTestService()
	ctx := context.Background()
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: uuid.New(), BindingType: domain.BindingUser, UserID: &u.ID,
	}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("binding to unknown app must fail, got %v", err)
	}
	a, _ := svc.CreateApp(ctx, mkapp("db"))
	cases := []domain.AppBinding{
		{ApplicationID: a.ID, BindingType: domain.BindingUser},
		{ApplicationID: a.ID, BindingType: domain.BindingUser, UserID: &u.ID, GroupID: &g.ID},
		{ApplicationID: a.ID, BindingType: domain.BindingGroup},
		{ApplicationID: a.ID, BindingType: domain.BindingPolicy, PolicyExpr: "group:x", UserID: &u.ID},
		{ApplicationID: a.ID, BindingType: "team"},
		{ApplicationID: a.ID, BindingType: domain.BindingUser, UserID: &u.ID, EvalMode: "sometimes"},
	}
	for i, c := range cases {
		if _, err := svc.CreateBinding(ctx, c); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("case %d must fail validation, got %v", i, err)
		}
	}
	if _, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: a.ID, BindingType: domain.BindingGroup, GroupID: &uuid.UUID{},
	}); err == nil {
		t.Fatal("binding to unknown group must fail")
	}
	b, err := svc.CreateBinding(ctx, domain.AppBinding{
		ApplicationID: a.ID, BindingType: domain.BindingGroup, GroupID: &g.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.EvalMode != domain.EvalAny {
		t.Fatalf("default eval mode must be any, got %q", b.EvalMode)
	}
	list, err := svc.ListBindings(ctx, a.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list must return the binding: %+v %v", list, err)
	}
	if _, err := svc.ListBindings(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("bindings of unknown app must fail, got %v", err)
	}
	if err := svc.DeleteBinding(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteBinding(ctx, b.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second delete must be not-found, got %v", err)
	}
}

func TestGroupBindingDeletedGroupDenies(t *testing.T) {
	svc, _, bindings, _, groups, u, g := newTestService()
	ctx := context.Background()
	a, _ := svc.CreateApp(ctx, mkapp("erp"))
	bindings.byApp[a.ID] = []domain.AppBinding{{
		ID: uuid.Nil, ApplicationID: a.ID, BindingType: domain.BindingGroup,
		GroupID: &g.ID, EvalMode: domain.EvalAny,
	}}
	delete(groups.byID, g.ID) // group deleted out of band
	if ok, err := svc.CanAccess(ctx, u, a.ID); err != nil || ok {
		t.Fatalf("deleted group must deny, got %v %v", ok, err)
	}
	bindings.byApp[a.ID] = []domain.AppBinding{{
		ApplicationID: a.ID, BindingType: "team", EvalMode: domain.EvalAny,
	}}
	if _, err := svc.CanAccess(ctx, u, a.ID); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("unknown binding type must fail, got %v", err)
	}
}
