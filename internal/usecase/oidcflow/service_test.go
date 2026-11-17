package oidcflow

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

type fakeClients struct {
	byID map[string]domain.OIDCClient
	err  error
}

func (f *fakeClients) GetByClientID(_ context.Context, id string) (domain.OIDCClient, error) {
	if f.err != nil {
		return domain.OIDCClient{}, f.err
	}
	c, ok := f.byID[id]
	if !ok {
		return domain.OIDCClient{}, domain.ErrNotFound
	}
	return c, nil
}

func (f *fakeClients) Create(_ context.Context, c domain.OIDCClient) (domain.OIDCClient, error) {
	return c, nil
}

func (f *fakeClients) Delete(_ context.Context, _ string) error { return nil }

func (f *fakeClients) List(_ context.Context, _, _ int) ([]domain.OIDCClient, int, error) {
	return nil, 0, nil
}

type fakeGroups struct {
	names []string
	err   error
}

func (f *fakeGroups) Create(_ context.Context, g domain.Group) (domain.Group, error) {
	return g, nil
}

func (f *fakeGroups) ByID(_ context.Context, id uuid.UUID) (domain.Group, error) {
	return domain.Group{ID: id}, nil
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

func (f *fakeGroups) AddMember(_ context.Context, _, _ uuid.UUID) error { return nil }

func (f *fakeGroups) RemoveMember(_ context.Context, _, _ uuid.UUID) error { return nil }

func (f *fakeGroups) MemberIDs(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

func (f *fakeGroups) MemberUsernamesByGroup(_ context.Context) (map[uuid.UUID][]string, error) {
	return map[uuid.UUID][]string{}, nil
}

func (f *fakeGroups) GroupsOfUser(_ context.Context, _ uuid.UUID) ([]domain.Group, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]domain.Group, 0, len(f.names))
	for _, n := range f.names {
		out = append(out, domain.Group{Name: n})
	}
	return out, nil
}

func (f *fakeGroups) IsMember(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return false, nil
}

type fakeConsents struct {
	grants map[string][]string
	err    error
}

func (f *fakeConsents) Get(_ context.Context, userID uuid.UUID, clientID string) (domain.OIDCConsent, error) {
	if f.err != nil {
		return domain.OIDCConsent{}, f.err
	}
	sc, ok := f.grants[userID.String()+"|"+clientID]
	if !ok {
		return domain.OIDCConsent{}, domain.ErrNotFound
	}
	return domain.OIDCConsent{UserID: userID, ClientID: clientID, Scopes: sc}, nil
}

func (f *fakeConsents) Grant(_ context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	if f.grants == nil {
		f.grants = map[string][]string{}
	}
	f.grants[userID.String()+"|"+clientID] = scopes
	return nil
}

func (f *fakeConsents) Revoke(_ context.Context, userID uuid.UUID, clientID string) error {
	delete(f.grants, userID.String()+"|"+clientID)
	return nil
}

func testService() (*Service, *fakeClients, *fakeGroups, *fakeConsents) {
	clients := &fakeClients{byID: map[string]domain.OIDCClient{
		"web": {ClientID: "web", Scopes: []string{"openid", "profile", "email", "groups", "offline_access"}},
	}}
	groups := &fakeGroups{names: []string{"eng", "ih_admin"}}
	consents := &fakeConsents{}
	svc, err := New(Deps{Clients: clients, Groups: groups, Consents: consents})
	if err != nil {
		panic(err)
	}
	return svc, clients, groups, consents
}

type fakeAttrs struct {
	defs   []domain.UserAttrDef
	values map[uuid.UUID]map[string][]string
	err    error
}

func (f *fakeAttrs) CreateDef(_ context.Context, d domain.UserAttrDef) (domain.UserAttrDef, error) {
	return d, nil
}

func (f *fakeAttrs) ListDefs(_ context.Context) ([]domain.UserAttrDef, error) {
	return f.defs, f.err
}

func (f *fakeAttrs) DeleteDef(_ context.Context, _ string) error { return nil }

func (f *fakeAttrs) SetValues(_ context.Context, _ uuid.UUID, _ map[uuid.UUID][]string, _ domain.UserAttrSource) error {
	return nil
}

func (f *fakeAttrs) ApplyUpstreamValues(_ context.Context, _ uuid.UUID, _ map[uuid.UUID][]string) error {
	return nil
}

func (f *fakeAttrs) ValuesOfUser(_ context.Context, userID uuid.UUID) (map[string][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.values[userID], nil
}

func (f *fakeAttrs) ValuesForUsers(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]map[string][]string, error) {
	return map[uuid.UUID]map[string][]string{}, nil
}

func testUser() domain.User {
	return domain.User{
		ID: uuid.New(), Username: "alice", Email: "alice@example.com",
		DisplayName: "Alice", IsActive: true,
	}
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New(empty) = nil error, want required-deps error")
	}
}

func TestEvaluateBuildsClaims(t *testing.T) {
	svc, _, _, _ := testService()
	u := testUser()
	out, err := svc.Evaluate(context.Background(), u, domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid", "profile", "groups"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	d := out.Decision
	if d.Subject != u.ID.String() {
		t.Fatalf("sub = %q, want user UUID %q", d.Subject, u.ID)
	}
	if d.Username != "alice" || d.Email != "alice@example.com" || d.Name != "Alice" {
		t.Fatalf("claims = %+v, want alice identity", d)
	}
	if len(d.Groups) != 2 || d.Groups[0] != "eng" || d.Groups[1] != "ih_admin" {
		t.Fatalf("groups = %v, want [eng ih_admin]", d.Groups)
	}
	if len(d.GrantedScopes) != 3 {
		t.Fatalf("granted = %v, want the 3 requested scopes", d.GrantedScopes)
	}
	if !out.NeedConsent {
		t.Fatal("NeedConsent = false on first authorize, want true")
	}
}

func TestEvaluateCarriesCustomClaims(t *testing.T) {
	svc, clients, groups, consents := testService()
	u := testUser()
	attrs := &fakeAttrs{
		defs: []domain.UserAttrDef{
			{Key: "dept", Type: domain.UserAttrString},
			{Key: "level", Type: domain.UserAttrNumber},
			{Key: "vip", Type: domain.UserAttrBoolean},
			{Key: "tags", Type: domain.UserAttrString, Multi: true},
		},
		values: map[uuid.UUID]map[string][]string{
			u.ID: {"dept": {"eng"}, "level": {"3"}, "vip": {"true"}, "tags": {"a", "b"}},
		},
	}
	svc, err := New(Deps{Clients: clients, Groups: groups, Consents: consents, Attrs: attrs})
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.Evaluate(context.Background(), u, domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := map[string]any{"dept": "eng", "level": 3.0, "vip": true, "tags": []any{"a", "b"}}
	if !reflect.DeepEqual(out.Decision.CustomAttrs, want) {
		t.Fatalf("CustomAttrs = %v, want %v", out.Decision.CustomAttrs, want)
	}
}

func TestEvaluateRememberedConsentSkipsPage(t *testing.T) {
	svc, _, _, consents := testService()
	u := testUser()
	consents.grants = map[string][]string{
		u.ID.String() + "|web": {"openid", "profile", "groups"},
	}
	out, err := svc.Evaluate(context.Background(), u, domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.NeedConsent {
		t.Fatal("NeedConsent = true with covering grant, want false")
	}
	// A grant that misses one scope must resurface the page.
	out, err = svc.Evaluate(context.Background(), u, domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !out.NeedConsent {
		t.Fatal("NeedConsent = false with partial grant, want true")
	}
}

func TestEvaluateRejectsUnknownScope(t *testing.T) {
	svc, _, _, _ := testService()
	_, err := svc.Evaluate(context.Background(), testUser(), domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid", "admin"},
	})
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Evaluate(unknown scope) = %v, want ErrValidation", err)
	}
}

func TestEvaluateRejectsUnknownClient(t *testing.T) {
	svc, _, _, _ := testService()
	_, err := svc.Evaluate(context.Background(), testUser(), domain.OIDCAuthRequest{
		ClientID: "ghost", RequestedScopes: []string{"openid"},
	})
	if !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("Evaluate(unknown client) = %v, want ErrValidation", err)
	}
}

func TestEvaluateRejectsDisabledUser(t *testing.T) {
	svc, _, _, _ := testService()
	u := testUser()
	u.IsActive = false
	_, err := svc.Evaluate(context.Background(), u, domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid"},
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("Evaluate(disabled) = %v, want ErrForbidden", err)
	}
}

func TestGrantConsentValidates(t *testing.T) {
	svc, _, _, _ := testService()
	if err := svc.GrantConsent(context.Background(), uuid.Nil, "web", []string{"openid"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("GrantConsent(nil user) = %v, want ErrValidation", err)
	}
	u := testUser()
	if err := svc.GrantConsent(context.Background(), u.ID, "web", []string{"openid"}); err != nil {
		t.Fatalf("GrantConsent: %v", err)
	}
	out, err := svc.Evaluate(context.Background(), u, domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.NeedConsent {
		t.Fatal("NeedConsent = true right after grant, want false")
	}
}

func TestCovers(t *testing.T) {
	if !covers([]string{"a", "b"}, []string{"a"}) {
		t.Fatal("covers(subset) = false, want true")
	}
	if !covers(nil, nil) {
		t.Fatal("covers(empty, empty) = false, want true")
	}
	if covers([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("covers(partial) = true, want false")
	}
	if covers(nil, []string{"a"}) {
		t.Fatal("covers(nil, want) = true, want false")
	}
}

type stubAccess struct {
	allow map[uuid.UUID]bool
	err   error
}

func (s stubAccess) CanAccess(_ context.Context, _ domain.User, appID uuid.UUID) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.allow[appID], nil
}

func TestEvaluateEnforcesBindings(t *testing.T) {
	svc, clients, groups, consents := testService()
	appID := uuid.New()
	c := clients.byID["web"]
	c.ApplicationID = appID
	clients.byID["web"] = c
	denied, err := New(Deps{Clients: clients, Groups: groups, Consents: consents, Access: stubAccess{allow: map[uuid.UUID]bool{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Evaluate(context.Background(), testUser(), domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid"},
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("denied binding must be forbidden, got %v", err)
	}
	allowed, err := New(Deps{Clients: clients, Groups: groups, Consents: consents, Access: stubAccess{allow: map[uuid.UUID]bool{appID: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allowed.Evaluate(context.Background(), testUser(), domain.OIDCAuthRequest{
		ClientID: "web", RequestedScopes: []string{"openid"},
	}); err != nil {
		t.Fatalf("allowed binding must pass: %v", err)
	}
	_ = svc
}
