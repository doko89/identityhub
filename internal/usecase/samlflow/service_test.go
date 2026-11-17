package samlflow

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

type fakeSPs struct {
	byEntity map[string]domain.SAMLServiceProvider
	err      error
}

func (f *fakeSPs) GetByEntityID(_ context.Context, entityID string) (domain.SAMLServiceProvider, error) {
	if f.err != nil {
		return domain.SAMLServiceProvider{}, f.err
	}
	sp, ok := f.byEntity[entityID]
	if !ok {
		return domain.SAMLServiceProvider{}, domain.ErrNotFound
	}
	return sp, nil
}

func (f *fakeSPs) Create(_ context.Context, sp domain.SAMLServiceProvider) (domain.SAMLServiceProvider, error) {
	return sp, nil
}

func (f *fakeSPs) Delete(_ context.Context, _ string) error { return nil }

func (f *fakeSPs) List(_ context.Context, _, _ int) ([]domain.SAMLServiceProvider, int, error) {
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

func testService() (*Service, *fakeSPs, *fakeGroups) {
	sps := &fakeSPs{byEntity: map[string]domain.SAMLServiceProvider{
		"https://sp.example.com/metadata": {
			EntityID: "https://sp.example.com/metadata",
			ACSURL:   "https://sp.example.com/acs",
		},
	}}
	groups := &fakeGroups{names: []string{"eng", "ih_admin"}}
	svc, err := New(Deps{SPs: sps, Groups: groups})
	if err != nil {
		panic(err)
	}
	return svc, sps, groups
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

func testRequest() domain.SAMLAuthnRequest {
	return domain.SAMLAuthnRequest{
		RequestID: "id-123", EntityID: "https://sp.example.com/metadata",
		ACSURL: "https://sp.example.com/acs", RelayState: "relay-1",
	}
}

func TestNewRequiresStores(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New without stores must fail")
	}
	if _, err := New(Deps{SPs: &fakeSPs{}}); err == nil {
		t.Fatal("New without groups must fail")
	}
}

func TestEvaluateBuildsDecision(t *testing.T) {
	svc, _, _ := testService()
	d, err := svc.Evaluate(context.Background(), testUser(), testRequest())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.NameID != "alice" {
		t.Fatalf("NameID = %q, want username alice", d.NameID)
	}
	if d.Email != "alice@example.com" || d.DisplayName != "Alice" {
		t.Fatalf("claims = %+v, want alice's email/display name", d)
	}
	if len(d.Groups) != 2 || d.Groups[0] != "eng" || d.Groups[1] != "ih_admin" {
		t.Fatalf("Groups = %v, want [eng ih_admin]", d.Groups)
	}
}

func TestEvaluateCarriesCustomAttributes(t *testing.T) {
	svc, sps, groups := testService()
	u := testUser()
	attrs := &fakeAttrs{
		defs: []domain.UserAttrDef{
			{Key: "dept", Type: domain.UserAttrString},
			{Key: "tags", Type: domain.UserAttrString, Multi: true},
		},
		values: map[uuid.UUID]map[string][]string{
			u.ID: {"dept": {"eng"}, "tags": {"a", "b"}},
		},
	}
	svc, err := New(Deps{SPs: sps, Groups: groups, Attrs: attrs})
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.Evaluate(context.Background(), u, testRequest())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := map[string][]string{"dept": {"eng"}, "tags": {"a", "b"}}
	if !reflect.DeepEqual(d.Attributes, want) {
		t.Fatalf("Attributes = %v, want %v", d.Attributes, want)
	}
}

func TestEvaluateEdgeCases(t *testing.T) {
	ctx := context.Background()
	t.Run("inactive user is forbidden", func(t *testing.T) {
		svc, _, _ := testService()
		u := testUser()
		u.IsActive = false
		if _, err := svc.Evaluate(ctx, u, testRequest()); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("err = %v, want ErrForbidden", err)
		}
	})
	t.Run("empty entity ID is rejected", func(t *testing.T) {
		svc, _, _ := testService()
		req := testRequest()
		req.EntityID = ""
		if _, err := svc.Evaluate(ctx, testUser(), req); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("err = %v, want ErrValidation", err)
		}
	})
	t.Run("unregistered SP fails closed", func(t *testing.T) {
		svc, _, _ := testService()
		req := testRequest()
		req.EntityID = "https://evil.example.com/metadata"
		if _, err := svc.Evaluate(ctx, testUser(), req); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("err = %v, want ErrValidation", err)
		}
	})
	t.Run("store errors propagate", func(t *testing.T) {
		svc, sps, _ := testService()
		sps.err = errors.New("db down")
		if _, err := svc.Evaluate(ctx, testUser(), testRequest()); err == nil {
			t.Fatal("expected store error to propagate")
		}
	})
	t.Run("group errors propagate", func(t *testing.T) {
		svc, _, groups := testService()
		groups.err = errors.New("db down")
		if _, err := svc.Evaluate(ctx, testUser(), testRequest()); err == nil {
			t.Fatal("expected group error to propagate")
		}
	})
	t.Run("user without groups gets empty list", func(t *testing.T) {
		svc, _, groups := testService()
		groups.names = nil
		d, err := svc.Evaluate(ctx, testUser(), testRequest())
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(d.Groups) != 0 {
			t.Fatalf("Groups = %v, want empty", d.Groups)
		}
	})
}

type stubAccess struct {
	allow map[uuid.UUID]bool
}

func (s stubAccess) CanAccess(_ context.Context, _ domain.User, appID uuid.UUID) (bool, error) {
	return s.allow[appID], nil
}

func TestEvaluateEnforcesBindings(t *testing.T) {
	svc, sps, groups := testService()
	appID := uuid.New()
	sp := sps.byEntity["https://sp.example.com/metadata"]
	sp.ApplicationID = appID
	sps.byEntity["https://sp.example.com/metadata"] = sp
	denied, err := New(Deps{SPs: sps, Groups: groups, Access: stubAccess{allow: map[uuid.UUID]bool{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Evaluate(context.Background(), testUser(), testRequest()); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("denied binding must be forbidden, got %v", err)
	}
	allowed, err := New(Deps{SPs: sps, Groups: groups, Access: stubAccess{allow: map[uuid.UUID]bool{appID: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allowed.Evaluate(context.Background(), testUser(), testRequest()); err != nil {
		t.Fatalf("allowed binding must pass: %v", err)
	}
	_ = svc
}
