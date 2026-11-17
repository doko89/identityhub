package samlflow

import (
	"context"
	"errors"
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

func (f *fakeGroups) Delete(_ context.Context, _ uuid.UUID) error { return nil }

func (f *fakeGroups) AddMember(_ context.Context, _, _ uuid.UUID) error { return nil }

func (f *fakeGroups) RemoveMember(_ context.Context, _, _ uuid.UUID) error { return nil }

func (f *fakeGroups) MemberIDs(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
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
