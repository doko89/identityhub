package branding

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

type stubStore struct {
	brand   domain.Branding
	gets    int
	updates int
	getErr  error
}

func (s *stubStore) Get(_ context.Context) (domain.Branding, error) {
	s.gets++
	if s.getErr != nil {
		return domain.Branding{}, s.getErr
	}
	return s.brand, nil
}

func (s *stubStore) Update(_ context.Context, b domain.Branding) (domain.Branding, error) {
	s.updates++
	if err := b.Validate(); err != nil {
		return domain.Branding{}, err
	}
	s.brand = b
	return b, nil
}

type stubAudit struct{ records int }

func (s *stubAudit) Append(_ context.Context, _ domain.AuditEntry) error {
	s.records++
	return nil
}

func (s *stubAudit) List(_ context.Context, _ domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	return nil, 0, nil
}

func testService(store *stubStore) *Service {
	audits := audit.New(&stubAudit{}, nil)
	svc, err := New(Deps{Store: store, Audit: audits})
	if err != nil {
		panic(err)
	}
	return svc
}

func TestNewRequiresDeps(t *testing.T) {
	audits := audit.New(&stubAudit{}, nil)
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New with nil deps must fail")
	}
	if _, err := New(Deps{Store: &stubStore{}}); err == nil {
		t.Fatal("New without Audit must fail")
	}
	if _, err := New(Deps{Audit: audits}); err == nil {
		t.Fatal("New without Store must fail")
	}
}

func TestGetCaches(t *testing.T) {
	store := &stubStore{brand: domain.Branding{ID: 1, OrgName: "Acme", Theme: domain.ThemeSystem}}
	svc := testService(store)
	ctx := context.Background()

	first, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	second, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if first.OrgName != "Acme" || second.OrgName != "Acme" {
		t.Fatalf("unexpected brands: %+v %+v", first, second)
	}
	if store.gets != 1 {
		t.Fatalf("expected 1 store read, got %d", store.gets)
	}
}

func TestGetFailureIsNotCached(t *testing.T) {
	store := &stubStore{getErr: errors.New("db down")}
	svc := testService(store)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err == nil {
		t.Fatal("Get must surface the store error")
	}
	store.getErr = nil
	store.brand = domain.Branding{ID: 1, OrgName: "Back"}
	if b, err := svc.Get(ctx); err != nil || b.OrgName != "Back" {
		t.Fatalf("retry after failure: brand=%+v err=%v", b, err)
	}
	if store.gets != 2 {
		t.Fatalf("expected 2 store reads, got %d", store.gets)
	}
}

func TestInvalidateReloads(t *testing.T) {
	store := &stubStore{brand: domain.Branding{ID: 1, OrgName: "One"}}
	svc := testService(store)
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("Get: %v", err)
	}
	store.brand.OrgName = "Two" // out-of-band change
	svc.Invalidate()
	b, err := svc.Get(ctx)
	if err != nil || b.OrgName != "Two" {
		t.Fatalf("after Invalidate: brand=%+v err=%v", b, err)
	}
}

func TestUpdateRefreshesCacheAndAudits(t *testing.T) {
	inner := &stubAudit{}
	audits := audit.New(inner, nil)
	store := &stubStore{brand: domain.Branding{ID: 1, OrgName: "Old"}}
	svc, err := New(Deps{Store: store, Audit: audits})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if _, err := svc.Get(ctx); err != nil {
		t.Fatalf("Get: %v", err)
	}
	actor := uuid.New()
	out, err := svc.Update(ctx, actor, domain.Branding{
		ID: 99, OrgName: "New", PrimaryColor: "#4f46e5", Theme: domain.ThemeDark,
		CustomCSS: ".login { color: red; }",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if out.ID != domain.BrandingID {
		t.Fatalf("Update must force id=1, got %d", out.ID)
	}
	if inner.records != 1 {
		t.Fatalf("expected 1 audit record, got %d", inner.records)
	}
	// The cached copy is the new brand: no further store read.
	got, err := svc.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OrgName != "New" || store.gets != 1 || store.updates != 1 {
		t.Fatalf("cache not refreshed: %+v gets=%d updates=%d", got, store.gets, store.updates)
	}
}

func TestUpdateRejectsBadInput(t *testing.T) {
	cases := []struct {
		name  string
		brand domain.Branding
	}{
		{"bad color", domain.Branding{PrimaryColor: "red"}},
		{"long tagline", domain.Branding{Tagline: strings.Repeat("a", 201)}},
		{"short hex", domain.Branding{PrimaryColor: "#fff"}},
		{"unknown theme", domain.Branding{Theme: "neon"}},
		{"css import", domain.Branding{CustomCSS: `@import url(evil);`}},
		{"css url", domain.Branding{CustomCSS: `.a{background:url(http://x/y.png)}`}},
		{"css style break", domain.Branding{CustomCSS: `a{}</STYLE><script>`}},
		{"css too large", domain.Branding{CustomCSS: strings.Repeat("a", 10*1024+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &stubStore{brand: domain.Branding{ID: 1, OrgName: "Old"}}
			svc := testService(store)
			if _, err := svc.Update(context.Background(), uuid.New(), tc.brand); !errors.Is(err, domain.ErrValidation) {
				t.Fatalf("Update(%s) err = %v, want validation failure", tc.name, err)
			}
			if store.updates != 0 {
				t.Fatalf("Update(%s) must not reach the store", tc.name)
			}
		})
	}
}
