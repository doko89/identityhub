package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

type fakeAttrs struct {
	defs []domain.UserAttrDef
	err  error
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

func (f *fakeAttrs) ValuesOfUser(_ context.Context, _ uuid.UUID) (map[string][]string, error) {
	return map[string][]string{}, nil
}

func (f *fakeAttrs) ValuesForUsers(_ context.Context, _ []uuid.UUID) (map[uuid.UUID]map[string][]string, error) {
	return map[uuid.UUID]map[string][]string{}, nil
}

func discoveryClaims(t *testing.T, p *Provider) []any {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	p.HandleDiscovery(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", rec.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery is not JSON: %v", err)
	}
	claims, _ := doc["claims_supported"].([]any)
	return claims
}

func TestDiscoveryListsCustomClaims(t *testing.T) {
	p := &Provider{issuer: "https://idp.example.com", attrs: &fakeAttrs{
		defs: []domain.UserAttrDef{{Key: "dept"}, {Key: "level"}},
	}}
	claims := discoveryClaims(t, p)
	want := len(baseClaimsSupported) + 2
	if len(claims) != want || claims[want-2] != "dept" || claims[want-1] != "level" {
		t.Fatalf("claims_supported = %v", claims)
	}
}

func TestDiscoveryDegradesWithoutAttrs(t *testing.T) {
	for name, p := range map[string]*Provider{
		"nil store":   {issuer: "https://idp.example.com"},
		"store error": {issuer: "https://idp.example.com", attrs: &fakeAttrs{err: context.DeadlineExceeded}},
	} {
		if claims := discoveryClaims(t, p); len(claims) != len(baseClaimsSupported) {
			t.Errorf("%s: claims_supported = %v, want static list", name, claims)
		}
	}
}

func TestNewSessionCustomClaims(t *testing.T) {
	p := &Provider{kid: "test-kid"}
	s := p.newSession(domain.OIDCDecision{
		Subject: "sub-1", Username: "alice", Email: "alice@example.com",
		Name: "Alice", Groups: []string{"eng"},
		CustomAttrs: map[string]any{"dept": "it", "level": 3.0},
	})
	extra := s.IDTokenClaims().Extra
	if extra["dept"] != "it" || extra["level"] != 3.0 {
		t.Errorf("custom claims = %v", extra)
	}
	if extra["preferred_username"] != "alice" || extra["email"] != "alice@example.com" {
		t.Errorf("built-in claims = %v", extra)
	}
	// Built-ins win on collision.
	s = p.newSession(domain.OIDCDecision{
		Subject: "sub-1", Username: "alice", Email: "alice@example.com",
		Name:        "Alice",
		CustomAttrs: map[string]any{"email": "evil@example.com"},
	})
	if s.IDTokenClaims().Extra["email"] != "alice@example.com" {
		t.Errorf("collision claim = %v, want built-in to win", s.IDTokenClaims().Extra)
	}
}
