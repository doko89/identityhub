package apikey

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

// ---------- fakes ----------

type fakeKeys struct {
	byID      map[uuid.UUID]domain.APIKey
	listErr   error
	createErr error
	byHashErr error
	revokeErr error
	touchErr  error
	touched   []uuid.UUID
}

func newFakeKeys(ks ...domain.APIKey) *fakeKeys {
	f := &fakeKeys{byID: map[uuid.UUID]domain.APIKey{}}
	for _, k := range ks {
		f.byID[k.ID] = k
	}
	return f
}

func (f *fakeKeys) Create(_ context.Context, k domain.APIKey) (domain.APIKey, error) {
	if f.createErr != nil {
		return domain.APIKey{}, f.createErr
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	f.byID[k.ID] = k
	return k, nil
}

func (f *fakeKeys) ByHash(_ context.Context, hash []byte) (domain.APIKey, error) {
	if f.byHashErr != nil {
		return domain.APIKey{}, f.byHashErr
	}
	for _, k := range f.byID {
		if string(k.KeyHash) == string(hash) {
			return k, nil
		}
	}
	return domain.APIKey{}, domain.ErrNotFound
}

func (f *fakeKeys) ListByUser(_ context.Context, userID uuid.UUID) ([]domain.APIKey, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []domain.APIKey
	for _, k := range f.byID {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeKeys) Revoke(_ context.Context, userID, id uuid.UUID, at time.Time) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	k, ok := f.byID[id]
	if !ok || k.UserID != userID || k.RevokedAt != nil {
		return domain.ErrNotFound
	}
	k.RevokedAt = &at
	f.byID[id] = k
	return nil
}

func (f *fakeKeys) TouchLastUsed(_ context.Context, id uuid.UUID, at time.Time) error {
	if f.touchErr != nil {
		return f.touchErr
	}
	k, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	k.LastUsedAt = &at
	f.byID[id] = k
	f.touched = append(f.touched, id)
	return nil
}

type fakeAudit struct {
	entries []domain.AuditEntry
}

func (f *fakeAudit) Append(_ context.Context, e domain.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeAudit) List(_ context.Context, _ domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	return f.entries, len(f.entries), nil
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

var testNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func testService(f *fakeKeys, a *fakeAudit) *Service {
	s, err := New(Deps{Keys: f, Audit: audit.New(a, fixedClock{testNow}), Clock: fixedClock{testNow}})
	if err != nil {
		panic(err)
	}
	return s
}

// ---------- New ----------

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("want error for nil deps")
	}
	if _, err := New(Deps{Keys: newFakeKeys()}); err == nil {
		t.Fatal("want error for nil audit")
	}
	if _, err := New(Deps{Audit: audit.New(&fakeAudit{}, nil)}); err == nil {
		t.Fatal("want error for nil keys")
	}
	if _, err := New(Deps{Keys: newFakeKeys(), Audit: audit.New(&fakeAudit{}, nil)}); err != nil {
		t.Fatalf("clock defaults: %v", err)
	}
}

// ---------- Create ----------

func TestCreate(t *testing.T) {
	ctx := context.Background()
	uid := uuid.New()
	f, a := newFakeKeys(), &fakeAudit{}
	s := testService(f, a)

	expiry := testNow.Add(24 * time.Hour)
	k, secret, err := s.Create(ctx, uid, "laptop", &expiry, true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(secret) != secretLength || !strings.HasPrefix(secret, SecretPrefix) {
		t.Fatalf("bad secret shape %q", secret)
	}
	if k.Prefix != secret[:prefixChars] {
		t.Fatalf("prefix %q does not match secret", k.Prefix)
	}
	if len(k.KeyHash) != 32 {
		t.Fatalf("hash is %d bytes, want 32", len(k.KeyHash))
	}
	if !k.CreatedWithMFA || k.ExpiresAt == nil || !k.ExpiresAt.Equal(expiry) {
		t.Fatalf("flags/expiry not stored: %+v", k)
	}
	if len(a.entries) != 1 || a.entries[0].Detail["action"] != audit.ActionAPIKeyCreate {
		t.Fatalf("create not audited: %+v", a.entries)
	}

	if _, _, err := s.Create(ctx, uid, "  ", nil, false); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("blank name: want validation, got %v", err)
	}
	if _, _, err := s.Create(ctx, uid, strings.Repeat("n", MaxNameLength+1), nil, false); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("long name: want validation, got %v", err)
	}
	past := testNow.Add(-time.Hour)
	if _, _, err := s.Create(ctx, uid, "x", &past, false); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("past expiry: want validation, got %v", err)
	}
	far := testNow.AddDate(0, 0, MaxExpiryDays+1)
	if _, _, err := s.Create(ctx, uid, "x", &far, false); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("far expiry: want validation, got %v", err)
	}
}

func TestCreateCapCountsActiveOnly(t *testing.T) {
	ctx := context.Background()
	uid := uuid.New()
	revokedAt := testNow.Add(-time.Hour)
	expiredAt := testNow.Add(-time.Hour)
	f := newFakeKeys(
		domain.APIKey{ID: uuid.New(), UserID: uid, RevokedAt: &revokedAt},
		domain.APIKey{ID: uuid.New(), UserID: uid, ExpiresAt: &expiredAt},
	)
	for range MaxKeysPerUser {
		f.byID[uuid.New()] = domain.APIKey{ID: uuid.New(), UserID: uid}
	}
	s := testService(f, &fakeAudit{})
	// Full: revoked + expired rows do not count, active ones do.
	if _, _, err := s.Create(ctx, uid, "one more", nil, false); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("over cap: want validation, got %v", err)
	}
	delete(f.byID, pickActive(t, f))
	if _, _, err := s.Create(ctx, uid, "fits", nil, false); err != nil {
		t.Fatalf("under cap: %v", err)
	}
}

func pickActive(t *testing.T, f *fakeKeys) uuid.UUID {
	t.Helper()
	for id, k := range f.byID {
		if k.Active(testNow) {
			return id
		}
	}
	t.Fatal("no active key")
	return uuid.Nil
}

func TestCreateStoreErrors(t *testing.T) {
	ctx := context.Background()
	uid := uuid.New()
	boom := errors.New("boom")

	f := newFakeKeys()
	f.listErr = boom
	if _, _, err := testService(f, &fakeAudit{}).Create(ctx, uid, "x", nil, false); !errors.Is(err, boom) {
		t.Fatalf("list error: want boom, got %v", err)
	}
	f = newFakeKeys()
	f.createErr = boom
	if _, _, err := testService(f, &fakeAudit{}).Create(ctx, uid, "x", nil, false); !errors.Is(err, boom) {
		t.Fatalf("create error: want boom, got %v", err)
	}
}

// ---------- List / Revoke ----------

func TestList(t *testing.T) {
	ctx := context.Background()
	uid, other := uuid.New(), uuid.New()
	f := newFakeKeys(
		domain.APIKey{ID: uuid.New(), UserID: uid, Name: "a"},
		domain.APIKey{ID: uuid.New(), UserID: other, Name: "b"},
	)
	got, err := testService(f, &fakeAudit{}).List(ctx, uid)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("List leaked other owner: %+v", got)
	}
	f.listErr = errors.New("boom")
	if _, err := testService(f, &fakeAudit{}).List(ctx, uid); err == nil {
		t.Fatal("want list error")
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	uid, other := uuid.New(), uuid.New()
	mine, theirs := uuid.New(), uuid.New()
	f := newFakeKeys(
		domain.APIKey{ID: mine, UserID: uid},
		domain.APIKey{ID: theirs, UserID: other},
	)
	a := &fakeAudit{}
	s := testService(f, a)

	if err := s.Revoke(ctx, uid, mine); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if f.byID[mine].RevokedAt == nil {
		t.Fatal("revoked_at not stamped")
	}
	if len(a.entries) != 1 || a.entries[0].Detail["action"] != audit.ActionAPIKeyRevoke {
		t.Fatalf("revoke not audited: %+v", a.entries)
	}
	if err := s.Revoke(ctx, uid, theirs); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("other owner: want not found, got %v", err)
	}
	if err := s.Revoke(ctx, uid, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown id: want not found, got %v", err)
	}
	f.revokeErr = errors.New("boom")
	if err := s.Revoke(ctx, uid, mine); err == nil {
		t.Fatal("want store error")
	}
}

// ---------- Authenticate ----------

func mint(t *testing.T, s *Service, uid uuid.UUID) (domain.APIKey, string) {
	t.Helper()
	k, secret, err := s.Create(context.Background(), uid, "cli", nil, false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return k, secret
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	uid := uuid.New()
	f := newFakeKeys()
	s := testService(f, &fakeAudit{})
	k, secret := mint(t, s, uid)

	got, err := s.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != k.ID {
		t.Fatalf("wrong key: %v", got.ID)
	}
	if len(f.touched) != 1 || f.touched[0] != k.ID {
		t.Fatalf("last use not touched: %v", f.touched)
	}

	// A failing stats write never fails authentication.
	f.touchErr = errors.New("boom")
	if _, err := s.Authenticate(ctx, secret); err != nil {
		t.Fatalf("touch error must not fail auth: %v", err)
	}
	f.touchErr = nil

	for name, bad := range map[string]string{
		"empty":        "",
		"short":        "ih_abc",
		"wrong prefix": "xx_" + strings.Repeat("A", 43),
		"bad charset":  SecretPrefix + strings.Repeat("!", 43),
		"unknown":      SecretPrefix + strings.Repeat("A", 43),
	} {
		if _, err := s.Authenticate(ctx, bad); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("%s: want unauthorized, got %v", name, err)
		}
	}

	// Revoked and expired keys stop authenticating.
	revoked := f.byID[k.ID]
	revoked.RevokedAt = &testNow
	f.byID[k.ID] = revoked
	if _, err := s.Authenticate(ctx, secret); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("revoked: want unauthorized, got %v", err)
	}
	expired := testNow.Add(-time.Hour)
	revoked.RevokedAt = nil
	revoked.ExpiresAt = &expired
	f.byID[k.ID] = revoked
	if _, err := s.Authenticate(ctx, secret); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expired: want unauthorized, got %v", err)
	}

	f.byHashErr = errors.New("boom")
	if _, err := s.Authenticate(ctx, secret); err == nil || errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("store error must surface, got %v", err)
	}
}
