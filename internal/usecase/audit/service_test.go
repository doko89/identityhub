package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

type fakeStore struct {
	entries []domain.AuditEntry
	err     error
}

func (f *fakeStore) Append(_ context.Context, e domain.AuditEntry) error {
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeStore) List(_ context.Context, _ domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	return f.entries, len(f.entries), f.err
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestRecordStampsAndDefaults(t *testing.T) {
	store := &fakeStore{}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	svc := New(store, fixedClock{now: now})

	user := uuid.New()
	if err := svc.Record(context.Background(), domain.AuditEntry{
		ActorUserID: &user, Method: domain.MethodPassword, Result: domain.ResultSuccess, IP: "10.0.0.1",
	}); err != nil {
		t.Fatalf("Record = %v", err)
	}
	if len(store.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(store.entries))
	}
	got := store.entries[0]
	if !got.At.Equal(now) {
		t.Errorf("At = %v, want %v", got.At, now)
	}
	if got.Detail == nil {
		t.Error("Detail = nil, want empty map")
	}
}

func TestRecordKeepsExplicitAt(t *testing.T) {
	store := &fakeStore{}
	svc := New(store, fixedClock{now: time.Now()})
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := svc.Record(context.Background(), domain.AuditEntry{
		At: at, Method: domain.MethodLDAP, Result: domain.ResultFailure,
	}); err != nil {
		t.Fatal(err)
	}
	if !store.entries[0].At.Equal(at) {
		t.Errorf("At = %v, want %v", store.entries[0].At, at)
	}
}

func TestRecordValidation(t *testing.T) {
	svc := New(&fakeStore{}, fixedClock{now: time.Now()})
	for _, e := range []domain.AuditEntry{
		{Result: domain.ResultSuccess},                   // no method
		{Method: domain.MethodPassword},                  // no result
		{Method: domain.MethodPassword, Result: "maybe"}, // bad result
	} {
		if err := svc.Record(context.Background(), e); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("Record(%+v) = %v, want ErrValidation", e, err)
		}
	}
}

func TestRecordPropagatesStoreError(t *testing.T) {
	svc := New(&fakeStore{err: errors.New("db down")}, fixedClock{now: time.Now()})
	err := svc.Record(context.Background(), domain.AuditEntry{Method: domain.MethodPassword, Result: domain.ResultSuccess})
	if err == nil || err.Error() != "db down" {
		t.Errorf("Record = %v, want store error", err)
	}
}

func TestNilClockDefaults(t *testing.T) {
	store := &fakeStore{}
	svc := New(store, nil)
	before := time.Now()
	if err := svc.Record(context.Background(), domain.AuditEntry{Method: domain.MethodPassword, Result: domain.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if store.entries[0].At.Before(before) {
		t.Errorf("At = %v, want >= %v", store.entries[0].At, before)
	}
}

func TestList(t *testing.T) {
	store := &fakeStore{entries: []domain.AuditEntry{{Method: domain.MethodPassword, Result: domain.ResultSuccess}}}
	svc := New(store, fixedClock{now: time.Now()})
	got, total, err := svc.List(context.Background(), domain.AuditFilter{Method: domain.MethodPassword})
	if err != nil || total != 1 || len(got) != 1 {
		t.Fatalf("List = %v, %d, %v", got, total, err)
	}
}
