package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
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

// pagedStore honors Limit/Offset like the postgres repository.
type pagedStore struct {
	entries []domain.AuditEntry
	got     domain.AuditFilter
}

func (f *pagedStore) Append(_ context.Context, e domain.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

func (f *pagedStore) List(_ context.Context, flt domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	f.got = flt
	start := flt.Offset
	if start > len(f.entries) {
		start = len(f.entries)
	}
	end := start + flt.Limit
	if flt.Limit <= 0 || end > len(f.entries) {
		end = len(f.entries)
	}
	return f.entries[start:end], len(f.entries), nil
}

func TestExportCSVShapeAndQuoting(t *testing.T) {
	actor, app := uuid.New(), uuid.New()
	at := time.Date(2026, 11, 17, 12, 30, 0, 0, time.UTC)
	store := &pagedStore{entries: []domain.AuditEntry{
		{
			ID: 7, At: at, ActorUserID: &actor, ApplicationID: &app,
			Method: domain.MethodPassword, Result: domain.ResultSuccess,
			IP:     "10.0.0.1",
			Detail: map[string]any{"action": "login", "note": "comma, quote\" and\nnewline"},
		},
		{ID: 8, At: at, Method: domain.MethodTOTP, Result: domain.ResultFailure},
	}}
	svc := New(store, fixedClock{now: time.Now()})
	var buf strings.Builder
	n, err := svc.ExportCSV(context.Background(), domain.AuditFilter{Limit: 1, Offset: 99}, &buf)
	if err != nil {
		t.Fatalf("ExportCSV = %v", err)
	}
	if n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	if store.got.Limit != MaxExportRows || store.got.Offset != 0 {
		t.Fatalf("filter = %+v, want Limit=%d Offset=0", store.got, MaxExportRows)
	}
	// The output must round-trip through a strict CSV parser.
	recs, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v\n%s", err, buf.String())
	}
	if len(recs) != 3 {
		t.Fatalf("records = %d, want header + 2 rows", len(recs))
	}
	wantHeader := []string{"id", "at", "actor_user_id", "application_id", "method", "result", "ip", "detail"}
	for i, h := range wantHeader {
		if recs[0][i] != h {
			t.Fatalf("header[%d] = %q, want %q", i, recs[0][i], h)
		}
	}
	if recs[1][0] != "7" || recs[1][1] != "2026-11-17T12:30:00Z" ||
		recs[1][2] != actor.String() || recs[1][3] != app.String() ||
		recs[1][4] != domain.MethodPassword || recs[1][5] != domain.ResultSuccess ||
		recs[1][6] != "10.0.0.1" {
		t.Fatalf("row 1 = %v", recs[1])
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(recs[1][7]), &detail); err != nil {
		t.Fatalf("detail is not JSON: %v", err)
	}
	if detail["note"] != "comma, quote\" and\nnewline" {
		t.Fatalf("Detail note = %v", detail["note"])
	}
	if recs[2][2] != "" || recs[2][3] != "" || recs[2][7] != "{}" {
		t.Fatalf("empty row 2 = %v, want blank ids and {} detail", recs[2])
	}
}

func TestExportCSVEmpty(t *testing.T) {
	svc := New(&pagedStore{}, fixedClock{now: time.Now()})
	var buf strings.Builder
	n, err := svc.ExportCSV(context.Background(), domain.AuditFilter{}, &buf)
	if err != nil {
		t.Fatalf("ExportCSV = %v", err)
	}
	if n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
	if !strings.HasPrefix(buf.String(), "id,at,actor_user_id,application_id,method,result,ip,detail") {
		t.Fatalf("missing header-only output: %q", buf.String())
	}
}
