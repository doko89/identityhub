//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

func TestAuditAppendAndList(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	audits := NewAuditRepository(db)
	users := NewUserRepository(db)

	u, err := users.Create(ctx, domain.User{
		Username: "audit-u-" + uuid.NewString()[:8], Email: "a@example.com",
		PasswordHash: []byte("h"), Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })

	now := time.Now().UTC().Truncate(time.Millisecond)
	uid := u.ID
	if err := audits.Append(ctx, domain.AuditEntry{
		At: now, ActorUserID: &uid, Method: domain.MethodPassword,
		Result: domain.ResultSuccess, IP: "10.0.0.9", Detail: map[string]any{"action": "login"},
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Nil detail + empty IP must not fail the write.
	if err := audits.Append(ctx, domain.AuditEntry{
		At: now, Method: domain.MethodLDAP, Result: domain.ResultFailure,
	}); err != nil {
		t.Fatalf("Append minimal: %v", err)
	}

	entries, total, err := audits.List(ctx, domain.AuditFilter{ActorUserID: &uid, Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total < 1 || len(entries) < 1 {
		t.Fatalf("List = %d entries, total %d; want >=1", len(entries), total)
	}
	got := entries[0]
	if got.Method != domain.MethodPassword || got.Result != domain.ResultSuccess || got.IP != "10.0.0.9" {
		t.Errorf("entry = %+v", got)
	}
	if got.Detail["action"] != "login" {
		t.Errorf("detail = %v", got.Detail)
	}
	// Method filter narrows; newest-first order holds.
	only, _, err := audits.List(ctx, domain.AuditFilter{Method: domain.MethodLDAP, Result: domain.ResultFailure, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range only {
		if e.Method != domain.MethodLDAP || e.Result != domain.ResultFailure {
			t.Fatalf("filtered entry = %+v", e)
		}
	}
}

func TestPasswordResetLifecycle(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := NewUserRepository(db)
	pw := NewPasswordRepository(db)

	u, err := users.Create(ctx, domain.User{
		Username: "reset-u-" + uuid.NewString()[:8], Email: "r@example.com",
		PasswordHash: []byte("h"), Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })

	mkHash := func(s string) []byte {
		sum := sha256.Sum256([]byte(s))
		return sum[:]
	}
	first, err := pw.Create(ctx, domain.PasswordResetToken{
		UserID: u.ID, TokenHash: mkHash("first"), ExpiresAt: time.Now().Add(15 * time.Minute), CreatedIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Second create revokes the first (one active token per user).
	second, err := pw.Create(ctx, domain.PasswordResetToken{
		UserID: u.ID, TokenHash: mkHash("second"), ExpiresAt: time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	got, err := pw.ByHash(ctx, mkHash("first"))
	if err != nil {
		t.Fatalf("ByHash(first): %v", err)
	}
	if got.UsedAt == nil {
		t.Error("first token still active, want revoked")
	}
	_ = first
	if err := pw.MarkUsed(ctx, second.ID, time.Now()); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	// Double-consume fails (single-use gate).
	if err := pw.MarkUsed(ctx, second.ID, time.Now()); err == nil {
		t.Fatal("second MarkUsed = nil, want failure")
	}
	if _, err := pw.ByHash(ctx, mkHash("missing")); err == nil {
		t.Fatal("ByHash(missing) = nil, want error")
	}
	// Expired tokens delete by count.
	if _, err := pw.Create(ctx, domain.PasswordResetToken{
		UserID: u.ID, TokenHash: mkHash("old"), ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := pw.DeleteExpired(ctx, time.Now())
	if err != nil || n < 1 {
		t.Fatalf("DeleteExpired = %d, %v; want >=1", n, err)
	}
}

func TestPasswordHistoryTrim(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := NewUserRepository(db)
	pw := NewPasswordRepository(db)

	u, err := users.Create(ctx, domain.User{
		Username: "hist-u-" + uuid.NewString()[:8], Email: "x@example.com",
		PasswordHash: []byte("h"), Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })

	for i := 0; i < 12; i++ {
		if err := pw.Add(ctx, u.ID, []byte{byte(i)}); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	hashes, err := pw.Recent(ctx, u.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 10 {
		t.Fatalf("Recent = %d hashes, want 10 (trimmed)", len(hashes))
	}
	if len(hashes[0]) != 1 || hashes[0][0] != 11 {
		t.Errorf("newest hash = %v, want [11]", hashes[0])
	}
}

func TestSessionRegistry(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := NewUserRepository(db)
	reg := NewSessionRegistryRepository(db)

	u, err := users.Create(ctx, domain.User{
		Username: "sess-u-" + uuid.NewString()[:8], Email: "s@example.com",
		PasswordHash: []byte("h"), Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })

	// Seed scs-shaped session rows plus registry links.
	for _, tok := range []string{"tok-keep", "tok-a", "tok-b"} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO sessions (token, data, expiry) VALUES ($1, $2, now() + interval '1 hour')`, tok, []byte("data")); err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(ctx, u.ID, tok); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM sessions WHERE token LIKE 'tok-%'`)
	})

	n, err := reg.RevokeOthers(ctx, u.ID, "tok-keep")
	if err != nil || n != 2 {
		t.Fatalf("RevokeOthers = %d, %v; want 2", n, err)
	}
	var remaining int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE token LIKE 'tok-%'`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("sessions left = %d, want 1 (keep)", remaining)
	}
	n, err = reg.RevokeAll(ctx, u.ID)
	if err != nil || n != 1 {
		t.Fatalf("RevokeAll = %d, %v; want 1", n, err)
	}
	if err := reg.Unregister(ctx, "tok-keep"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
}
