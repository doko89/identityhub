//go:build integration

package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/worker"
)

// isolatedDB creates a scratch database for version assertions: other
// integration packages bump the shared test database concurrently, so
// exact deltas are only meaningful in isolation.
func isolatedDB(t *testing.T) *DB {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		base = os.Getenv("DATABASE_URL")
	}
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	name := "ver_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	admin := *u
	admin.Path = "/postgres"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, admin.String())
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", name)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(c, admin.String())
		if err != nil {
			return
		}
		defer conn.Close(c)
		_, _ = conn.Exec(c, fmt.Sprintf("DROP DATABASE %s WITH (FORCE)", name))
	})
	u.Path = "/" + name
	if err := MigrateUp(ctx, u.String()); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	db, err := Open(ctx, u.String())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestDirectoryVersionBumps(t *testing.T) {
	db := isolatedDB(t)
	ctx := context.Background()
	users := NewUserRepository(db)
	groups := NewGroupRepository(db)
	mfa := NewMFARepository(db)
	versions := NewDirectoryVersionRepository(db)

	before, err := versions.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if before < 1 {
		t.Fatalf("version = %d, want >= 1", before)
	}
	bumped := func(what string, n int64) {
		t.Helper()
		after, err := versions.Current(ctx)
		if err != nil {
			t.Fatalf("Current: %v", err)
		}
		if after-before != n {
			t.Fatalf("%s moved version by %d, want %d", what, after-before, n)
		}
		before = after
	}

	u, err := users.Create(ctx, domain.User{
		Username: "ver-u-" + uuid.NewString()[:8], Email: "v@example.com",
		PasswordHash: []byte("hash"), Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	bumped("user create", 1)

	u.DisplayName = "Version"
	if _, err := users.Update(ctx, u); err != nil {
		t.Fatalf("update user: %v", err)
	}
	bumped("user update", 1)

	if err := users.SetPasswordHash(ctx, u.ID, []byte("hash2")); err != nil {
		t.Fatalf("set hash: %v", err)
	}
	bumped("password change", 1)

	g, err := groups.Create(ctx, domain.Group{Name: "ver-g-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	bumped("group create", 1)

	if err := groups.AddMember(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	bumped("add member", 1)

	// Idempotent re-adds change no rows and skip the bump.
	if err := groups.AddMember(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("re-add member: %v", err)
	}
	bumped("no-op re-add", 0)

	if err := groups.RemoveMember(ctx, u.ID, g.ID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	bumped("remove member", 1)

	if err := mfa.EnrollTOTP(ctx, domain.TOTPCredential{UserID: u.ID, SeedEnc: []byte("sealed")}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	bumped("mfa enroll", 1)

	if err := mfa.DisableTOTP(ctx, u.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	bumped("mfa disable", 1)
}

func TestCleanupOldAudit(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	audits := NewAuditRepository(db)

	old := domain.AuditEntry{At: time.Now().UTC().Add(-100 * 24 * time.Hour), Method: domain.MethodPassword, Result: domain.ResultSuccess}
	fresh := domain.AuditEntry{At: time.Now().UTC(), Method: domain.MethodPassword, Result: domain.ResultSuccess}
	if err := audits.Append(ctx, old); err != nil {
		t.Fatalf("append old: %v", err)
	}
	if err := audits.Append(ctx, fresh); err != nil {
		t.Fatalf("append fresh: %v", err)
	}
	n, err := worker.CleanupOldAudit(ctx, db.Pool, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("CleanupOldAudit: %v", err)
	}
	if n < 1 {
		t.Fatalf("deleted = %d, want >= 1", n)
	}
	var remaining int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log WHERE at > now() - interval '1 hour'`).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining < 1 {
		t.Fatal("fresh row deleted, want it kept")
	}
	if n, err := worker.CleanupOldAudit(ctx, db.Pool, 0); err != nil || n != 0 {
		t.Fatalf("disabled retention = %d, %v; want 0, nil", n, err)
	}
}
