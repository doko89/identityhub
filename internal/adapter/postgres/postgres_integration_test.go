//go:build integration

// Integration tests against a real Postgres (TECH_SPEC §9). Run with:
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/identityhub_test \
//	  go test -tags=integration ./internal/adapter/postgres/
package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := MigrateUp(ctx, url); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	db, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestMigrationSeedsAdminGroup(t *testing.T) {
	db := testDB(t)
	groups := NewGroupRepository(db)
	g, err := groups.ByName(context.Background(), domain.AdminGroup)
	if err != nil {
		t.Fatalf("ih_admin seed missing: %v", err)
	}
	if g.Name != domain.AdminGroup {
		t.Fatalf("seed group name = %q", g.Name)
	}
	// The DB trigger must refuse deleting the reserved group even on raw SQL.
	_, err = db.Pool.Exec(context.Background(), `DELETE FROM groups WHERE name='ih_admin'`)
	if err == nil {
		t.Fatal("raw DELETE of ih_admin succeeded, want trigger refusal")
	}
	// Repository-level guard.
	if err := groups.Delete(context.Background(), g.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("Delete(ih_admin) = %v, want ErrForbidden", err)
	}
	var brandingCount int
	if err := db.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM branding WHERE id=1`).Scan(&brandingCount); err != nil {
		t.Fatalf("branding seed query: %v", err)
	}
	if brandingCount != 1 {
		t.Fatalf("branding(id=1) rows = %d, want 1", brandingCount)
	}
}

func TestUserLifecycle(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := NewUserRepository(db)
	groups := NewGroupRepository(db)

	username := "it-user-" + uuid.NewString()[:8]
	u, err := users.Create(ctx, domain.User{
		Username: username, Email: username + "@example.com", DisplayName: "IT User",
		PasswordHash: []byte("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"),
		Source:       domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID)
	})

	if _, err := users.Create(ctx, domain.User{Username: username, Source: domain.SourceLocal, PasswordHash: []byte("x")}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
	got, err := users.ByUsername(ctx, username)
	if err != nil || got.ID != u.ID {
		t.Fatalf("ByUsername: %v / %+v", err, got)
	}
	if _, err := users.ByUsername(ctx, "no-such-user"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("ByUsername(missing) = %v, want ErrNotFound", err)
	}

	admin, err := groups.ByName(ctx, domain.AdminGroup)
	if err != nil {
		t.Fatalf("ByName(ih_admin): %v", err)
	}
	if err := groups.AddMember(ctx, u.ID, admin.ID); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	member, err := groups.IsMember(ctx, u.ID, domain.AdminGroup)
	if err != nil || !member {
		t.Fatalf("IsMember = %v, %v; want true, nil", member, err)
	}
	if err := groups.RemoveMember(ctx, u.ID, admin.ID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if member, _ := groups.IsMember(ctx, u.ID, domain.AdminGroup); member {
		t.Fatal("IsMember after remove = true, want false")
	}
}

func TestSessionsTablePresent(t *testing.T) {
	db := testDB(t)
	var exists bool
	err := db.Pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='sessions')`).Scan(&exists)
	if err != nil || !exists {
		t.Fatalf("sessions table exists = %v, err = %v", exists, err)
	}
}
