//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

func TestAPIKeyRepository(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	users := NewUserRepository(db)
	repo := NewAPIKeyRepository(db)

	owner, err := users.Create(ctx, domain.User{
		Username: "key-owner-" + uuid.NewString()[:8], Email: "owner@example.com", PasswordHash: []byte("hash"),
		Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	other, err := users.Create(ctx, domain.User{
		Username: "key-stranger-" + uuid.NewString()[:8], Email: "stranger@example.com", PasswordHash: []byte("hash"),
		Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatalf("create stranger: %v", err)
	}

	sum := sha256.Sum256([]byte("secret-" + uuid.NewString()))
	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	created, err := repo.Create(ctx, domain.APIKey{
		UserID: owner.ID, Name: "cli", Prefix: "ih_testprefix",
		KeyHash: sum[:], CreatedWithMFA: true, ExpiresAt: &expiry,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == uuid.Nil || created.CreatedAt.IsZero() {
		t.Fatalf("Create did not fill id/created_at: %+v", created)
	}
	if !created.CreatedWithMFA || created.ExpiresAt == nil || !created.ExpiresAt.Equal(expiry) {
		t.Fatalf("flags not round-tripped: %+v", created)
	}

	byHash, err := repo.ByHash(ctx, sum[:])
	if err != nil {
		t.Fatalf("ByHash: %v", err)
	}
	if byHash.ID != created.ID {
		t.Fatalf("ByHash id = %v, want %v", byHash.ID, created.ID)
	}
	missing := sha256.Sum256([]byte("nope"))
	if _, err := repo.ByHash(ctx, missing[:]); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("ByHash unknown = %v, want ErrNotFound", err)
	}

	listed, err := repo.ListByUser(ctx, owner.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("ListByUser = %+v, want one key", listed)
	}
	if listed, err := repo.ListByUser(ctx, other.ID); err != nil || len(listed) != 0 {
		t.Fatalf("ListByUser(stranger) = %v, %v, want empty", listed, err)
	}

	now := time.Now().UTC()
	if err := repo.TouchLastUsed(ctx, created.ID, now); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	if touched, _ := repo.ByHash(ctx, sum[:]); touched.LastUsedAt == nil {
		t.Fatal("last_used_at not stamped")
	}
	if err := repo.TouchLastUsed(ctx, uuid.New(), now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("TouchLastUsed unknown = %v, want ErrNotFound", err)
	}

	if err := repo.Revoke(ctx, other.ID, created.ID, now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke by stranger = %v, want ErrNotFound", err)
	}
	if err := repo.Revoke(ctx, owner.ID, created.ID, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revoked, _ := repo.ByHash(ctx, sum[:]); revoked.RevokedAt == nil {
		t.Fatal("revoked_at not stamped")
	}
	if err := repo.Revoke(ctx, owner.ID, created.ID, now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Revoke again = %v, want ErrNotFound", err)
	}
}
