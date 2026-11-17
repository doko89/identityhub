package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// APIKey is one row of the api_keys table: a personal access token the
// owner creates under /account for the identityhub CLI. Only the SHA-256
// hash of the secret is stored; the secret itself is shown once at
// creation and cannot be recovered later.
type APIKey struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Name           string
	Prefix         string
	KeyHash        []byte
	CreatedWithMFA bool
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	LastUsedAt     *time.Time
	CreatedAt      time.Time
}

// Active reports whether the key authenticates at now: neither revoked
// nor past its expiry (a nil expiry never expires).
func (k APIKey) Active(now time.Time) bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		return false
	}
	return true
}

// APIKeyStore persists personal API keys.
type APIKeyStore interface {
	Create(ctx context.Context, k APIKey) (APIKey, error)
	// ByHash loads a key by its secret hash (ByHash finds revoked and
	// expired keys too; the caller decides what Active means).
	ByHash(ctx context.Context, hash []byte) (APIKey, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]APIKey, error)
	// Revoke soft-revokes one of the owner's keys. It returns
	// ErrNotFound when the id is unknown or owned by someone else, so
	// ownership is never leaked.
	Revoke(ctx context.Context, userID, id uuid.UUID, at time.Time) error
	// TouchLastUsed records use; failures are best-effort for callers
	// (a stats write must never fail authentication).
	TouchLastUsed(ctx context.Context, id uuid.UUID, at time.Time) error
}
