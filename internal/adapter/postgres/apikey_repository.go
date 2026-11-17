package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// APIKeyRepository implements domain.APIKeyStore with pgx.
type APIKeyRepository struct {
	db *DB
}

// NewAPIKeyRepository wires the store on the shared pool.
func NewAPIKeyRepository(db *DB) *APIKeyRepository { return &APIKeyRepository{db: db} }

const apiKeyColumns = `id, user_id, name, key_prefix, key_hash,
	created_with_mfa, expires_at, revoked_at, last_used_at, created_at`

func scanAPIKey(row pgx.Row) (domain.APIKey, error) {
	var k domain.APIKey
	err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.KeyHash,
		&k.CreatedWithMFA, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt, &k.CreatedAt)
	return k, err
}

// Create stores one key row.
func (r *APIKeyRepository) Create(ctx context.Context, k domain.APIKey) (domain.APIKey, error) {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	const q = `INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash,
		created_with_mfa, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING ` + apiKeyColumns
	created, err := scanAPIKey(r.db.Pool.QueryRow(ctx, q, k.ID, k.UserID, k.Name,
		k.Prefix, k.KeyHash, k.CreatedWithMFA, k.ExpiresAt))
	if err != nil {
		return domain.APIKey{}, mapWriteError(mapReadError(err))
	}
	return created, nil
}

// ByHash loads a key by its secret hash, whatever its state.
func (r *APIKeyRepository) ByHash(ctx context.Context, hash []byte) (domain.APIKey, error) {
	const q = `SELECT ` + apiKeyColumns + ` FROM api_keys WHERE key_hash=$1`
	k, err := scanAPIKey(r.db.Pool.QueryRow(ctx, q, hash))
	if err != nil {
		return domain.APIKey{}, mapReadError(err)
	}
	return k, nil
}

// ListByUser returns the owner's keys, newest first (revoked ones
// included: the account page shows their history).
func (r *APIKeyRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.APIKey, error) {
	const q = `SELECT ` + apiKeyColumns + ` FROM api_keys
		WHERE user_id=$1 ORDER BY created_at DESC`
	rows, err := r.db.Pool.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.APIKey, error) {
		return scanAPIKey(row)
	})
}

// Revoke stamps revoked_at on one of the owner's keys. Unknown ids and
// other owners' ids both answer ErrNotFound.
func (r *APIKeyRepository) Revoke(ctx context.Context, userID, id uuid.UUID, at time.Time) error {
	tag, err := r.db.Pool.Exec(ctx, `UPDATE api_keys SET revoked_at=$3
		WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, userID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// TouchLastUsed records authentication use.
func (r *APIKeyRepository) TouchLastUsed(ctx context.Context, id uuid.UUID, at time.Time) error {
	tag, err := r.db.Pool.Exec(ctx, `UPDATE api_keys SET last_used_at=$2 WHERE id=$1`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
