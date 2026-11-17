package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// PasswordRepository implements domain.PasswordResetStore and
// domain.PasswordHistoryStore with pgx (PRD §6.10).
type PasswordRepository struct {
	db *DB
}

// NewPasswordRepository wires the password stores on the shared pool.
func NewPasswordRepository(db *DB) *PasswordRepository { return &PasswordRepository{db: db} }

// Create revokes any previous active token for the user, then stores the
// new one (one active token per user, TECH_SPEC §8).
func (r *PasswordRepository) Create(ctx context.Context, tok domain.PasswordResetToken) (domain.PasswordResetToken, error) {
	if tok.ID == uuid.Nil {
		tok.ID = uuid.New()
	}
	err := r.db.InTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE password_reset_tokens SET used_at=now()
			WHERE user_id=$1 AND used_at IS NULL`, tok.UserID); err != nil {
			return err
		}
		const q = `INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_ip)
			VALUES ($1,$2,$3,$4,$5)
			RETURNING id, user_id, token_hash, expires_at, used_at, host(created_ip), created_at`
		var created domain.PasswordResetToken
		var ip *string
		if err := tx.QueryRow(ctx, q, tok.ID, tok.UserID, tok.TokenHash, tok.ExpiresAt, nullIP(tok.CreatedIP)).
			Scan(&created.ID, &created.UserID, &created.TokenHash, &created.ExpiresAt, &created.UsedAt, &ip, &created.CreatedAt); err != nil {
			return mapWriteError(err)
		}
		if ip != nil {
			created.CreatedIP = *ip
		}
		tok = created
		return nil
	})
	if err != nil {
		return domain.PasswordResetToken{}, err
	}
	return tok, nil
}

// ByHash loads a token by its hash (tokens are stored hashed, TECH_SPEC §8).
func (r *PasswordRepository) ByHash(ctx context.Context, hash []byte) (domain.PasswordResetToken, error) {
	const q = `SELECT id, user_id, token_hash, expires_at, used_at, host(created_ip), created_at
		FROM password_reset_tokens WHERE token_hash=$1`
	var t domain.PasswordResetToken
	var ip *string
	if err := r.db.Pool.QueryRow(ctx, q, hash).
		Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &ip, &t.CreatedAt); err != nil {
		return domain.PasswordResetToken{}, mapReadError(err)
	}
	if ip != nil {
		t.CreatedIP = *ip
	}
	return t, nil
}

// MarkUsed records redemption so the single-use rule holds even if the
// follow-up steps fail partway.
func (r *PasswordRepository) MarkUsed(ctx context.Context, id uuid.UUID, at time.Time) error {
	tag, err := r.db.Pool.Exec(ctx, `UPDATE password_reset_tokens SET used_at=$2
		WHERE id=$1 AND used_at IS NULL`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DeleteExpired removes tokens past their TTL; returns the deleted count.
func (r *PasswordRepository) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM password_reset_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// History retention for the "not equal to the last 10" rule (PRD §6.10).
const passwordHistoryKeep = 10

// Add records hash and trims the user's history to the newest 10.
func (r *PasswordRepository) Add(ctx context.Context, userID uuid.UUID, hash []byte) error {
	return r.db.InTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO password_history (user_id, password_hash) VALUES ($1,$2)`,
			userID, hash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM password_history WHERE user_id=$1 AND id NOT IN (
			SELECT id FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2)`,
			userID, passwordHistoryKeep)
		return err
	})
}

// Recent returns up to limit newest hashes, newest first.
func (r *PasswordRepository) Recent(ctx context.Context, userID uuid.UUID, limit int) ([][]byte, error) {
	if limit <= 0 || limit > passwordHistoryKeep {
		limit = passwordHistoryKeep
	}
	rows, err := r.db.Pool.Query(ctx, `SELECT password_hash FROM password_history
		WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) ([]byte, error) {
		var h []byte
		err := row.Scan(&h)
		return h, err
	})
}
