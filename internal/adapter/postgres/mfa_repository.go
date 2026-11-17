package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// MFARepository implements domain.MFAStore with pgx. TOTP seeds arrive
// pre-sealed with ENC_KEY (crypto.Seal); the repository never sees
// plaintext. Recovery codes arrive pre-hashed (SHA-256); verification is
// a hash-equality match.
type MFARepository struct {
	db *DB
}

// NewMFARepository wires an MFAStore on the shared pool.
func NewMFARepository(db *DB) *MFARepository { return &MFARepository{db: db} }

// EnrollTOTP stores a fresh credential. A second enroll without a prior
// disable collides on the primary key and reports domain.ErrConflict.
func (r *MFARepository) EnrollTOTP(ctx context.Context, cred domain.TOTPCredential) error {
	const q = `INSERT INTO mfa_totp (user_id, seed_enc, last_step) VALUES ($1, $2, 0)`
	_, err := r.db.Pool.Exec(ctx, q, cred.UserID, cred.SeedEnc)
	if err != nil {
		return mapWriteError(err)
	}
	// Enrollment flips legacy-bind decisions for the user.
	_ = BumpDirectoryVersion(ctx, r.db)
	return nil
}

// TOTPOfUser loads the credential or reports domain.ErrNotFound.
func (r *MFARepository) TOTPOfUser(ctx context.Context, userID uuid.UUID) (domain.TOTPCredential, error) {
	const q = `SELECT user_id, seed_enc, created_at, last_step FROM mfa_totp WHERE user_id = $1`
	var c domain.TOTPCredential
	err := r.db.Pool.QueryRow(ctx, q, userID).Scan(&c.UserID, &c.SeedEnc, &c.CreatedAt, &c.LastStep)
	if err != nil {
		return domain.TOTPCredential{}, mapReadError(err)
	}
	return c, nil
}

// AcceptStep records step as the last used step when — and only when —
// it is newer than the stored one, in a single UPDATE (TECH_SPEC §8:
// atomic anti-replay). A replayed or concurrent reuse reports
// domain.ErrConflict; a missing credential reports domain.ErrNotFound.
func (r *MFARepository) AcceptStep(ctx context.Context, userID uuid.UUID, step int64) error {
	const q = `UPDATE mfa_totp SET last_step = $2 WHERE user_id = $1 AND last_step < $2`
	tag, err := r.db.Pool.Exec(ctx, q, userID, step)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := r.db.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mfa_totp WHERE user_id = $1)`, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return domain.ErrNotFound
	}
	return domain.ErrConflict
}

// DisableTOTP removes the credential and all recovery codes of the user
// in one transaction. It is idempotent: disabling a user without MFA is
// a no-op (the MFA-loss admin reset must not fail on a half-reset user).
func (r *MFARepository) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	_ = BumpDirectoryVersion(ctx, r.db)
	return nil
}

// AddRecoveryCodes stores pre-hashed single-use codes.
func (r *MFARepository) AddRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes [][]byte) error {
	if len(hashes) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(hashes))
	for _, h := range hashes {
		rows = append(rows, []any{uuid.New(), userID, h})
	}
	_, err := r.db.Pool.CopyFrom(ctx,
		pgx.Identifier{"mfa_recovery_codes"},
		[]string{"id", "user_id", "code_hash"},
		pgx.CopyFromRows(rows))
	return mapWriteError(err)
}

// ReplaceRecoveryCodes swaps the whole code set in one transaction:
// old codes (used or not) die, the new hashes take over. An empty set
// clears without inserting.
func (r *MFARepository) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes [][]byte) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if len(hashes) > 0 {
		rows := make([][]any, 0, len(hashes))
		for _, h := range hashes {
			rows = append(rows, []any{uuid.New(), userID, h})
		}
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"mfa_recovery_codes"},
			[]string{"id", "user_id", "code_hash"},
			pgx.CopyFromRows(rows)); err != nil {
			return mapWriteError(err)
		}
	}
	return tx.Commit(ctx)
}

// UseRecoveryCode burns one unused code by hash. Unknown, foreign, or
// already-used codes all report domain.ErrNotFound so callers answer
// generically (TECH_SPEC §8: no enumeration oracle).
func (r *MFARepository) UseRecoveryCode(ctx context.Context, userID uuid.UUID, hash []byte, at time.Time) error {
	const q = `UPDATE mfa_recovery_codes SET used_at = $3
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`
	tag, err := r.db.Pool.Exec(ctx, q, userID, hash, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// RemainingRecoveryCodes counts the user's still-unused codes.
func (r *MFARepository) RemainingRecoveryCodes(ctx context.Context, userID uuid.UUID) (int, error) {
	const q = `SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`
	var n int
	if err := r.db.Pool.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
