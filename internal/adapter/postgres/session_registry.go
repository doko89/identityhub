package postgres

import (
	"context"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// SessionRegistryRepository implements domain.SessionRegistry with pgx.
// Revocation deletes the scs session rows themselves, so logout takes
// effect on the very next request with no denylist (TECH_SPEC §10).
type SessionRegistryRepository struct {
	db *DB
}

// NewSessionRegistryRepository wires a SessionRegistry on the shared pool.
func NewSessionRegistryRepository(db *DB) *SessionRegistryRepository {
	return &SessionRegistryRepository{db: db}
}

// Register links a fresh session token to a user (idempotent).
func (r *SessionRegistryRepository) Register(ctx context.Context, userID uuid.UUID, token string) error {
	_, err := r.db.Pool.Exec(ctx, `INSERT INTO user_sessions (user_id, session_token) VALUES ($1,$2)
		ON CONFLICT DO NOTHING`, userID, token)
	return err
}

// Unregister drops one token (logout, idempotent).
func (r *SessionRegistryRepository) Unregister(ctx context.Context, token string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM user_sessions WHERE session_token=$1`, token)
	return err
}

// RevokeOthers deletes every session of userID except keepToken and
// returns the revoked count.
func (r *SessionRegistryRepository) RevokeOthers(ctx context.Context, userID uuid.UUID, keepToken string) (int64, error) {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM sessions WHERE token IN (
		SELECT session_token FROM user_sessions WHERE user_id=$1 AND session_token<>$2)`,
		userID, keepToken)
	if err != nil {
		return 0, err
	}
	_, err = r.db.Pool.Exec(ctx, `DELETE FROM user_sessions WHERE user_id=$1 AND session_token<>$2`,
		userID, keepToken)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeAll deletes every session of userID (admin disable, ...).
func (r *SessionRegistryRepository) RevokeAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM sessions WHERE token IN (
		SELECT session_token FROM user_sessions WHERE user_id=$1)`, userID)
	if err != nil {
		return 0, err
	}
	_, err = r.db.Pool.Exec(ctx, `DELETE FROM user_sessions WHERE user_id=$1`, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

var (
	_ domain.SessionRegistry      = (*SessionRegistryRepository)(nil)
	_ domain.AuditStore           = (*AuditRepository)(nil)
	_ domain.PasswordResetStore   = (*PasswordRepository)(nil)
	_ domain.PasswordHistoryStore = (*PasswordRepository)(nil)
)
