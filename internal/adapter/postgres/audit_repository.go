package postgres

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// AuditRepository implements domain.AuditStore with pgx.
type AuditRepository struct {
	db *DB
}

// NewAuditRepository wires an AuditStore on the shared pool.
func NewAuditRepository(db *DB) *AuditRepository { return &AuditRepository{db: db} }

// Append records one audit entry. Every login — success or failure —
// produces exactly one entry (PRD §6.9); callers fail the login when the
// audit write fails so the log stays complete.
func (r *AuditRepository) Append(ctx context.Context, e domain.AuditEntry) error {
	detail := e.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	const q = `INSERT INTO audit_log (at, actor_user_id, application_id, method, result, ip, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`
	_, err = r.db.Pool.Exec(ctx, q, e.At, e.ActorUserID, e.ApplicationID, e.Method, e.Result, nullIP(e.IP), raw)
	return err
}

// List returns a page of entries, newest first, plus the total count.
func (r *AuditRepository) List(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	limit, offset := page(f.Limit, f.Offset)
	const q = `SELECT id, at, actor_user_id, application_id, method, result, host(ip), detail
		FROM audit_log
		WHERE ($1::uuid IS NULL OR actor_user_id = $1)
		  AND ($2::uuid IS NULL OR application_id = $2)
		  AND ($3 = '' OR method = $3)
		  AND ($4 = '' OR result = $4)
		  AND ($5::timestamptz IS NULL OR at >= $5)
		  AND ($6::timestamptz IS NULL OR at <= $6)
		ORDER BY at DESC, id DESC LIMIT $7 OFFSET $8`
	rows, err := r.db.Pool.Query(ctx, q, f.ActorUserID, f.ApplicationID, f.Method, f.Result, f.Since, f.Until, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	entries, err := pgx.CollectRows(rows, scanAudit)
	if err != nil {
		return nil, 0, err
	}
	const cq = `SELECT COUNT(*) FROM audit_log
		WHERE ($1::uuid IS NULL OR actor_user_id = $1)
		  AND ($2::uuid IS NULL OR application_id = $2)
		  AND ($3 = '' OR method = $3)
		  AND ($4 = '' OR result = $4)
		  AND ($5::timestamptz IS NULL OR at >= $5)
		  AND ($6::timestamptz IS NULL OR at <= $6)`
	var total int
	if err := r.db.Pool.QueryRow(ctx, cq, f.ActorUserID, f.ApplicationID, f.Method, f.Result, f.Since, f.Until).Scan(&total); err != nil {
		return nil, 0, err
	}
	return entries, total, nil
}

func scanAudit(row pgx.CollectableRow) (domain.AuditEntry, error) {
	var e domain.AuditEntry
	var actor, app *uuid.UUID
	var ip *string
	var raw []byte
	if err := row.Scan(&e.ID, &e.At, &actor, &app, &e.Method, &e.Result, &ip, &raw); err != nil {
		return domain.AuditEntry{}, err
	}
	e.ActorUserID = actor
	e.ApplicationID = app
	if ip != nil {
		e.IP = *ip
	}
	e.Detail = map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &e.Detail); err != nil {
			return domain.AuditEntry{}, err
		}
	}
	return e, nil
}

// nullIP maps "" to NULL so unknown IPs stay NULL instead of failing the
// INET cast.
func nullIP(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}
