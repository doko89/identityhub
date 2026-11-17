// Package worker runs background jobs: LDAP sync, session and token
// cleanup (TECH_SPEC §6.6). Jobs call usecases; email outbox delivery
// arrives with the notification milestone.
package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Runner executes periodic jobs until ctx is cancelled.
type Runner struct {
	pool     *pgxpool.Pool
	interval time.Duration
	log      *slog.Logger
	// ldapSync pulls the directory and applies it; nil disables the job
	// (LDAP upstream not configured).
	ldapSync func(ctx context.Context) error
	// auditRetention bounds audit_log rows; <=0 keeps rows forever
	// (AUDIT_RETENTION; audit data is never deleted by default).
	auditRetention time.Duration
}

// NewRunner wires the worker on the shared pool.
func NewRunner(pool *pgxpool.Pool, interval time.Duration, log *slog.Logger) *Runner {
	return &Runner{pool: pool, interval: interval, log: log}
}

// WithLDAPSync enables the periodic directory sync job. main.go supplies
// the closure (ldapclient snapshot + usecase/user apply); the worker only
// schedules and logs it.
func (r *Runner) WithLDAPSync(fn func(ctx context.Context) error) *Runner {
	r.ldapSync = fn
	return r
}

// WithAuditRetention prunes audit_log rows older than d on every pass.
// Non-positive d keeps rows forever (the default: audit data is never
// deleted unless the operator opts in).
func (r *Runner) WithAuditRetention(d time.Duration) *Runner {
	r.auditRetention = d
	return r
}

// Run executes one pass immediately, then repeats every interval.
func (r *Runner) Run(ctx context.Context) error {
	r.log.Info("worker started", "interval", r.interval.String())
	r.runOnce(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.log.Info("worker stopped")
			return nil
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

func (r *Runner) runOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if r.ldapSync != nil {
		if err := r.ldapSync(ctx); err != nil {
			r.log.Error("ldap sync failed", "error", err)
		}
	}
	if n, err := CleanupExpiredSessions(ctx, r.pool); err != nil {
		r.log.Error("cleanup expired sessions failed", "error", err)
	} else if n > 0 {
		r.log.Info("cleaned expired sessions", "count", n)
	}
	if n, err := CleanupExpiredResetTokens(ctx, r.pool); err != nil {
		r.log.Error("cleanup expired reset tokens failed", "error", err)
	} else if n > 0 {
		r.log.Info("cleaned expired reset tokens", "count", n)
	}
	if n, err := CleanupExpiredOIDC(ctx, r.pool); err != nil {
		r.log.Error("cleanup expired OIDC sessions failed", "error", err)
	} else if n > 0 {
		r.log.Info("cleaned expired OIDC sessions", "count", n)
	}
	if n, err := CleanupExpiredSAML(ctx, r.pool); err != nil {
		r.log.Error("cleanup expired SAML requests failed", "error", err)
	} else if n > 0 {
		r.log.Info("cleaned expired SAML requests", "count", n)
	}
	if r.auditRetention > 0 {
		if n, err := CleanupOldAudit(ctx, r.pool, r.auditRetention); err != nil {
			r.log.Error("cleanup old audit rows failed", "error", err)
		} else if n > 0 {
			r.log.Info("cleaned old audit rows", "count", n)
		}
	}
}

// CleanupExpiredSessions deletes scs rows past expiry. pgxstore never
// deletes on its own, so without this the sessions table grows forever.
func CleanupExpiredSessions(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM sessions WHERE expiry < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CleanupExpiredResetTokens deletes single-use reset tokens past their TTL.
func CleanupExpiredResetTokens(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM password_reset_tokens WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CleanupExpiredOIDC deletes fosite flow sessions and consent challenges
// past expiry (TECH_SPEC §6.6 token_cleanup).
func CleanupExpiredOIDC(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM oidc_flow_sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	n := tag.RowsAffected()
	tag, err = pool.Exec(ctx, `DELETE FROM oidc_consent_challenges WHERE expires_at < now()`)
	if err != nil {
		return n, err
	}
	return n + tag.RowsAffected(), nil
}

// CleanupExpiredSAML deletes stashed SSO requests past their TTL.
func CleanupExpiredSAML(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM saml_requests WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CleanupOldAudit deletes audit rows older than retention. Every login
// writes a row, so busy directories grow this table without bound;
// retention is opt-in (AUDIT_RETENTION) because audit data is never
// deleted by default.
func CleanupOldAudit(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	tag, err := pool.Exec(ctx, `DELETE FROM audit_log WHERE at < now() - ($1::bigint * interval '1 second')`,
		int64(retention/time.Second))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
