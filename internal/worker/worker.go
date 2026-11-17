// Package worker runs background jobs: LDAP sync, email outbox, session and
// token cleanup (TECH_SPEC §6.6). Jobs call usecases; in M0 only the
// database cleanup jobs exist — sync/email arrive in M1.
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
}

// NewRunner wires the worker on the shared pool.
func NewRunner(pool *pgxpool.Pool, interval time.Duration, log *slog.Logger) *Runner {
	return &Runner{pool: pool, interval: interval, log: log}
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
