package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/identityhub/identityhub/migrations"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// MigrateUp applies all pending migrations. It opens a short-lived stdlib
// connection (goose works on database/sql) via the pgx stdlib driver.
// Concurrent boots (app + worker, rolling deploys) serialize on an
// advisory lock: the loser waits for the winner instead of racing on
// the version table and crashing.
func MigrateUp(ctx context.Context, databaseURL string) error {
	return withMigrationLock(ctx, databaseURL, func() error {
		return runGoose(ctx, databaseURL, func(db *sql.DB) error {
			return goose.Up(db, ".")
		})
	})
}

// gooseAdvisoryLockKey serializes MigrateUp across processes (0x49485542
// reads "IHUB" in hex).
const gooseAdvisoryLockKey int64 = 0x49485542

// withMigrationLock holds a session advisory lock while fn runs. The
// lock lives on a dedicated pinned connection; closing it releases
// the lock even if the explicit unlock is skipped.
func withMigrationLock(ctx context.Context, databaseURL string, fn func() error) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database for migrate lock: %w", err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate lock connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gooseAdvisoryLockKey); err != nil {
		return fmt.Errorf("migrate lock: %w", err)
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, gooseAdvisoryLockKey)
	return fn()
}

// MigrateDown rolls back the most recent migration.
func MigrateDown(ctx context.Context, databaseURL string) error {
	return runGoose(ctx, databaseURL, func(db *sql.DB) error {
		return goose.Down(db, ".")
	})
}

// MigrationStatus reports applied/pending migrations (for `migrate status`).
func MigrationStatus(ctx context.Context, databaseURL string) error {
	return runGoose(ctx, databaseURL, func(db *sql.DB) error {
		return goose.Status(db, ".")
	})
}

func runGoose(ctx context.Context, databaseURL string, fn func(*sql.DB) error) error {
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database for migrate: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database for migrate: %w", err)
	}
	return fn(db)
}
