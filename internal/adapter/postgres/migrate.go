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
func MigrateUp(ctx context.Context, databaseURL string) error {
	return runGoose(ctx, databaseURL, func(db *sql.DB) error {
		return goose.Up(db, ".")
	})
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
