//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// Concurrent boots (app + worker) must serialize migrations instead of
// racing on the version table. Runs in its own scratch database so the
// race window is real (fresh schema) without disturbing the packages
// that share TEST_DATABASE_URL.
func TestMigrateUpConcurrent(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		base = os.Getenv("DATABASE_URL")
	}
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}
	adminURL, err := replaceDBName(base, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	targetURL, err := replaceDBName(base, "zz_migrate_race")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS zz_migrate_race`); err != nil {
		t.Fatalf("drop scratch db: %v", err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE zz_migrate_race`); err != nil {
		t.Fatalf("create scratch db: %v", err)
	}
	defer admin.ExecContext(context.Background(), `DROP DATABASE IF EXISTS zz_migrate_race`)

	const racers = 8
	var wg sync.WaitGroup
	errs := make(chan error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- MigrateUp(ctx, targetURL)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent MigrateUp: %v", err)
		}
	}
	db, err := sql.Open("pgx", targetURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var versions int
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM goose_db_version WHERE is_applied`).Scan(&versions)
	if err != nil || versions < 1 {
		t.Fatalf("applied versions = %d, err = %v", versions, err)
	}
	var posix int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='uid_number'`).Scan(&posix)
	if err != nil || posix != 1 {
		t.Fatalf("uid_number column present = %d, err = %v", posix, err)
	}
}

func replaceDBName(rawURL, name string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}
