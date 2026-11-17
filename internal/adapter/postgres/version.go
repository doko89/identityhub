package postgres

import "context"

// DirectoryVersionRepository implements domain.DirectoryVersioner with
// pgx: one singleton row bumped by every directory write.
type DirectoryVersionRepository struct {
	db *DB
}

// NewDirectoryVersionRepository wires the store on the shared pool.
func NewDirectoryVersionRepository(db *DB) *DirectoryVersionRepository {
	return &DirectoryVersionRepository{db: db}
}

// Current returns the directory generation.
func (r *DirectoryVersionRepository) Current(ctx context.Context) (int64, error) {
	var v int64
	if err := r.db.Pool.QueryRow(ctx, `SELECT version FROM directory_version WHERE id=1`).Scan(&v); err != nil {
		return 0, mapReadError(err)
	}
	return v, nil
}

// BumpDirectoryVersion increments the directory generation. Repository
// writes call it best-effort after a successful commit: it runs outside
// the write's transaction (a crash between the two heals via the LDAP
// TTL backstop), and a failure must never fail the user write itself.
func BumpDirectoryVersion(ctx context.Context, db *DB) error {
	_, err := db.Pool.Exec(ctx, `UPDATE directory_version SET version = version + 1, updated_at = now() WHERE id = 1`)
	return err
}
