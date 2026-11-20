package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// AppUsageRepository implements domain.AppUsageStore with pgx.
type AppUsageRepository struct {
	db *DB
}

// NewAppUsageRepository wires an AppUsageStore on the shared pool.
func NewAppUsageRepository(db *DB) *AppUsageRepository { return &AppUsageRepository{db: db} }

// AddFavorite pins an app for a user (idempotent).
func (r *AppUsageRepository) AddFavorite(ctx context.Context, userID, appID uuid.UUID) error {
	const q = `INSERT INTO user_favorite_apps (user_id, application_id) VALUES ($1,$2)
		ON CONFLICT DO NOTHING`
	_, err := r.db.Pool.Exec(ctx, q, userID, appID)
	return err
}

// RemoveFavorite unpins an app for a user (idempotent).
func (r *AppUsageRepository) RemoveFavorite(ctx context.Context, userID, appID uuid.UUID) error {
	const q = `DELETE FROM user_favorite_apps WHERE user_id=$1 AND application_id=$2`
	_, err := r.db.Pool.Exec(ctx, q, userID, appID)
	return err
}

// Favorites returns the user's pinned app ids.
func (r *AppUsageRepository) Favorites(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]bool, error) {
	const q = `SELECT application_id FROM user_favorite_apps WHERE user_id=$1`
	rows, err := r.db.Pool.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// RecordLaunch upserts the user's last-launch timestamp for an app.
func (r *AppUsageRepository) RecordLaunch(ctx context.Context, userID, appID uuid.UUID) error {
	const q = `INSERT INTO user_app_launches (user_id, application_id, launched_at) VALUES ($1,$2,now())
		ON CONFLICT (user_id, application_id) DO UPDATE SET launched_at = now()`
	_, err := r.db.Pool.Exec(ctx, q, userID, appID)
	return err
}

// LastLaunched returns the user's last-launch timestamp per app.
func (r *AppUsageRepository) LastLaunched(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]time.Time, error) {
	const q = `SELECT application_id, launched_at FROM user_app_launches WHERE user_id=$1`
	rows, err := r.db.Pool.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]time.Time{}
	for rows.Next() {
		var id uuid.UUID
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = at
	}
	return out, rows.Err()
}

var _ domain.AppUsageStore = (*AppUsageRepository)(nil)
