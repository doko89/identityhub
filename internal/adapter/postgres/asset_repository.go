package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// AssetRepository implements domain.AssetStore with pgx.
type AssetRepository struct {
	db *DB
}

// NewAssetRepository wires an AssetStore on the shared pool.
func NewAssetRepository(db *DB) *AssetRepository { return &AssetRepository{db: db} }

func scanAsset(row pgx.Row) (domain.Asset, error) {
	var a domain.Asset
	err := row.Scan(&a.ID, &a.AssetType, &a.ObjectKey, &a.ByteSize, &a.Width, &a.Height, &a.UploadedBy, &a.CreatedAt)
	if err != nil {
		return domain.Asset{}, err
	}
	return a, nil
}

// Create inserts an asset metadata row; a duplicate object key reports
// domain.ErrConflict (keys embed a fresh UUID, so this only fires on
// retry bugs).
func (r *AssetRepository) Create(ctx context.Context, a domain.Asset) (domain.Asset, error) {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	const q = `INSERT INTO assets (id, asset_type, object_key, byte_size, width, height, uploaded_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, asset_type, object_key, byte_size, width, height, uploaded_by, created_at`
	created, err := scanAsset(r.db.Pool.QueryRow(ctx, q, a.ID, a.AssetType, a.ObjectKey,
		a.ByteSize, a.Width, a.Height, a.UploadedBy))
	if err != nil {
		return domain.Asset{}, mapWriteError(err)
	}
	return created, nil
}

// ByID loads an asset by id.
func (r *AssetRepository) ByID(ctx context.Context, id uuid.UUID) (domain.Asset, error) {
	const q = `SELECT id, asset_type, object_key, byte_size, width, height, uploaded_by, created_at
		FROM assets WHERE id = $1`
	a, err := scanAsset(r.db.Pool.QueryRow(ctx, q, id))
	if err != nil {
		return domain.Asset{}, mapReadError(err)
	}
	return a, nil
}

// Delete removes an asset metadata row (the object itself is deleted by
// the caller through domain.FileStorage).
func (r *AssetRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM assets WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
