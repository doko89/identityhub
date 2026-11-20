package domain

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"
)

// Asset types accepted by the upload endpoint (TECH_SPEC §6.7).
const (
	AssetAvatar          = "avatar"
	AssetAppLogo         = "app_logo"
	AssetSaaSLogo        = "saas_logo"
	AssetLoginBackground = "login_background"
)

// Asset is one row of the assets table.
type Asset struct {
	ID         uuid.UUID
	AssetType  string
	ObjectKey  string
	ByteSize   int
	Width      int
	Height     int
	UploadedBy *uuid.UUID
	CreatedAt  time.Time
}

// PublicPath returns the /uploads/... URL served for this asset.
func (a Asset) PublicPath() string {
	return "/uploads/" + a.AssetType + "/" + a.ID.String() + ".webp"
}

// FileStorage abstracts local/S3 object backends (TECH_SPEC §6.7).
// Implementations live in internal/adapter/storage (M6).
type FileStorage interface {
	Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// AssetStore persists asset metadata rows.
type AssetStore interface {
	Create(ctx context.Context, a Asset) (Asset, error)
	ByID(ctx context.Context, id uuid.UUID) (Asset, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
