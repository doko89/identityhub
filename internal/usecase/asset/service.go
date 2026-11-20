// Package asset implements asset uploads (TECH_SPEC §6.7): users upload
// an avatar for their own account, admins upload app/SaaS logos. The
// backend validates the bytes and re-encodes every image to webp — the
// .webp contract is guaranteed by the server, never the client.
package asset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"

	"github.com/HugoSmits86/nativewebp"
	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

const (
	// MaxUploadBytes is the 10 MB input cap (TECH_SPEC §8). Magic bytes,
	// not the extension, decide the format.
	MaxUploadBytes = 10 << 20
	// MaxDimension caps the long edge for icons (avatar/logo); larger
	// images scale down.
	MaxDimension = 512
	// MaxBackgroundDimension caps the long edge for login_background,
	// which renders fullscreen (1080p).
	MaxBackgroundDimension = 1920
)

// maxDimensionFor returns the long-edge cap for one asset type.
func maxDimensionFor(assetType string) int {
	if assetType == domain.AssetLoginBackground {
		return MaxBackgroundDimension
	}
	return MaxDimension
}

// Service holds the upload rules. All outer details arrive as domain
// interfaces.
type Service struct {
	assets  domain.AssetStore
	storage domain.FileStorage
}

// Deps wires a Service. Both are required.
type Deps struct {
	Assets  domain.AssetStore
	Storage domain.FileStorage
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Assets == nil || d.Storage == nil {
		return nil, errors.New("asset: Assets and Storage are required")
	}
	return &Service{assets: d.Assets, storage: d.Storage}, nil
}

// Upload validates one image and stores it as webp under
// <type>/<uuid>.webp. actorID is nil for system uploads.
func (s *Service) Upload(ctx context.Context, actorID *uuid.UUID, assetType string, r io.Reader) (domain.Asset, error) {
	switch assetType {
	case domain.AssetAvatar, domain.AssetAppLogo, domain.AssetSaaSLogo, domain.AssetLoginBackground:
	default:
		return domain.Asset{}, fmt.Errorf("%w: unknown asset type %q", domain.ErrValidation, assetType)
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxUploadBytes+1))
	if err != nil {
		return domain.Asset{}, fmt.Errorf("asset: read upload: %w", err)
	}
	if len(raw) > MaxUploadBytes {
		return domain.Asset{}, fmt.Errorf("%w: image exceeds 10 MB", domain.ErrValidation)
	}
	if len(raw) == 0 {
		return domain.Asset{}, fmt.Errorf("%w: empty image", domain.ErrValidation)
	}
	img, err := decode(raw)
	if err != nil {
		return domain.Asset{}, err
	}
	img = fit(img, maxDimensionFor(assetType))
	var buf bytes.Buffer
	if err := nativewebp.Encode(&buf, img, nil); err != nil {
		return domain.Asset{}, fmt.Errorf("asset: webp encode: %w", err)
	}
	encoded := buf.Bytes()
	bounds := img.Bounds()
	id := uuid.New()
	key := assetType + "/" + id.String() + ".webp"
	if err := s.storage.Put(ctx, key, bytes.NewReader(encoded), int64(len(encoded)), "image/webp"); err != nil {
		return domain.Asset{}, fmt.Errorf("asset: store object: %w", err)
	}
	created, err := s.assets.Create(ctx, domain.Asset{
		ID: id, AssetType: assetType, ObjectKey: key,
		ByteSize: len(encoded), Width: bounds.Dx(), Height: bounds.Dy(), UploadedBy: actorID,
	})
	if err != nil {
		_ = s.storage.Delete(ctx, key)
		return domain.Asset{}, fmt.Errorf("asset: store metadata: %w", err)
	}
	return created, nil
}

// decode accepts jpeg, png or webp by magic bytes. stdlib handles the
// first two; nativewebp the third.
func decode(raw []byte) (image.Image, error) {
	if img, _, err := image.Decode(bytes.NewReader(raw)); err == nil {
		return img, nil
	}
	if img, err := nativewebp.Decode(bytes.NewReader(raw)); err == nil {
		return img, nil
	}
	return nil, fmt.Errorf("%w: image must be jpeg, png or webp", domain.ErrValidation)
}

// fit scales img down so its long edge is at most max, preserving the
// aspect ratio (nearest-neighbor; uploads are small and this keeps the
// dependency tree stdlib-only for resizing).
func fit(img image.Image, max int) image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	longest := maxInt(w, h)
	if longest <= max {
		return img
	}
	scale := float64(max) / float64(longest)
	nw, nh := maxInt(int(float64(w)*scale), 1), maxInt(int(float64(h)*scale), 1)
	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	for y := range nh {
		sy := b.Min.Y + y*h/nh
		for x := range nw {
			dst.Set(x, y, img.At(b.Min.X+x*w/nw, sy))
		}
	}
	return dst
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
