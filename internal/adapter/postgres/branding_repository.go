package postgres

import (
	"context"

	"github.com/identityhub/identityhub/internal/domain"
)

// BrandingRepository implements domain.BrandingStore with pgx. The branding
// table holds exactly one row (id = 1), seeded by migration 00001.
type BrandingRepository struct {
	db *DB
}

// NewBrandingRepository wires a BrandingStore on the shared pool.
func NewBrandingRepository(db *DB) *BrandingRepository { return &BrandingRepository{db: db} }

const brandingColumns = `id, org_name, tagline, logo_url, favicon_url, primary_color, theme, login_background_url, custom_css`

// Get loads the singleton branding row.
func (r *BrandingRepository) Get(ctx context.Context) (domain.Branding, error) {
	const q = `SELECT ` + brandingColumns + ` FROM branding WHERE id = 1`
	var b domain.Branding
	err := r.db.Pool.QueryRow(ctx, q).Scan(&b.ID, &b.OrgName, &b.Tagline, &b.LogoURL,
		&b.FaviconURL, &b.PrimaryColor, &b.Theme, &b.LoginBackgroundURL, &b.CustomCSS)
	if err != nil {
		return domain.Branding{}, mapReadError(err)
	}
	return b, nil
}

// Update rewrites the singleton row. Validation (hex colors, known themes,
// custom_css safety rules) runs before the write so bad input never lands.
func (r *BrandingRepository) Update(ctx context.Context, b domain.Branding) (domain.Branding, error) {
	b.ID = domain.BrandingID
	if err := b.Validate(); err != nil {
		return domain.Branding{}, err
	}
	const q = `UPDATE branding SET org_name = $1, tagline = $2, logo_url = $3, favicon_url = $4,
		primary_color = $5, theme = $6, login_background_url = $7, custom_css = $8
		WHERE id = 1 RETURNING ` + brandingColumns
	var out domain.Branding
	err := r.db.Pool.QueryRow(ctx, q, b.OrgName, b.Tagline, b.LogoURL, b.FaviconURL,
		b.PrimaryColor, b.Theme, b.LoginBackgroundURL, b.CustomCSS).Scan(&out.ID, &out.OrgName,
		&out.Tagline, &out.LogoURL, &out.FaviconURL, &out.PrimaryColor, &out.Theme,
		&out.LoginBackgroundURL, &out.CustomCSS)
	if err != nil {
		return domain.Branding{}, mapWriteError(err)
	}
	return out, nil
}
