-- +goose Up
-- +goose StatementBegin
-- Admin dashboard theme (grid columns, icon shape, density, background).
ALTER TABLE branding ADD COLUMN dashboard_columns INT NOT NULL DEFAULT 3;
ALTER TABLE branding ADD COLUMN dashboard_icon_shape TEXT NOT NULL DEFAULT 'rounded';
ALTER TABLE branding ADD COLUMN dashboard_density TEXT NOT NULL DEFAULT 'comfortable';
ALTER TABLE branding ADD COLUMN dashboard_background TEXT NOT NULL DEFAULT 'pattern';
ALTER TABLE branding ADD COLUMN dashboard_background_url TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE branding DROP COLUMN IF EXISTS dashboard_columns;
ALTER TABLE branding DROP COLUMN IF EXISTS dashboard_icon_shape;
ALTER TABLE branding DROP COLUMN IF EXISTS dashboard_density;
ALTER TABLE branding DROP COLUMN IF EXISTS dashboard_background;
ALTER TABLE branding DROP COLUMN IF EXISTS dashboard_background_url;
-- +goose StatementEnd
