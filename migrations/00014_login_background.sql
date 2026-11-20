-- +goose Up
-- +goose StatementBegin
-- Login backgrounds get their own asset type (1920px long edge) instead
-- of reusing app_logo (512px), which pixelates fullscreen photos.
ALTER TABLE assets DROP CONSTRAINT assets_asset_type_check;
ALTER TABLE assets ADD CONSTRAINT assets_asset_type_check CHECK (asset_type IN ('avatar', 'app_logo', 'saas_logo', 'login_background'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Down fails while login_background rows exist; delete them first.
ALTER TABLE assets DROP CONSTRAINT assets_asset_type_check;
ALTER TABLE assets ADD CONSTRAINT assets_asset_type_check CHECK (asset_type IN ('avatar', 'app_logo', 'saas_logo'));
-- +goose StatementEnd
