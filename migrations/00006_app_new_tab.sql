-- +goose Up
-- +goose StatementBegin
-- Per-app "open in new tab" dashboard behavior. Default FALSE preserves
-- the current same-tab launch; admins opt apps into a new tab.
ALTER TABLE applications ADD COLUMN open_in_new_tab BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE applications DROP COLUMN IF EXISTS open_in_new_tab;
-- +goose StatementEnd
