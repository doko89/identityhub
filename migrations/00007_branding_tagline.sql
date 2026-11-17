-- +goose Up
-- +goose StatementBegin
-- Editable login-panel tagline (PRD §6.8). Empty keeps the built-in
-- default text in the client.
ALTER TABLE branding ADD COLUMN tagline TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE branding DROP COLUMN IF EXISTS tagline;
-- +goose StatementEnd
