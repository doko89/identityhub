-- +goose Up
-- +goose StatementBegin
-- Binding effect (allow/deny): deny-bindings exclude users from an app
-- even when an allow-binding matches (deny wins). Existing rows default
-- to allow, so current configs keep their meaning.
ALTER TABLE app_bindings ADD COLUMN effect TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE app_bindings DROP COLUMN IF EXISTS effect;
-- +goose StatementEnd
