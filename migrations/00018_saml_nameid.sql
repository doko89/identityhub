-- +goose Up
-- +goose StatementBegin
-- Per-SP SAML NameID source (SendGrid keys users by email while phpIPAM
-- and FortiGate need the username, so one global is not enough).
ALTER TABLE saml_sps ADD COLUMN name_id TEXT NOT NULL DEFAULT 'username'
    CHECK (name_id IN ('username', 'email'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE saml_sps DROP COLUMN IF EXISTS name_id;
-- +goose StatementEnd
