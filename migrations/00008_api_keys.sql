-- +goose Up
-- +goose StatementBegin
-- Personal API keys for the identityhub CLI (TECH_SPEC §6.1). Only the
-- SHA-256 hash of the secret is stored; the secret itself is shown once
-- at creation. A key inherits its owner's permissions; admin keys must be
-- created from an MFA-verified session (created_with_mfa), which is what
-- satisfies the admin MFA gate for Bearer requests.
CREATE TABLE api_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    key_prefix       TEXT NOT NULL,
    key_hash         BYTEA NOT NULL UNIQUE,
    created_with_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at       TIMESTAMPTZ NULL,
    revoked_at       TIMESTAMPTZ NULL,
    last_used_at     TIMESTAMPTZ NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_user_idx ON api_keys (user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS api_keys;
-- +goose StatementEnd
