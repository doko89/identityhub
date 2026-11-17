-- +goose Up
-- +goose StatementBegin
-- M3: SAML IdP storage (TECH_SPEC §6.3). saml_keys persists the RSA
-- signing key + self-signed certificate so restarts keep the same IdP
-- identity. saml_requests carries SSO requests across the login round
-- trip byte-identically (raw query for Redirect binding, raw body for
-- POST) so signature validation replays exactly what the SP sent.
-- The saml_sps registry itself lives in the initial migration.
CREATE TABLE saml_keys (
    kid        TEXT PRIMARY KEY,
    key_pem    TEXT NOT NULL,
    cert_pem   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE saml_requests (
    challenge    TEXT PRIMARY KEY,
    method       TEXT NOT NULL CHECK (method IN ('GET', 'POST')),
    target       TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX saml_requests_expiry_idx ON saml_requests (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS saml_requests;
DROP TABLE IF EXISTS saml_keys;
-- +goose StatementEnd
