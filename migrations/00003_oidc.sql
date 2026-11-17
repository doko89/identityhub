-- +goose Up
-- +goose StatementBegin
-- M2: OIDC provider storage (TECH_SPEC §6.2). fosite flow sessions
-- (authorize codes, access/refresh tokens, PKCE, OIDC sessions) live in
-- one table keyed by code/token signature; the serialized requester is
-- JSON in `data`. Signing keys persist in oidc_keys so restarts keep the
-- same kid. Consents remember granted scopes per user+client; consent
-- challenges carry the authorize request across the consent-page round
-- trip (raw query is re-parsed, never trusted from the browser).
CREATE TABLE oidc_flow_sessions (
    signature  TEXT NOT NULL,
    flow_type  TEXT NOT NULL CHECK (flow_type IN ('authorize_code', 'access_token', 'refresh_token', 'pkce', 'openid')),
    request_id TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL DEFAULT '',
    data       JSONB NOT NULL,
    active     BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Composite key: fosite keys authorize codes and PKCE sessions by
    -- the same code signature, so one column cannot be unique.
    PRIMARY KEY (signature, flow_type)
);
CREATE INDEX oidc_flow_sessions_request_idx ON oidc_flow_sessions (request_id);
CREATE INDEX oidc_flow_sessions_expiry_idx ON oidc_flow_sessions (expires_at);

CREATE TABLE oidc_keys (
    kid        TEXT PRIMARY KEY,
    pem        TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oidc_consents (
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    scopes     TEXT[] NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE oidc_consent_challenges (
    challenge  TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    query      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX oidc_consent_challenges_expiry_idx ON oidc_consent_challenges (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oidc_consent_challenges;
DROP TABLE IF EXISTS oidc_consents;
DROP TABLE IF EXISTS oidc_keys;
DROP TABLE IF EXISTS oidc_flow_sessions;
-- +goose StatementEnd
