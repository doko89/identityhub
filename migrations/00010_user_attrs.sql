-- +goose Up
-- +goose StatementBegin
-- Admin-defined custom user attributes: the schema (key, type,
-- multi-valued) lives in user_attr_defs; per-user values live in
-- user_attr_values. Values ride every protocol: LDAP search attributes,
-- OIDC claims and SAML assertion attributes. Upstream LDAP populates
-- mapped keys on sync (source='ldap'); the admin API writes
-- source='admin'. Mapped keys are upstream-managed: each sync replaces
-- them wholesale, so admin edits to a mapped key are overwritten.
CREATE TABLE user_attr_defs (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attr_key   TEXT NOT NULL UNIQUE,
    attr_type  TEXT NOT NULL CHECK (attr_type IN ('string', 'number', 'boolean')),
    multi      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE user_attr_values (
    user_id  UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    def_id   UUID NOT NULL REFERENCES user_attr_defs (id) ON DELETE CASCADE,
    ordinal  INT NOT NULL CHECK (ordinal >= 0),
    value    TEXT NOT NULL,
    source   TEXT NOT NULL DEFAULT 'admin' CHECK (source IN ('admin', 'ldap')),
    PRIMARY KEY (user_id, def_id, ordinal)
);
CREATE INDEX user_attr_values_user_idx ON user_attr_values (user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_attr_values;
DROP TABLE IF EXISTS user_attr_defs;
-- +goose StatementEnd
