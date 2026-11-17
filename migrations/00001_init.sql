-- +goose Up
-- +goose StatementBegin
-- M0 initial schema: core data model (TECH_SPEC §5) + scs session table.
-- Seeds: reserved ih_admin group + singleton branding row.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL DEFAULT '',
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash BYTEA NULL,
    source        TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'ldap')),
    external_dn   TEXT NOT NULL DEFAULT '',
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    avatar_url    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX users_email_idx ON users (email);

CREATE TABLE groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE user_groups (
    user_id  UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE applications (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    icon_url      TEXT NOT NULL DEFAULT '',
    launch_url    TEXT NOT NULL DEFAULT '',
    group_label   TEXT NOT NULL DEFAULT '',
    provider_type TEXT NOT NULL CHECK (provider_type IN ('oidc', 'saml', 'ldap', 'radius')),
    is_visible    BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order    INT NOT NULL DEFAULT 0
);

CREATE TABLE oidc_clients (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id     UUID NOT NULL UNIQUE REFERENCES applications (id) ON DELETE CASCADE,
    client_id          TEXT NOT NULL UNIQUE,
    client_secret_hash BYTEA NULL,
    redirect_uris      TEXT[] NOT NULL DEFAULT '{}',
    scopes             TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE saml_sps (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL UNIQUE REFERENCES applications (id) ON DELETE CASCADE,
    entity_id      TEXT NOT NULL UNIQUE,
    acs_url        TEXT NOT NULL,
    slo_url        TEXT NOT NULL DEFAULT '',
    metadata_xml   TEXT NOT NULL DEFAULT '',
    cert_pem       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ldap_provider_config (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id   UUID NOT NULL UNIQUE REFERENCES applications (id) ON DELETE CASCADE,
    bind_dn_template TEXT NOT NULL DEFAULT '',
    base_dn          TEXT NOT NULL DEFAULT '',
    user_filter      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE radius_clients (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id    UUID NOT NULL UNIQUE REFERENCES applications (id) ON DELETE CASCADE,
    nas_identifier    TEXT NOT NULL UNIQUE,
    shared_secret_enc BYTEA NOT NULL
);

CREATE TABLE app_bindings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    binding_type   TEXT NOT NULL CHECK (binding_type IN ('user', 'group', 'policy')),
    user_id        UUID NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id       UUID NULL REFERENCES groups (id) ON DELETE CASCADE,
    policy_expr    TEXT NOT NULL DEFAULT '',
    eval_mode      TEXT NOT NULL DEFAULT 'any' CHECK (eval_mode IN ('any', 'all'))
);
CREATE INDEX app_bindings_app_idx ON app_bindings (application_id);

CREATE TABLE mfa_totp (
    user_id    UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    seed_enc   BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_step  BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE mfa_recovery_codes (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id   UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL UNIQUE,
    used_at   TIMESTAMPTZ NULL
);
CREATE INDEX mfa_recovery_codes_user_idx ON mfa_recovery_codes (user_id);

CREATE TABLE password_reset_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ NULL,
    created_ip INET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE password_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX password_history_user_idx ON password_history (user_id, created_at DESC);

CREATE TABLE webauthn_credentials (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key    BYTEA NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0,
    aaguid        UUID NULL,
    name          TEXT NOT NULL DEFAULT ''
);

CREATE TABLE assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_type  TEXT NOT NULL CHECK (asset_type IN ('avatar', 'app_logo', 'saas_logo')),
    object_key  TEXT NOT NULL UNIQUE,
    byte_size   INT NOT NULL,
    width       INT NOT NULL,
    height      INT NOT NULL,
    uploaded_by UUID NULL REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE branding (
    id                   INT PRIMARY KEY CHECK (id = 1),
    org_name             TEXT NOT NULL DEFAULT 'IdentityHub',
    logo_url             TEXT NOT NULL DEFAULT '',
    favicon_url          TEXT NOT NULL DEFAULT '',
    primary_color        TEXT NOT NULL DEFAULT '#4f46e5',
    theme                TEXT NOT NULL DEFAULT 'system',
    login_background_url TEXT NOT NULL DEFAULT '',
    custom_css           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE audit_log (
    id             BIGSERIAL PRIMARY KEY,
    at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id  UUID NULL REFERENCES users (id) ON DELETE SET NULL,
    application_id UUID NULL REFERENCES applications (id) ON DELETE SET NULL,
    method         TEXT NOT NULL,
    result         TEXT NOT NULL,
    ip             INET NULL,
    detail         JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id, at DESC);

-- scs session store (alexedwards/scs pgxstore layout).
CREATE TABLE sessions (
    token  TEXT PRIMARY KEY,
    data   BYTEA NOT NULL,
    expiry TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expiry);

-- Guard: the reserved ih_admin group can never be deleted or renamed.
CREATE OR REPLACE FUNCTION forbid_ih_admin_change() RETURNS trigger AS $$
BEGIN
    IF OLD.name = 'ih_admin' THEN
        RAISE EXCEPTION 'the ih_admin group cannot be deleted or renamed';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER groups_forbid_ih_admin_change
    BEFORE DELETE OR UPDATE OF name ON groups
    FOR EACH ROW EXECUTE FUNCTION forbid_ih_admin_change();

-- Seeds.
INSERT INTO groups (name, description)
VALUES ('ih_admin', 'Reserved: members are IdentityHub administrators')
ON CONFLICT (name) DO NOTHING;

INSERT INTO branding (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS groups_forbid_ih_admin_change ON groups;
DROP FUNCTION IF EXISTS forbid_ih_admin_change();
DROP TABLE IF EXISTS sessions, audit_log, branding, assets, webauthn_credentials,
    password_history, password_reset_tokens, mfa_recovery_codes, mfa_totp,
    app_bindings, radius_clients, ldap_provider_config, saml_sps, oidc_clients,
    applications, user_groups, groups, users;
-- +goose StatementEnd
