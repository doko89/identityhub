-- +goose Up
-- +goose StatementBegin
-- Index hygiene from the audit: drop one redundant index, cover the
-- unindexed foreign keys. Deliberately NOT adding method/result indexes
-- on audit_log: the OR-parameterized list query rarely uses them under
-- generic plans, while every login INSERT would pay for them.
-- user_attr_values_user_idx duplicates the (user_id, def_id, ordinal)
-- primary key prefix.
DROP INDEX IF EXISTS user_attr_values_user_idx;
-- Foreign-key coverage (cascade deletes and filtered lookups).
CREATE INDEX IF NOT EXISTS app_bindings_user_idx ON app_bindings (user_id);
CREATE INDEX IF NOT EXISTS app_bindings_group_idx ON app_bindings (group_id);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS user_attr_values_def_idx ON user_attr_values (def_id);
CREATE INDEX IF NOT EXISTS oidc_consent_challenges_user_idx ON oidc_consent_challenges (user_id);
-- Mirrors audit_log_actor_idx for the ?app= filter and the app-delete
-- SET NULL scan.
CREATE INDEX IF NOT EXISTS audit_log_application_idx ON audit_log (application_id, at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS audit_log_application_idx;
DROP INDEX IF EXISTS oidc_consent_challenges_user_idx;
DROP INDEX IF EXISTS user_attr_values_def_idx;
DROP INDEX IF EXISTS password_reset_tokens_user_idx;
DROP INDEX IF EXISTS app_bindings_group_idx;
DROP INDEX IF EXISTS app_bindings_user_idx;
CREATE INDEX IF NOT EXISTS user_attr_values_user_idx ON user_attr_values (user_id);
-- +goose StatementEnd
