-- +goose Up
-- +goose StatementBegin
-- Dashboard favorites + recently-used (one row per user/app; launches
-- upsert so the table stays small and always holds "last launched").
CREATE TABLE user_favorite_apps (
    user_id        UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, application_id)
);
CREATE INDEX user_favorite_apps_user_idx ON user_favorite_apps (user_id);
CREATE TABLE user_app_launches (
    user_id        UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    launched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, application_id)
);
CREATE INDEX user_app_launches_user_idx ON user_app_launches (user_id, launched_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_app_launches;
DROP TABLE IF EXISTS user_favorite_apps;
-- +goose StatementEnd
