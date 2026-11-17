-- +goose Up
-- +goose StatementBegin
-- M1: link login sessions to users so password change/reset can terminate
-- every other session (PRD §6.10). session_token matches the scs sessions
-- table PK; revoking deletes from both tables.
CREATE TABLE user_sessions (
    user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_token TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, session_token)
);
CREATE INDEX user_sessions_token_idx ON user_sessions (session_token);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_sessions;
-- +goose StatementEnd
