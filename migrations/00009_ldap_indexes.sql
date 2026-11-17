-- +goose Up
-- +goose StatementBegin
-- LDAP search fast paths: membership lookup by group (MemberIDs and the
-- tree-serving membership join filter on group_id, which the
-- (user_id, group_id) primary key cannot serve), and case-insensitive
-- username lookup backing the (uid=...) search short-circuit
-- (caseIgnoreMatch).
CREATE INDEX IF NOT EXISTS user_groups_group_id_idx ON user_groups (group_id);
CREATE INDEX IF NOT EXISTS users_username_lower_idx ON users (lower(username));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS users_username_lower_idx;
DROP INDEX IF EXISTS user_groups_group_id_idx;
-- +goose StatementEnd
