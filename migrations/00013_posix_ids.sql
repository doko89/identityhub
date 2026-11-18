-- +goose Up
-- +goose StatementBegin
-- Stable POSIX IDs for Linux/SSSD integration (rfc2307bis): sequences
-- hand out uidNumber/gidNumber from 10000 upward, existing rows are
-- backfilled by the volatile DEFAULT, and future inserts draw from the
-- same sequences. IDs are never reused or changed.
CREATE SEQUENCE IF NOT EXISTS users_uid_number_seq START WITH 10000;
CREATE SEQUENCE IF NOT EXISTS groups_gid_number_seq START WITH 10000;
ALTER TABLE users ADD COLUMN uid_number INT NOT NULL DEFAULT nextval('users_uid_number_seq') UNIQUE;
ALTER TABLE groups ADD COLUMN gid_number INT NOT NULL DEFAULT nextval('groups_gid_number_seq') UNIQUE;
ALTER SEQUENCE users_uid_number_seq OWNED BY users.uid_number;
ALTER SEQUENCE groups_gid_number_seq OWNED BY groups.gid_number;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN IF EXISTS uid_number;
ALTER TABLE groups DROP COLUMN IF EXISTS gid_number;
DROP SEQUENCE IF EXISTS users_uid_number_seq;
DROP SEQUENCE IF EXISTS groups_gid_number_seq;
-- +goose StatementEnd
