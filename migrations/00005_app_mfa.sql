-- +goose Up
-- +goose StatementBegin
-- M5/M6: per-app MFA policy for regular users (PRD §6.6). Admins always
-- require MFA (enforced in code, no column needed); this flag marks apps
-- whose non-admin users must pass a second factor.
ALTER TABLE applications ADD COLUMN mfa_required BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE applications DROP COLUMN IF EXISTS mfa_required;
-- +goose StatementEnd
