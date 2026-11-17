-- +goose Up
-- +goose StatementBegin
-- Monotonic directory generation for LDAP cache invalidation. Every
-- repository write that affects the served tree (users, groups,
-- memberships, MFA outcome) bumps the counter in the same spirit as the
-- write itself; the LDAP provider compares it before serving a cached
-- snapshot, so invalidations work across the serve/worker processes.
CREATE TABLE directory_version (
    id         INT PRIMARY KEY CHECK (id = 1),
    version    BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO directory_version (id, version) VALUES (1, 1) ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS directory_version;
-- +goose StatementEnd
