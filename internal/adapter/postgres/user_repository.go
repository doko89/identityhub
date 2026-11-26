package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/identityhub/identityhub/internal/domain"
)

// UserRepository implements domain.UserStore with pgx.
type UserRepository struct {
	db *DB
}

// NewUserRepository wires a UserStore on the shared pool.
func NewUserRepository(db *DB) *UserRepository { return &UserRepository{db: db} }

const userColumns = `id, username, email, display_name, password_hash, source, external_dn, is_active, avatar_url, created_at, updated_at, uid_number`

func scanUser(row pgx.Row) (domain.User, error) {
	var u domain.User
	var source string
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash,
		&source, &u.ExternalDN, &u.IsActive, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt, &u.UIDNumber)
	if err != nil {
		return domain.User{}, err
	}
	u.Source = domain.UserSource(source)
	return u, nil
}

// Create inserts a user; duplicate username maps to domain.ErrConflict.
func (r *UserRepository) Create(ctx context.Context, u domain.User) (domain.User, error) {
	if err := u.Validate(); err != nil {
		return domain.User{}, err
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	const q = `INSERT INTO users (id, username, email, display_name, password_hash, source, external_dn, is_active, avatar_url)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING ` + userColumns
	created, err := scanUser(r.db.Pool.QueryRow(ctx, q, u.ID, u.Username, u.Email,
		u.DisplayName, u.PasswordHash, string(u.Source), u.ExternalDN, u.IsActive, u.AvatarURL))
	if err != nil {
		return domain.User{}, mapWriteError(err)
	}
	_ = BumpDirectoryVersion(ctx, r.db)
	return created, nil
}

// ByID loads a user by id.
func (r *UserRepository) ByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	u, err := scanUser(r.db.Pool.QueryRow(ctx, q, id))
	if err != nil {
		return domain.User{}, mapReadError(err)
	}
	return u, nil
}

// ByUsername loads a user by exact username.
func (r *UserRepository) ByUsername(ctx context.Context, username string) (domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE username = $1`
	u, err := scanUser(r.db.Pool.QueryRow(ctx, q, username))
	if err != nil {
		return domain.User{}, mapReadError(err)
	}
	return u, nil
}

// ByUsernameFold loads a user by case-insensitive exact username (LDAP
// uid matching is caseIgnoreMatch while the column stays
// case-sensitive). Usernames differing only by case must not be
// created; the lowest id wins.
func (r *UserRepository) ByUsernameFold(ctx context.Context, username string) (domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE lower(username) = lower($1) ORDER BY id LIMIT 1`
	u, err := scanUser(r.db.Pool.QueryRow(ctx, q, username))
	if err != nil {
		return domain.User{}, mapReadError(err)
	}
	return u, nil
}

// AllActive lists every active user in one query (LDAP tree serving).
// treeColumns is the slim projection for directory serving: only what
// the LDAP tree renders. Password hashes must never ride along into a
// cached whole-directory snapshot.
const treeColumns = `id, username, email, display_name, is_active, uid_number`

func (r *UserRepository) AllActive(ctx context.Context) ([]domain.User, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT `+treeColumns+` FROM users WHERE is_active ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.User, error) {
		var u domain.User
		err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.IsActive, &u.UIDNumber)
		return u, err
	})
}

// ByEmail loads the most recently created user with this email.
func (r *UserRepository) ByEmail(ctx context.Context, email string) (domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE email = $1 ORDER BY created_at DESC LIMIT 1`
	u, err := scanUser(r.db.Pool.QueryRow(ctx, q, email))
	if err != nil {
		return domain.User{}, mapReadError(err)
	}
	return u, nil
}

// List returns a page of users plus the total matching count.
func (r *UserRepository) List(ctx context.Context, f domain.UserFilter) ([]domain.User, int, error) {
	limit, offset := page(f.Limit, f.Offset)
	const q = `SELECT ` + userColumns + ` FROM users
		WHERE ($1 = '' OR username ILIKE '%'||$1||'%' OR email ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%')
		  AND ($2 = '' OR source = $2)
		  AND ($3::boolean IS NULL OR is_active = $3)
		ORDER BY created_at DESC LIMIT $4 OFFSET $5`
	rows, err := r.db.Pool.Query(ctx, q, f.Query, string(f.Source), f.Active, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.User, error) {
		return scanUser(row)
	})
	if err != nil {
		return nil, 0, err
	}
	const cq = `SELECT COUNT(*) FROM users
		WHERE ($1 = '' OR username ILIKE '%'||$1||'%' OR email ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%')
		  AND ($2 = '' OR source = $2)
		  AND ($3::boolean IS NULL OR is_active = $3)`
	var total int
	if err := r.db.Pool.QueryRow(ctx, cq, f.Query, string(f.Source), f.Active).Scan(&total); err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// Update rewrites mutable profile fields of an existing user.
func (r *UserRepository) Update(ctx context.Context, u domain.User) (domain.User, error) {
	if err := u.Validate(); err != nil {
		return domain.User{}, err
	}
	const q = `UPDATE users SET email=$2, display_name=$3, external_dn=$4, is_active=$5, avatar_url=$6, updated_at=now()
		WHERE id=$1 RETURNING ` + userColumns
	updated, err := scanUser(r.db.Pool.QueryRow(ctx, q, u.ID, u.Email, u.DisplayName, u.ExternalDN, u.IsActive, u.AvatarURL))
	if err != nil {
		return domain.User{}, mapWriteError(mapReadError(err))
	}
	_ = BumpDirectoryVersion(ctx, r.db)
	return updated, nil
}

// SetActive flips the active flag (used by LDAP sync soft-disable, M1).
func (r *UserRepository) SetActive(ctx context.Context, id uuid.UUID, active bool) error {
	tag, err := r.db.Pool.Exec(ctx, `UPDATE users SET is_active=$2, updated_at=now() WHERE id=$1`, id, active)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	_ = BumpDirectoryVersion(ctx, r.db)
	return nil
}

// SetPasswordHash replaces the password hash and bumps updated_at.
func (r *UserRepository) SetPasswordHash(ctx context.Context, id uuid.UUID, hash []byte) error {
	tag, err := r.db.Pool.Exec(ctx, `UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1`, id, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	_ = BumpDirectoryVersion(ctx, r.db)
	return nil
}

// Delete hard-removes a user row; dependents cascade per schema.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	_ = BumpDirectoryVersion(ctx, r.db)
	return nil
}

func mapReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func mapWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: %s", domain.ErrConflict, pgErr.ConstraintName)
	}
	return err
}

func page(limit, offset int) (int, int) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
