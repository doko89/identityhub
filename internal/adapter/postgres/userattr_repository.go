package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// UserAttrRepository implements domain.UserAttrStore with pgx.
type UserAttrRepository struct {
	db *DB
}

// NewUserAttrRepository wires a UserAttrStore on the shared pool.
func NewUserAttrRepository(db *DB) *UserAttrRepository { return &UserAttrRepository{db: db} }

// CreateDef persists an attribute def; duplicate keys map to
// domain.ErrConflict.
func (r *UserAttrRepository) CreateDef(ctx context.Context, d domain.UserAttrDef) (domain.UserAttrDef, error) {
	if err := d.Validate(); err != nil {
		return domain.UserAttrDef{}, err
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	const q = `INSERT INTO user_attr_defs (id, attr_key, attr_type, multi)
		VALUES ($1,$2,$3,$4) RETURNING id, attr_key, attr_type, multi`
	var created domain.UserAttrDef
	var typ string
	if err := r.db.Pool.QueryRow(ctx, q, d.ID, d.Key, string(d.Type), d.Multi).
		Scan(&created.ID, &created.Key, &typ, &created.Multi); err != nil {
		return domain.UserAttrDef{}, mapWriteError(err)
	}
	created.Type = domain.UserAttrType(typ)
	return created, nil
}

// ListDefs returns every def ordered by key.
func (r *UserAttrRepository) ListDefs(ctx context.Context) ([]domain.UserAttrDef, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT id, attr_key, attr_type, multi FROM user_attr_defs ORDER BY attr_key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.UserAttrDef, error) {
		var d domain.UserAttrDef
		var typ string
		if err := row.Scan(&d.ID, &d.Key, &typ, &d.Multi); err != nil {
			return domain.UserAttrDef{}, err
		}
		d.Type = domain.UserAttrType(typ)
		return d, nil
	})
}

// DeleteDef drops a def; its values cascade via the foreign key.
func (r *UserAttrRepository) DeleteDef(ctx context.Context, key string) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM user_attr_defs WHERE attr_key=$1`, key)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// SetValues replaces the values of the given defs for one user; an
// empty slice clears that def. Other defs are untouched.
func (r *UserAttrRepository) SetValues(ctx context.Context, userID uuid.UUID, values map[uuid.UUID][]string, source domain.UserAttrSource) error {
	if len(values) == 0 {
		return nil
	}
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for defID, vals := range values {
		if _, err := tx.Exec(ctx, `DELETE FROM user_attr_values WHERE user_id=$1 AND def_id=$2`, userID, defID); err != nil {
			return err
		}
		for i, v := range vals {
			if _, err := tx.Exec(ctx, `INSERT INTO user_attr_values (user_id, def_id, ordinal, value, source)
				VALUES ($1,$2,$3,$4,$5)`, userID, defID, i, v, string(source)); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// ApplyUpstreamValues replaces every ldap-sourced value of the user
// with values (marked ldap) and clears ldap-sourced keys missing from
// it. Defs present in values are replaced wholesale regardless of
// previous source: mapped keys are upstream-managed.
func (r *UserAttrRepository) ApplyUpstreamValues(ctx context.Context, userID uuid.UUID, values map[uuid.UUID][]string) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ids := make([]uuid.UUID, 0, len(values))
	for defID := range values {
		ids = append(ids, defID)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_attr_values
		WHERE user_id=$1 AND (source='ldap' OR def_id = ANY($2))`, userID, ids); err != nil {
		return err
	}
	for defID, vals := range values {
		for i, v := range vals {
			if _, err := tx.Exec(ctx, `INSERT INTO user_attr_values (user_id, def_id, ordinal, value, source)
				VALUES ($1,$2,$3,$4,'ldap')`, userID, defID, i, v); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// ValuesOfUser returns keyed values for one user, ordered per key.
func (r *UserAttrRepository) ValuesOfUser(ctx context.Context, userID uuid.UUID) (map[string][]string, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT d.attr_key, v.value FROM user_attr_values v
		JOIN user_attr_defs d ON d.id = v.def_id
		WHERE v.user_id=$1 ORDER BY d.attr_key, v.ordinal`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var key, val string
		if err := rows.Scan(&key, &val); err != nil {
			return nil, err
		}
		out[key] = append(out[key], val)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ValuesForUsers returns keyed values for many users in one query.
func (r *UserAttrRepository) ValuesForUsers(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]map[string][]string, error) {
	out := map[uuid.UUID]map[string][]string{}
	if len(userIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.Pool.Query(ctx, `SELECT v.user_id, d.attr_key, v.value FROM user_attr_values v
		JOIN user_attr_defs d ON d.id = v.def_id
		WHERE v.user_id = ANY($1) ORDER BY v.user_id, d.attr_key, v.ordinal`, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var key, val string
		if err := rows.Scan(&id, &key, &val); err != nil {
			return nil, err
		}
		m, ok := out[id]
		if !ok {
			m = map[string][]string{}
			out[id] = m
		}
		m[key] = append(m[key], val)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

var _ domain.UserAttrStore = (*UserAttrRepository)(nil)
