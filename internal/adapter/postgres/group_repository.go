package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// GroupRepository implements domain.GroupStore with pgx.
type GroupRepository struct {
	db *DB
}

// NewGroupRepository wires a GroupStore on the shared pool.
func NewGroupRepository(db *DB) *GroupRepository { return &GroupRepository{db: db} }

// Create inserts a group; duplicate name maps to domain.ErrConflict.
func (r *GroupRepository) Create(ctx context.Context, g domain.Group) (domain.Group, error) {
	if err := g.Validate(); err != nil {
		return domain.Group{}, err
	}
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	const q = `INSERT INTO groups (id, name, description) VALUES ($1,$2,$3) RETURNING id, name, description`
	var created domain.Group
	if err := r.db.Pool.QueryRow(ctx, q, g.ID, g.Name, g.Description).Scan(&created.ID, &created.Name, &created.Description); err != nil {
		return domain.Group{}, mapWriteError(err)
	}
	return created, nil
}

// ByID loads a group by id.
func (r *GroupRepository) ByID(ctx context.Context, id uuid.UUID) (domain.Group, error) {
	var g domain.Group
	err := r.db.Pool.QueryRow(ctx, `SELECT id, name, description FROM groups WHERE id=$1`, id).
		Scan(&g.ID, &g.Name, &g.Description)
	if err != nil {
		return domain.Group{}, mapReadError(err)
	}
	return g, nil
}

// ByName loads a group by exact name.
func (r *GroupRepository) ByName(ctx context.Context, name string) (domain.Group, error) {
	var g domain.Group
	err := r.db.Pool.QueryRow(ctx, `SELECT id, name, description FROM groups WHERE name=$1`, name).
		Scan(&g.ID, &g.Name, &g.Description)
	if err != nil {
		return domain.Group{}, mapReadError(err)
	}
	return g, nil
}

// List returns a page of groups plus the total count.
func (r *GroupRepository) List(ctx context.Context, limit, offset int) ([]domain.Group, int, error) {
	limit, offset = page(limit, offset)
	rows, err := r.db.Pool.Query(ctx, `SELECT id, name, description FROM groups ORDER BY name LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Group, error) {
		var g domain.Group
		err := row.Scan(&g.ID, &g.Name, &g.Description)
		return g, err
	})
	if err != nil {
		return nil, 0, err
	}
	var total int
	if err := r.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM groups`).Scan(&total); err != nil {
		return nil, 0, err
	}
	return groups, total, nil
}

// Delete removes a group. Deleting ih_admin is refused here (defense in
// depth — the database trigger refuses it too).
func (r *GroupRepository) Delete(ctx context.Context, id uuid.UUID) error {
	g, err := r.ByID(ctx, id)
	if err != nil {
		return err
	}
	if g.Name == domain.AdminGroup {
		return domain.ErrForbidden
	}
	_, err = r.db.Pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, id)
	return err
}

// AddMember adds a user to a group (idempotent).
func (r *GroupRepository) AddMember(ctx context.Context, userID, groupID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `INSERT INTO user_groups (user_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, userID, groupID)
	return err
}

// RemoveMember removes a user from a group.
func (r *GroupRepository) RemoveMember(ctx context.Context, userID, groupID uuid.UUID) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM user_groups WHERE user_id=$1 AND group_id=$2`, userID, groupID)
	return err
}

// MemberIDs lists member user ids of a group.
func (r *GroupRepository) MemberIDs(ctx context.Context, groupID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT user_id FROM user_groups WHERE group_id=$1`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (uuid.UUID, error) {
		var id uuid.UUID
		err := row.Scan(&id)
		return id, err
	})
}

// GroupsOfUser lists the groups a user belongs to.
func (r *GroupRepository) GroupsOfUser(ctx context.Context, userID uuid.UUID) ([]domain.Group, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT g.id, g.name, g.description FROM groups g
		JOIN user_groups ug ON ug.group_id = g.id WHERE ug.user_id=$1 ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Group, error) {
		var g domain.Group
		err := row.Scan(&g.ID, &g.Name, &g.Description)
		return g, err
	})
}

// IsMember reports membership by group name (used by the ih_admin guard).
func (r *GroupRepository) IsMember(ctx context.Context, userID uuid.UUID, groupName string) (bool, error) {
	var exists bool
	err := r.db.Pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM user_groups ug JOIN groups g ON g.id = ug.group_id
		WHERE ug.user_id=$1 AND g.name=$2)`, userID, groupName).Scan(&exists)
	return exists, err
}
