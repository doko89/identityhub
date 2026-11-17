package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// ApplicationRepository implements domain.ApplicationStore with pgx.
type ApplicationRepository struct {
	db *DB
}

// NewApplicationRepository wires an ApplicationStore on the shared pool.
func NewApplicationRepository(db *DB) *ApplicationRepository {
	return &ApplicationRepository{db: db}
}

const appColumns = `id, slug, name, description, icon_url, launch_url, group_label, provider_type, is_visible, sort_order, mfa_required, open_in_new_tab`

func scanApplication(row pgx.Row) (domain.Application, error) {
	var a domain.Application
	var provider string
	err := row.Scan(&a.ID, &a.Slug, &a.Name, &a.Description, &a.IconURL,
		&a.LaunchURL, &a.GroupLabel, &provider, &a.IsVisible, &a.SortOrder, &a.MFARequired, &a.OpenInNewTab)
	if err != nil {
		return domain.Application{}, err
	}
	a.ProviderType = domain.ProviderType(provider)
	return a, nil
}

// Create inserts an application; a duplicate slug reports domain.ErrConflict.
func (r *ApplicationRepository) Create(ctx context.Context, a domain.Application) (domain.Application, error) {
	if err := a.Validate(); err != nil {
		return domain.Application{}, err
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	const q = `INSERT INTO applications (id, slug, name, description, icon_url, launch_url, group_label, provider_type, is_visible, sort_order, mfa_required, open_in_new_tab)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING ` + appColumns
	created, err := scanApplication(r.db.Pool.QueryRow(ctx, q, a.ID, a.Slug, a.Name,
		a.Description, a.IconURL, a.LaunchURL, a.GroupLabel, string(a.ProviderType),
		a.IsVisible, a.SortOrder, a.MFARequired, a.OpenInNewTab))
	if err != nil {
		return domain.Application{}, mapWriteError(err)
	}
	return created, nil
}

// ByID loads an application by id.
func (r *ApplicationRepository) ByID(ctx context.Context, id uuid.UUID) (domain.Application, error) {
	const q = `SELECT ` + appColumns + ` FROM applications WHERE id = $1`
	a, err := scanApplication(r.db.Pool.QueryRow(ctx, q, id))
	if err != nil {
		return domain.Application{}, mapReadError(err)
	}
	return a, nil
}

// BySlug loads an application by slug.
func (r *ApplicationRepository) BySlug(ctx context.Context, slug string) (domain.Application, error) {
	const q = `SELECT ` + appColumns + ` FROM applications WHERE slug = $1`
	a, err := scanApplication(r.db.Pool.QueryRow(ctx, q, slug))
	if err != nil {
		return domain.Application{}, mapReadError(err)
	}
	return a, nil
}

// List returns applications ordered for the dashboard (sort_order, name),
// plus the total matching count.
func (r *ApplicationRepository) List(ctx context.Context, f domain.AppFilter) ([]domain.Application, int, error) {
	limit, offset := page(f.Limit, f.Offset)
	const q = `SELECT ` + appColumns + ` FROM applications
		WHERE ($1 = '' OR group_label ILIKE '%'||$1||'%')
		ORDER BY sort_order ASC, name ASC LIMIT $2 OFFSET $3`
	rows, err := r.db.Pool.Query(ctx, q, f.Group, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	apps, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Application, error) {
		return scanApplication(row)
	})
	if err != nil {
		return nil, 0, err
	}
	const cq = `SELECT COUNT(*) FROM applications WHERE ($1 = '' OR group_label ILIKE '%'||$1||'%')`
	var total int
	if err := r.db.Pool.QueryRow(ctx, cq, f.Group).Scan(&total); err != nil {
		return nil, 0, err
	}
	return apps, total, nil
}

// Update rewrites the mutable fields of an existing application.
func (r *ApplicationRepository) Update(ctx context.Context, a domain.Application) (domain.Application, error) {
	if err := a.Validate(); err != nil {
		return domain.Application{}, err
	}
	const q = `UPDATE applications
		SET slug=$2, name=$3, description=$4, icon_url=$5, launch_url=$6,
		    group_label=$7, provider_type=$8, is_visible=$9, sort_order=$10, mfa_required=$11, open_in_new_tab=$12
		WHERE id=$1 RETURNING ` + appColumns
	updated, err := scanApplication(r.db.Pool.QueryRow(ctx, q, a.ID, a.Slug, a.Name,
		a.Description, a.IconURL, a.LaunchURL, a.GroupLabel, string(a.ProviderType),
		a.IsVisible, a.SortOrder, a.MFARequired, a.OpenInNewTab))
	if err != nil {
		return domain.Application{}, mapWriteError(mapReadError(err))
	}
	return updated, nil
}

// Delete removes an application (bindings and provider configs cascade).
func (r *ApplicationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// BindingRepository implements domain.BindingStore with pgx.
type BindingRepository struct {
	db *DB
}

// NewBindingRepository wires a BindingStore on the shared pool.
func NewBindingRepository(db *DB) *BindingRepository { return &BindingRepository{db: db} }

func scanBinding(row pgx.Row) (domain.AppBinding, error) {
	var b domain.AppBinding
	var bindingType, evalMode string
	err := row.Scan(&b.ID, &b.ApplicationID, &bindingType, &b.UserID, &b.GroupID, &b.PolicyExpr, &evalMode)
	if err != nil {
		return domain.AppBinding{}, err
	}
	b.BindingType = domain.BindingType(bindingType)
	b.EvalMode = domain.EvalMode(evalMode)
	return b, nil
}

// Create inserts a binding. The usecase validates the one-of invariant;
// the repository maps FK violations to the caller's error as-is.
func (r *BindingRepository) Create(ctx context.Context, b domain.AppBinding) (domain.AppBinding, error) {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	if b.EvalMode == "" {
		b.EvalMode = domain.EvalAny
	}
	const q = `INSERT INTO app_bindings (id, application_id, binding_type, user_id, group_id, policy_expr, eval_mode)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, application_id, binding_type, user_id, group_id, policy_expr, eval_mode`
	created, err := scanBinding(r.db.Pool.QueryRow(ctx, q, b.ID, b.ApplicationID,
		string(b.BindingType), b.UserID, b.GroupID, b.PolicyExpr, string(b.EvalMode)))
	if err != nil {
		return domain.AppBinding{}, mapWriteError(err)
	}
	return created, nil
}

// ForApplication lists every binding of one application.
func (r *BindingRepository) ForApplication(ctx context.Context, appID uuid.UUID) ([]domain.AppBinding, error) {
	const q = `SELECT id, application_id, binding_type, user_id, group_id, policy_expr, eval_mode
		FROM app_bindings WHERE application_id = $1 ORDER BY binding_type, policy_expr`
	rows, err := r.db.Pool.Query(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.AppBinding, error) {
		return scanBinding(row)
	})
}

// Delete removes one binding.
func (r *BindingRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM app_bindings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
