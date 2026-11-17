package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// SAMLSPRepository implements domain.SAMLSPStore with pgx.
type SAMLSPRepository struct {
	db *DB
}

// NewSAMLSPRepository wires an SAMLSPStore on the shared pool.
func NewSAMLSPRepository(db *DB) *SAMLSPRepository {
	return &SAMLSPRepository{db: db}
}

const samlSPColumns = `id, application_id, entity_id, acs_url, slo_url, metadata_xml, cert_pem`

func scanSAMLSP(row pgx.Row) (domain.SAMLServiceProvider, error) {
	var sp domain.SAMLServiceProvider
	err := row.Scan(&sp.ID, &sp.ApplicationID, &sp.EntityID,
		&sp.ACSURL, &sp.SLOURL, &sp.MetadataXML, &sp.CertPEM)
	if err != nil {
		return domain.SAMLServiceProvider{}, err
	}
	return sp, nil
}

// GetByEntityID loads an SP by its entity ID.
func (r *SAMLSPRepository) GetByEntityID(ctx context.Context, entityID string) (domain.SAMLServiceProvider, error) {
	const q = `SELECT ` + samlSPColumns + ` FROM saml_sps WHERE entity_id = $1`
	sp, err := scanSAMLSP(r.db.Pool.QueryRow(ctx, q, entityID))
	if err != nil {
		return domain.SAMLServiceProvider{}, mapReadError(err)
	}
	return sp, nil
}

// Create persists an SP; EntityID and ACSURL are required. ApplicationID
// must reference an existing application row.
func (r *SAMLSPRepository) Create(ctx context.Context, sp domain.SAMLServiceProvider) (domain.SAMLServiceProvider, error) {
	if sp.EntityID == "" || sp.ACSURL == "" || sp.ApplicationID == uuid.Nil {
		return domain.SAMLServiceProvider{}, fmt.Errorf("%w: saml entity_id, acs_url and application are required", domain.ErrValidation)
	}
	if sp.ID == uuid.Nil {
		sp.ID = uuid.New()
	}
	const q = `INSERT INTO saml_sps (id, application_id, entity_id, acs_url, slo_url, metadata_xml, cert_pem)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, application_id, entity_id, acs_url, slo_url, metadata_xml, cert_pem`
	created, err := scanSAMLSP(r.db.Pool.QueryRow(ctx, q, sp.ID, sp.ApplicationID,
		sp.EntityID, sp.ACSURL, sp.SLOURL, sp.MetadataXML, sp.CertPEM))
	if err != nil {
		return domain.SAMLServiceProvider{}, mapWriteError(err)
	}
	return created, nil
}

// Delete removes an SP by its entity ID.
func (r *SAMLSPRepository) Delete(ctx context.Context, entityID string) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM saml_sps WHERE entity_id = $1`, entityID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// List returns a page of SPs plus the total count.
func (r *SAMLSPRepository) List(ctx context.Context, limit, offset int) ([]domain.SAMLServiceProvider, int, error) {
	limit, offset = page(limit, offset)
	rows, err := r.db.Pool.Query(ctx, `SELECT `+samlSPColumns+
		` FROM saml_sps ORDER BY entity_id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.SAMLServiceProvider
	for rows.Next() {
		sp, err := scanSAMLSP(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var total int
	if err := r.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM saml_sps`).Scan(&total); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ApplicationID resolves the application row of an SP for audit.
func (r *SAMLSPRepository) ApplicationID(ctx context.Context, entityID string) (uuid.UUID, error) {
	const q = `SELECT application_id FROM saml_sps WHERE entity_id = $1`
	var id uuid.UUID
	if err := r.db.Pool.QueryRow(ctx, q, entityID).Scan(&id); err != nil {
		return uuid.Nil, mapReadError(err)
	}
	return id, nil
}

// SAMLRequestRepository implements domain.SAMLRequestStore with pgx.
type SAMLRequestRepository struct {
	db *DB
}

// NewSAMLRequestRepository wires a request store on the shared pool.
func NewSAMLRequestRepository(db *DB) *SAMLRequestRepository {
	return &SAMLRequestRepository{db: db}
}

// Create persists a stashed SSO request; collisions (same 256-bit value
// twice) surface as a plain error so the caller can retry with fresh
// randomness.
func (r *SAMLRequestRepository) Create(ctx context.Context, sr domain.SAMLRequest) error {
	const q = `INSERT INTO saml_requests (challenge, method, target, content_type, expires_at)
		VALUES ($1,$2,$3,$4,$5)`
	_, err := r.db.Pool.Exec(ctx, q, sr.Challenge, sr.Method, sr.Target, sr.ContentType, sr.ExpiresAt)
	return err
}

// Get loads a live request; expired or missing ones report ErrNotFound.
func (r *SAMLRequestRepository) Get(ctx context.Context, challenge string) (domain.SAMLRequest, error) {
	const q = `SELECT challenge, method, target, content_type, expires_at
		FROM saml_requests WHERE challenge = $1 AND expires_at > now()`
	var sr domain.SAMLRequest
	if err := r.db.Pool.QueryRow(ctx, q, challenge).
		Scan(&sr.Challenge, &sr.Method, &sr.Target, &sr.ContentType, &sr.ExpiresAt); err != nil {
		return domain.SAMLRequest{}, mapReadError(err)
	}
	return sr, nil
}

// Delete drops a request (best-effort cleanup after issuance); unknown
// challenges report ErrNotFound.
func (r *SAMLRequestRepository) Delete(ctx context.Context, challenge string) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM saml_requests WHERE challenge = $1`, challenge)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
