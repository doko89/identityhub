package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// RADIUSClientRepository implements domain.RADIUSClientStore with pgx.
// SharedSecretEnc must already be sealed (crypto.Seal with ENC_KEY);
// this repository never sees plaintext secrets.
type RADIUSClientRepository struct {
	db *DB
}

// NewRADIUSClientRepository wires a RADIUSClientStore on the shared pool.
func NewRADIUSClientRepository(db *DB) *RADIUSClientRepository {
	return &RADIUSClientRepository{db: db}
}

// Create inserts a NAS client; duplicate nas_identifier or a second
// client for the same application maps to domain.ErrConflict.
func (r *RADIUSClientRepository) Create(ctx context.Context, c domain.RADIUSClient) (domain.RADIUSClient, error) {
	if c.NASIdentifier == "" {
		return domain.RADIUSClient{}, fmt.Errorf("%w: nas identifier is required", domain.ErrValidation)
	}
	if len(c.SharedSecretEnc) == 0 {
		return domain.RADIUSClient{}, fmt.Errorf("%w: sealed shared secret is required", domain.ErrValidation)
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	const q = `INSERT INTO radius_clients (id, application_id, nas_identifier, shared_secret_enc)
		VALUES ($1,$2,$3,$4)
		RETURNING id, application_id, nas_identifier, shared_secret_enc`
	var created domain.RADIUSClient
	err := r.db.Pool.QueryRow(ctx, q, c.ID, c.ApplicationID, c.NASIdentifier, c.SharedSecretEnc).
		Scan(&created.ID, &created.ApplicationID, &created.NASIdentifier, &created.SharedSecretEnc)
	if err != nil {
		return domain.RADIUSClient{}, mapWriteError(err)
	}
	return created, nil
}

// ByNASIdentifier loads a NAS client by its identifier (source IP).
func (r *RADIUSClientRepository) ByNASIdentifier(ctx context.Context, nasIdentifier string) (domain.RADIUSClient, error) {
	const q = `SELECT id, application_id, nas_identifier, shared_secret_enc
		FROM radius_clients WHERE nas_identifier = $1`
	var c domain.RADIUSClient
	err := r.db.Pool.QueryRow(ctx, q, nasIdentifier).
		Scan(&c.ID, &c.ApplicationID, &c.NASIdentifier, &c.SharedSecretEnc)
	if err != nil {
		return domain.RADIUSClient{}, mapReadError(err)
	}
	return c, nil
}
