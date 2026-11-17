package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identityhub/identityhub/internal/domain"
)

// OIDCClientRepository implements domain.OIDCClientStore with pgx.
// ClientName for the consent page comes from a join with applications.
type OIDCClientRepository struct {
	db *DB
}

// NewOIDCClientRepository wires an OIDCClientStore on the shared pool.
func NewOIDCClientRepository(db *DB) *OIDCClientRepository {
	return &OIDCClientRepository{db: db}
}

const oidcClientColumns = `c.id, c.application_id, c.client_id, c.client_secret_hash, c.redirect_uris, c.scopes`

func scanOIDCClient(row pgx.Row) (domain.OIDCClient, error) {
	var c domain.OIDCClient
	err := row.Scan(&c.ID, &c.ApplicationID, &c.ClientID,
		&c.ClientSecretHash, &c.RedirectURIs, &c.Scopes)
	if err != nil {
		return domain.OIDCClient{}, err
	}
	return c, nil
}

// GetByClientID loads a client by its public client_id.
func (r *OIDCClientRepository) GetByClientID(ctx context.Context, clientID string) (domain.OIDCClient, error) {
	const q = `SELECT ` + oidcClientColumns + ` FROM oidc_clients c WHERE c.client_id = $1`
	c, err := scanOIDCClient(r.db.Pool.QueryRow(ctx, q, clientID))
	if err != nil {
		return domain.OIDCClient{}, mapReadError(err)
	}
	return c, nil
}

// ClientName returns the application name for the consent page.
func (r *OIDCClientRepository) ClientName(ctx context.Context, applicationID uuid.UUID) (string, error) {
	const q = `SELECT name FROM applications WHERE id = $1`
	var name string
	if err := r.db.Pool.QueryRow(ctx, q, applicationID).Scan(&name); err != nil {
		return "", mapReadError(err)
	}
	return name, nil
}

// Create persists a client; ClientSecretHash must already be hashed
// (nil for public PKCE-only clients). ApplicationID must exist.
func (r *OIDCClientRepository) Create(ctx context.Context, c domain.OIDCClient) (domain.OIDCClient, error) {
	if c.ClientID == "" || c.ApplicationID == uuid.Nil {
		return domain.OIDCClient{}, fmt.Errorf("%w: oidc client_id and application are required", domain.ErrValidation)
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	const q = `INSERT INTO oidc_clients (id, application_id, client_id, client_secret_hash, redirect_uris, scopes)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, application_id, client_id, client_secret_hash, redirect_uris, scopes`
	created, err := scanOIDCClient(r.db.Pool.QueryRow(ctx, q, c.ID, c.ApplicationID,
		c.ClientID, c.ClientSecretHash, c.RedirectURIs, c.Scopes))
	if err != nil {
		return domain.OIDCClient{}, mapWriteError(err)
	}
	return created, nil
}

// Delete removes a client by its public client_id.
func (r *OIDCClientRepository) Delete(ctx context.Context, clientID string) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM oidc_clients WHERE client_id = $1`, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// List returns a page of clients plus the total count.
func (r *OIDCClientRepository) List(ctx context.Context, limit, offset int) ([]domain.OIDCClient, int, error) {
	limit, offset = page(limit, offset)
	rows, err := r.db.Pool.Query(ctx, `SELECT `+oidcClientColumns+
		` FROM oidc_clients c ORDER BY c.client_id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.OIDCClient
	for rows.Next() {
		c, err := scanOIDCClient(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var total int
	if err := r.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM oidc_clients`).Scan(&total); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// OIDCConsentRepository implements domain.OIDCConsentStore with pgx.
type OIDCConsentRepository struct {
	db *DB
}

// NewOIDCConsentRepository wires an OIDCConsentStore on the shared pool.
func NewOIDCConsentRepository(db *DB) *OIDCConsentRepository {
	return &OIDCConsentRepository{db: db}
}

// Get loads the remembered grant; missing grants report ErrNotFound.
func (r *OIDCConsentRepository) Get(ctx context.Context, userID uuid.UUID, clientID string) (domain.OIDCConsent, error) {
	const q = `SELECT user_id, client_id, scopes, granted_at FROM oidc_consents
		WHERE user_id = $1 AND client_id = $2`
	var c domain.OIDCConsent
	if err := r.db.Pool.QueryRow(ctx, q, userID, clientID).
		Scan(&c.UserID, &c.ClientID, &c.Scopes, &c.GrantedAt); err != nil {
		return domain.OIDCConsent{}, mapReadError(err)
	}
	return c, nil
}

// Grant upserts the remembered scopes for user+client.
func (r *OIDCConsentRepository) Grant(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	const q = `INSERT INTO oidc_consents (user_id, client_id, scopes, granted_at)
		VALUES ($1,$2,$3,now())
		ON CONFLICT (user_id, client_id)
		DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = now()`
	_, err := r.db.Pool.Exec(ctx, q, userID, clientID, scopes)
	return err
}

// Revoke forgets the grant; unknown grants report ErrNotFound.
func (r *OIDCConsentRepository) Revoke(ctx context.Context, userID uuid.UUID, clientID string) error {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM oidc_consents WHERE user_id = $1 AND client_id = $2`,
		userID, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// OIDCChallengeRepository implements domain.OIDCConsentChallengeStore.
type OIDCChallengeRepository struct {
	db *DB
}

// NewOIDCChallengeRepository wires a challenge store on the shared pool.
func NewOIDCChallengeRepository(db *DB) *OIDCChallengeRepository {
	return &OIDCChallengeRepository{db: db}
}

func scanChallenge(row pgx.Row) (domain.OIDCConsentChallenge, error) {
	var c domain.OIDCConsentChallenge
	err := row.Scan(&c.Challenge, &c.UserID, &c.ClientID, &c.Query, &c.ExpiresAt)
	if err != nil {
		return domain.OIDCConsentChallenge{}, err
	}
	return c, nil
}

// Create persists a challenge; collisions (same 256-bit value twice) map
// to a plain error so the caller can retry with fresh randomness.
func (r *OIDCChallengeRepository) Create(ctx context.Context, c domain.OIDCConsentChallenge) error {
	const q = `INSERT INTO oidc_consent_challenges (challenge, user_id, client_id, query, expires_at)
		VALUES ($1,$2,$3,$4,$5)`
	_, err := r.db.Pool.Exec(ctx, q, c.Challenge, c.UserID, c.ClientID, c.Query, c.ExpiresAt)
	return err
}

// Get loads a live challenge; expired or missing ones report ErrNotFound.
func (r *OIDCChallengeRepository) Get(ctx context.Context, challenge string) (domain.OIDCConsentChallenge, error) {
	const q = `SELECT challenge, user_id, client_id, query, expires_at
		FROM oidc_consent_challenges WHERE challenge = $1 AND expires_at > now()`
	c, err := scanChallenge(r.db.Pool.QueryRow(ctx, q, challenge))
	if err != nil {
		return domain.OIDCConsentChallenge{}, mapReadError(err)
	}
	return c, nil
}

// Consume deletes a live challenge and returns it. The delete is the
// read: a second consume finds no row, so double submits fail closed.
func (r *OIDCChallengeRepository) Consume(ctx context.Context, challenge string) (domain.OIDCConsentChallenge, error) {
	const q = `DELETE FROM oidc_consent_challenges
		WHERE challenge = $1 AND expires_at > now()
		RETURNING challenge, user_id, client_id, query, expires_at`
	c, err := scanChallenge(r.db.Pool.QueryRow(ctx, q, challenge))
	if err != nil {
		return domain.OIDCConsentChallenge{}, mapReadError(err)
	}
	return c, nil
}
