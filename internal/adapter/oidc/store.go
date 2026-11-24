package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"

	"github.com/identityhub/identityhub/internal/domain"
)

// Flow types stored in oidc_flow_sessions.flow_type.
const (
	flowAuthorizeCode = "authorize_code"
	flowAccessToken   = "access_token"
	flowRefreshToken  = "refresh_token"
	flowPKCE          = "pkce"
	flowOpenID        = "openid"
)

// Querier is the pgx surface the store needs: *pgxpool.Pool and pgx.Tx
// both satisfy it.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// namedClientStore optionally resolves the application display name for
// the consent page.
type namedClientStore interface {
	domain.OIDCClientStore
	ClientName(ctx context.Context, applicationID uuid.UUID) (string, error)
}

// lifespans reads token lifetimes for session expiry bookkeeping.
type lifespans interface {
	GetAuthorizeCodeLifespan(ctx context.Context) time.Duration
	GetAccessTokenLifespan(ctx context.Context) time.Duration
	GetRefreshTokenLifespan(ctx context.Context) time.Duration
}

// Store implements fosite's storage interfaces on Postgres:
// ClientManager, oauth2.CoreStorage, oauth2.TokenRevocationStorage,
// PKCERequestStorage and OpenIDConnectRequestStorage. Requesters are
// serialized as JSON; the client is re-resolved from oidc_clients on
// every read so secret/redirect changes apply immediately.
type Store struct {
	q       Querier
	clients domain.OIDCClientStore
	life    lifespans

	// jti guards ClientAssertionJWTValid in memory. No v1 client uses
	// private_key_jwt assertions, so this map only sees traffic if such
	// a grant is composed later; entries expire lazily on write.
	jtiMu sync.Mutex
	jti   map[string]time.Time
}

// NewStore wires fosite storage on q.
func NewStore(q Querier, clients domain.OIDCClientStore, life lifespans) *Store {
	return &Store{q: q, clients: clients, life: life, jti: map[string]time.Time{}}
}

// storedRequest is the JSON form of a fosite requester. The session is
// always *openid.DefaultSession: every handler entry point in provider.go
// constructs one, so ID-token issuance works after a storage round trip.
type storedRequest struct {
	ID                string                 `json:"id"`
	RequestedAt       time.Time              `json:"requested_at"`
	RequestedScope    []string               `json:"requested_scope"`
	GrantedScope      []string               `json:"granted_scope"`
	Form              url.Values             `json:"form"`
	RequestedAudience []string               `json:"requested_audience"`
	GrantedAudience   []string               `json:"granted_audience"`
	Session           *openid.DefaultSession `json:"session"`
}

func encodeRequester(req fosite.Requester) (storedRequest, error) {
	sess, ok := req.GetSession().(*openid.DefaultSession)
	if !ok {
		return storedRequest{}, errors.New("oidc: session must be *openid.DefaultSession")
	}
	return storedRequest{
		ID:                req.GetID(),
		RequestedAt:       req.GetRequestedAt(),
		RequestedScope:    []string(req.GetRequestedScopes()),
		GrantedScope:      []string(req.GetGrantedScopes()),
		Form:              req.GetRequestForm(),
		RequestedAudience: []string(req.GetRequestedAudience()),
		GrantedAudience:   []string(req.GetGrantedAudience()),
		Session:           sess,
	}, nil
}

func (s *Store) decodeRequester(ctx context.Context, raw []byte) (fosite.Requester, error) {
	var sr storedRequest
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, err
	}
	if sr.Session == nil {
		return nil, errors.New("oidc: stored request has no session")
	}
	// The client is re-resolved from oidc_clients by load(), never from
	// the stored blob, so live rows always win over stored copies.
	return &fosite.Request{
		ID:                sr.ID,
		RequestedAt:       sr.RequestedAt,
		RequestedScope:    fosite.Arguments(sr.RequestedScope),
		GrantedScope:      fosite.Arguments(sr.GrantedScope),
		Form:              sr.Form,
		Session:           sr.Session,
		RequestedAudience: fosite.Arguments(sr.RequestedAudience),
		GrantedAudience:   fosite.Arguments(sr.GrantedAudience),
	}, nil
}

// resolveClient attaches the live client row to a decoded request. It
// runs on every read so rotated secrets and redirect changes take effect
// without waiting for outstanding codes to drain.
func (s *Store) resolveClient(ctx context.Context, req *fosite.Request, clientID string) error {
	cl, err := s.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	req.Client = cl
	return nil
}

func (s *Store) put(ctx context.Context, flow, key string, req fosite.Requester, expiresAt time.Time) error {
	sr, err := encodeRequester(req)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(sr)
	if err != nil {
		return err
	}
	const q = `INSERT INTO oidc_flow_sessions (signature, flow_type, request_id, client_id, subject, data, active, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7)
		ON CONFLICT (signature, flow_type) DO UPDATE SET
			request_id = EXCLUDED.request_id, client_id = EXCLUDED.client_id,
			subject = EXCLUDED.subject, data = EXCLUDED.data,
			active = TRUE, expires_at = EXCLUDED.expires_at`
	_, err = s.q.Exec(ctx, q, key, flow, req.GetID(), req.GetClient().GetID(),
		req.GetSession().GetSubject(), raw, expiresAt.UTC())
	return err
}

// storedRow is one oidc_flow_sessions row.
type storedRow struct {
	data      []byte
	active    bool
	expired   bool
	requestID string
	clientID  string
}

// get loads a row without decoding it.
func (s *Store) get(ctx context.Context, flow, key string) (storedRow, error) {
	const q = `SELECT data, active, expires_at <= now(), request_id, client_id
		FROM oidc_flow_sessions WHERE signature = $1 AND flow_type = $2`
	var row storedRow
	err := s.q.QueryRow(ctx, q, key, flow).
		Scan(&row.data, &row.active, &row.expired, &row.requestID, &row.clientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storedRow{}, fosite.ErrNotFound
		}
		return storedRow{}, err
	}
	return row, nil
}

func (s *Store) delete(ctx context.Context, flow, key string) error {
	_, err := s.q.Exec(ctx, `DELETE FROM oidc_flow_sessions WHERE signature = $1 AND flow_type = $2`, key, flow)
	return err
}

// load decodes a row into a live requester, resolving the current client.
func (s *Store) load(ctx context.Context, row storedRow) (fosite.Requester, error) {
	decoded, err := s.decodeRequester(ctx, row.data)
	if err != nil {
		return nil, err
	}
	req, ok := decoded.(*fosite.Request)
	if !ok {
		return nil, errors.New("oidc: decoded request has unexpected type")
	}
	if err := s.resolveClient(ctx, req, row.clientID); err != nil {
		return nil, err
	}
	return req, nil
}

// loadLive enforces expiry: expired rows are deleted and report NotFound.
func (s *Store) loadLive(ctx context.Context, flow, key string) (fosite.Requester, storedRow, error) {
	row, err := s.get(ctx, flow, key)
	if err != nil {
		return nil, storedRow{}, err
	}
	if row.expired {
		_ = s.delete(ctx, flow, key)
		return nil, storedRow{}, fosite.ErrNotFound
	}
	req, err := s.load(ctx, row)
	if err != nil {
		return nil, storedRow{}, err
	}
	return req, row, nil
}

// ---------- clients ----------

// oidcClient is a fosite client backed by an oidc_clients row.
type oidcClient struct {
	*fosite.DefaultClient
	name string
}

// GetName reports the application display name for the consent page.
func (c *oidcClient) GetName() string { return c.name }

// GetResponseModes implements fosite.ResponseModeClient: without it
// fosite rejects every explicit response_mode (including form_post,
// which .NET-based clients like Technitium send by default) with
// invalid_request. Flow-level validity stays enforced by fosite.
func (c *oidcClient) GetResponseModes() []fosite.ResponseModeType {
	return []fosite.ResponseModeType{
		fosite.ResponseModeQuery,
		fosite.ResponseModeFragment,
		fosite.ResponseModeFormPost,
	}
}

// GetClient implements fosite.ClientManager. Only the authorization-code
// (+refresh) grant with response_type=code is served; secrets stay
// bcrypt-hashed in the database and are compared inside fosite.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	c, err := s.clients.GetByClientID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	name := c.ClientID
	if named, ok := s.clients.(namedClientStore); ok {
		if n, err := named.ClientName(ctx, c.ApplicationID); err == nil && n != "" {
			name = n
		}
	}
	return &oidcClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            c.ClientID,
			Secret:        c.ClientSecretHash,
			RedirectURIs:  c.RedirectURIs,
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        c.Scopes,
			Public:        len(c.ClientSecretHash) == 0,
		},
		name: name,
	}, nil
}

// ClientAssertionJWTValid implements fosite.ClientManager (in-memory;
// see Store.jti).
func (s *Store) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.jtiMu.Lock()
	defer s.jtiMu.Unlock()
	if exp, ok := s.jti[jti]; ok && exp.After(time.Now()) {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT implements fosite.ClientManager.
func (s *Store) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	s.jtiMu.Lock()
	defer s.jtiMu.Unlock()
	now := time.Now()
	for k, e := range s.jti {
		if e.Before(now) {
			delete(s.jti, k)
		}
	}
	if _, ok := s.jti[jti]; ok {
		return fosite.ErrJTIKnown
	}
	s.jti[jti] = exp
	return nil
}

// ---------- authorize codes ----------

// CreateAuthorizeCodeSession implements oauth2.AuthorizeCodeStorage.
func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	return s.put(ctx, flowAuthorizeCode, code, req,
		time.Now().Add(s.life.GetAuthorizeCodeLifespan(ctx)))
}

// GetAuthorizeCodeSession implements oauth2.AuthorizeCodeStorage. Used
// codes report ErrInvalidatedAuthorizeCode together with the requester so
// fosite can run reuse detection.
func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	req, row, err := s.loadLive(ctx, flowAuthorizeCode, code)
	if err != nil {
		return nil, err
	}
	if !row.active {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}
	return req, nil
}

// InvalidateAuthorizeCodeSession implements oauth2.AuthorizeCodeStorage.
func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	tag, err := s.q.Exec(ctx, `UPDATE oidc_flow_sessions SET active = FALSE
		WHERE signature = $1 AND flow_type = $2`, code, flowAuthorizeCode)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// ---------- access tokens ----------

// CreateAccessTokenSession implements oauth2.AccessTokenStorage.
func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	exp := req.GetSession().GetExpiresAt(fosite.AccessToken)
	if exp.IsZero() {
		exp = time.Now().Add(s.life.GetAccessTokenLifespan(ctx))
	}
	return s.put(ctx, flowAccessToken, signature, req, exp)
}

// GetAccessTokenSession implements oauth2.AccessTokenStorage.
func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	req, _, err := s.loadLive(ctx, flowAccessToken, signature)
	return req, err
}

// DeleteAccessTokenSession implements oauth2.AccessTokenStorage.
func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, flowAccessToken, signature)
}

// ---------- refresh tokens ----------

// CreateRefreshTokenSession implements oauth2.RefreshTokenStorage.
func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature, _ string, req fosite.Requester) error {
	exp := req.GetSession().GetExpiresAt(fosite.RefreshToken)
	if exp.IsZero() {
		exp = time.Now().Add(s.life.GetRefreshTokenLifespan(ctx))
	}
	return s.put(ctx, flowRefreshToken, signature, req, exp)
}

// GetRefreshTokenSession implements oauth2.RefreshTokenStorage. Rotated
// tokens report ErrInactiveToken with the requester so fosite revokes the
// whole grant (refresh-reuse detection, RFC 6819 §5.2.2.3).
func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	req, row, err := s.loadLive(ctx, flowRefreshToken, signature)
	if err != nil {
		return nil, err
	}
	if !row.active {
		return req, fosite.ErrInactiveToken
	}
	return req, nil
}

// DeleteRefreshTokenSession implements oauth2.RefreshTokenStorage.
func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, flowRefreshToken, signature)
}

// RotateRefreshToken implements oauth2.RefreshTokenStorage: the old
// refresh token dies and its access token is revoked (rotation).
func (s *Store) RotateRefreshToken(ctx context.Context, requestID, _ string) error {
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}
	return s.RevokeAccessToken(ctx, requestID)
}

// RevokeRefreshToken implements oauth2.TokenRevocationStorage: every
// refresh token of the grant goes inactive (reuse becomes detectable).
func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.q.Exec(ctx, `UPDATE oidc_flow_sessions SET active = FALSE
		WHERE request_id = $1 AND flow_type = $2`, requestID, flowRefreshToken)
	return err
}

// RevokeAccessToken implements oauth2.TokenRevocationStorage.
func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.q.Exec(ctx, `DELETE FROM oidc_flow_sessions
		WHERE request_id = $1 AND flow_type = $2`, requestID, flowAccessToken)
	return err
}

// ---------- PKCE ----------

// CreatePKCERequestSession implements pkce.PKCERequestStorage.
func (s *Store) CreatePKCERequestSession(ctx context.Context, code string, req fosite.Requester) error {
	return s.put(ctx, flowPKCE, code, req,
		time.Now().Add(s.life.GetAuthorizeCodeLifespan(ctx)))
}

// GetPKCERequestSession implements pkce.PKCERequestStorage.
func (s *Store) GetPKCERequestSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	req, _, err := s.loadLive(ctx, flowPKCE, code)
	return req, err
}

// DeletePKCERequestSession implements pkce.PKCERequestStorage.
func (s *Store) DeletePKCERequestSession(ctx context.Context, code string) error {
	return s.delete(ctx, flowPKCE, code)
}

// ---------- OIDC sessions ----------

// CreateOpenIDConnectSession implements openid.OpenIDConnectRequestStorage.
func (s *Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	return s.put(ctx, flowOpenID, authorizeCode, req,
		time.Now().Add(s.life.GetAuthorizeCodeLifespan(ctx)))
}

// GetOpenIDConnectSession implements openid.OpenIDConnectRequestStorage.
func (s *Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	req, _, err := s.loadLive(ctx, flowOpenID, authorizeCode)
	return req, err
}

// DeleteOpenIDConnectSession implements openid.OpenIDConnectRequestStorage.
func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.delete(ctx, flowOpenID, authorizeCode)
}
