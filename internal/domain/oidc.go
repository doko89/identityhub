package domain

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Standard OIDC scopes recognized by the provider (TECH_SPEC §6.2).
// `offline_access` (alias `offline`) gates refresh-token issuance.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeGroups        = "groups"
	ScopeOfflineAccess = "offline_access"
	ScopeOffline       = "offline"
)

// OIDCAuthRequest is the fosite-free view of an authorize request: what
// the user must authenticate for and consent to. Produced by
// OIDCProvider.ParseAuthorizeRequest, consumed by usecase/oidcflow.
type OIDCAuthRequest struct {
	ClientID        string
	ClientName      string
	RedirectURI     string
	RequestedScopes []string
	State           string
}

// OIDCDecision is the authenticated user's answer to an authorize
// request: identity claims plus the granted scopes. The adapter turns it
// into authorize-code/ID-token issuance; it never sees passwords.
type OIDCDecision struct {
	Subject       string // stable user UUID (sub claim)
	Username      string // preferred_username claim
	Email         string // email claim
	Name          string // name claim
	Groups        []string
	GrantedScopes []string
	// CustomAttrs carries custom attributes as typed claims
	// (single-valued scalars, multi-valued arrays).
	CustomAttrs map[string]any
}

// OIDCClientStore is the port for per-app OIDC client registration
// (PRD §6.3). Secrets are stored hashed (bcrypt, for fosite); public
// PKCE-only clients carry a nil hash.
type OIDCClientStore interface {
	GetByClientID(ctx context.Context, clientID string) (OIDCClient, error)
	// Create persists a client; ClientSecretHash must already be hashed.
	Create(ctx context.Context, c OIDCClient) (OIDCClient, error)
	Delete(ctx context.Context, clientID string) error
	List(ctx context.Context, limit, offset int) ([]OIDCClient, int, error)
}

// ClientSecretHasher hashes OIDC client secrets (bcrypt, for fosite).
// Implemented in internal/adapter/oidc; registration flows hash through
// this port so usecases never touch the OIDC library.
type ClientSecretHasher interface {
	HashSecret(plain string) ([]byte, error)
}

// OIDCConsent is a remembered scope grant from a user to a client.
type OIDCConsent struct {
	UserID    uuid.UUID
	ClientID  string
	Scopes    []string
	GrantedAt time.Time
}

// OIDCConsentStore remembers consent-page decisions so repeat logins to
// the same client skip the page when the grant still covers the request.
type OIDCConsentStore interface {
	Get(ctx context.Context, userID uuid.UUID, clientID string) (OIDCConsent, error)
	// Grant upserts the remembered scopes for user+client.
	Grant(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error
	Revoke(ctx context.Context, userID uuid.UUID, clientID string) error
}

// OIDCConsentChallenge carries an authorize request across the
// consent-page round trip. Query is the raw authorize query, stored
// server-side and re-parsed on decision — the browser only holds the
// opaque challenge.
type OIDCConsentChallenge struct {
	Challenge string
	UserID    uuid.UUID
	ClientID  string
	Query     string
	ExpiresAt time.Time
}

// OIDCConsentChallengeStore persists challenges with a short TTL.
type OIDCConsentChallengeStore interface {
	Create(ctx context.Context, c OIDCConsentChallenge) error
	// Consume returns the challenge and deletes it atomically; repeat
	// consumption (double submit) reports ErrNotFound.
	Consume(ctx context.Context, challenge string) (OIDCConsentChallenge, error)
	Get(ctx context.Context, challenge string) (OIDCConsentChallenge, error)
}

// OIDCProvider is the domain-owned OIDC port (TECH_SPEC §2): fosite sits
// behind it in internal/adapter/oidc and can be swapped without touching
// usecases or delivery. Authorize calls re-parse the HTTP request, so no
// fosite type crosses the boundary — including across the consent
// round trip, where the stored raw query is re-parsed.
type OIDCProvider interface {
	// ParseAuthorizeRequest validates an authorize request and returns
	// its public parameters for the login/consent flow.
	ParseAuthorizeRequest(ctx context.Context, r *http.Request) (OIDCAuthRequest, error)
	// FinishAuthorizeRequest re-validates and issues the authorize
	// response: a 302 to the client redirect_uri with the code.
	FinishAuthorizeRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, d OIDCDecision) error
	// DenyAuthorizeRequest redirects with access_denied.
	DenyAuthorizeRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error
	// WriteAuthorizeError answers a failed authorize request the
	// OAuth2 way (redirect with error code when possible).
	WriteAuthorizeError(ctx context.Context, w http.ResponseWriter, r *http.Request, err error)
	// HandleToken serves POST /oauth2/token (code exchange + refresh).
	HandleToken(ctx context.Context, w http.ResponseWriter, r *http.Request)
	// HandleUserinfo serves GET /oauth2/userinfo.
	HandleUserinfo(ctx context.Context, w http.ResponseWriter, r *http.Request)
	// HandleDiscovery serves GET /.well-known/openid-configuration.
	HandleDiscovery(w http.ResponseWriter, r *http.Request)
	// HandleJWKS serves GET /oauth2/jwks.
	HandleJWKS(w http.ResponseWriter, r *http.Request)
}
