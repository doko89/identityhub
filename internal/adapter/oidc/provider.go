// Package oidc wraps ory/fosite behind the domain.OIDCProvider port
// (TECH_SPEC §2): grant flows, PKCE, refresh rotation and ID-token
// signing come from fosite; client, consent and session data live in
// Postgres. No other package imports fosite — the swap boundary is this
// package plus domain/oidc.go.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/identityhub/identityhub/internal/domain"
)

// Token lifespans (TECH_SPEC §6.2). Refresh rotation always applies:
// using a refresh token revokes it and its access token.
const (
	AccessTokenLifespan   = time.Hour
	RefreshTokenLifespan  = 30 * 24 * time.Hour
	AuthorizeCodeLifespan = 10 * time.Minute
	IDTokenLifespan       = time.Hour
)

// Config wires the provider. Issuer is the public origin (APP_BASE_URL);
// GlobalSecret signs HMAC tokens (ENC_KEY, 32 bytes).
type Config struct {
	Issuer       string
	GlobalSecret []byte
	// SendDebug exposes fosite debug messages to clients. Development
	// only — production must leave it false.
	SendDebug bool
}

// Provider implements domain.OIDCProvider with fosite.
type Provider struct {
	oauth2 *fosite.Fosite
	store  *Store
	config *fosite.Config
	issuer string
	key    *rsa.PrivateKey
	kid    string
}

// KeyGetter abstracts the RSA signing key source (keys.go).
type KeyGetter struct {
	Key *rsa.PrivateKey
	KID string
}

// New composes fosite with the authorize-code, refresh, OIDC explicit,
// OIDC refresh, introspection (for userinfo) and PKCE handlers. Only
// response_type=code is served; implicit/hybrid grants stay disabled.
func New(ctx context.Context, q Querier, clients domain.OIDCClientStore, cfg Config) (*Provider, error) {
	if strings.TrimRight(cfg.Issuer, "/") == "" {
		return nil, errors.New("oidc: Issuer is required")
	}
	if len(cfg.GlobalSecret) < 32 {
		return nil, errors.New("oidc: GlobalSecret must be at least 32 bytes")
	}
	kg, err := LoadOrGenerateKey(ctx, q)
	if err != nil {
		return nil, err
	}
	fc := &fosite.Config{
		AccessTokenLifespan:   AccessTokenLifespan,
		RefreshTokenLifespan:  RefreshTokenLifespan,
		AuthorizeCodeLifespan: AuthorizeCodeLifespan,
		IDTokenLifespan:       IDTokenLifespan,
		IDTokenIssuer:         strings.TrimRight(cfg.Issuer, "/"),
		ScopeStrategy:         fosite.ExactScopeStrategy,
		GlobalSecret:          cfg.GlobalSecret,
		// Refresh tokens require an offline scope (TECH_SPEC §6.2).
		RefreshTokenScopes: []string{domain.ScopeOffline, domain.ScopeOfflineAccess},
		// PRD §5.2: public clients authenticate via PKCE, never a secret.
		EnforcePKCEForPublicClients: true,
		SendDebugMessagesToClients:  cfg.SendDebug,
	}
	store := NewStore(q, clients, fc)
	keyGetter := func(context.Context) (any, error) { return kg.Key, nil }
	strategy := compose.NewOAuth2HMACStrategy(fc)
	oidcStrategy := compose.NewOpenIDConnectStrategy(keyGetter, fc)
	oauth2 := compose.Compose(fc, store,
		&compose.CommonStrategy{
			CoreStrategy:               strategy,
			OpenIDConnectTokenStrategy: oidcStrategy,
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2PKCEFactory,
	)
	inner, ok := oauth2.(*fosite.Fosite)
	if !ok {
		return nil, errors.New("oidc: composed provider has unexpected type")
	}
	return &Provider{
		oauth2: inner, store: store, config: fc,
		issuer: strings.TrimRight(cfg.Issuer, "/"), key: kg.Key, kid: kg.KID,
	}, nil
}

// HashClientSecret hashes a client secret for storage. Verification runs
// inside fosite against this bcrypt hash.
func HashClientSecret(plain string) ([]byte, error) {
	if plain == "" {
		return nil, errors.New("oidc: client secret must not be empty")
	}
	return bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
}

// ParseAuthorizeRequest implements domain.OIDCProvider.
func (p *Provider) ParseAuthorizeRequest(ctx context.Context, r *http.Request) (domain.OIDCAuthRequest, error) {
	ar, err := p.oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		return domain.OIDCAuthRequest{}, err
	}
	name := ar.GetClient().GetID()
	if named, ok := ar.GetClient().(interface{ GetName() string }); ok && named.GetName() != "" {
		name = named.GetName()
	}
	return domain.OIDCAuthRequest{
		ClientID:        ar.GetClient().GetID(),
		ClientName:      name,
		RedirectURI:     ar.GetRedirectURI().String(),
		RequestedScopes: []string(ar.GetRequestedScopes()),
		State:           ar.GetState(),
	}, nil
}

// FinishAuthorizeRequest implements domain.OIDCProvider: it re-parses
// the authorize request (fresh validation), grants the decided scopes,
// and issues the 302 to the client redirect_uri.
func (p *Provider) FinishAuthorizeRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, d domain.OIDCDecision) error {
	ar, err := p.oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return err
	}
	for _, scope := range d.GrantedScopes {
		ar.GrantScope(scope)
	}
	resp, err := p.oauth2.NewAuthorizeResponse(ctx, ar, p.newSession(d))
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return err
	}
	p.oauth2.WriteAuthorizeResponse(ctx, w, ar, resp)
	return nil
}

// DenyAuthorizeRequest implements domain.OIDCProvider.
func (p *Provider) DenyAuthorizeRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ar, err := p.oauth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return err
	}
	p.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied.
		WithHint("The resource owner denied the request."))
	return nil
}

// WriteAuthorizeError implements domain.OIDCProvider.
func (p *Provider) WriteAuthorizeError(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) {
	ar, parseErr := p.oauth2.NewAuthorizeRequest(ctx, r)
	if parseErr != nil {
		// The request is too broken to redirect (unknown client or
		// redirect_uri): answer JSON instead of guessing a target.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p.oauth2.WriteAuthorizeError(ctx, w, ar, err)
}

// HandleToken implements domain.OIDCProvider.
func (p *Provider) HandleToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	session := openid.NewDefaultSession()
	ar, err := p.oauth2.NewAccessRequest(ctx, r, session)
	if err != nil {
		p.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}
	resp, err := p.oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		p.oauth2.WriteAccessError(ctx, w, ar, err)
		return
	}
	p.oauth2.WriteAccessResponse(ctx, w, ar, resp)
}

// HandleUserinfo implements domain.OIDCProvider: the bearer token is
// introspected (signature + storage lookup) and the stored claims are
// rendered as the userinfo response.
func (p *Provider) HandleUserinfo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	token := fosite.AccessTokenFromRequest(r)
	_, ar, err := p.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, openid.NewDefaultSession())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	sess, ok := ar.GetSession().(*openid.DefaultSession)
	if !ok || sess.GetSubject() == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	claims := sess.IDTokenClaims()
	out := map[string]any{"sub": claims.Subject}
	for k, v := range claims.Extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleDiscovery implements domain.OIDCProvider.
func (p *Provider) HandleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/oauth2/auth",
		"token_endpoint":                        p.issuer + "/oauth2/token",
		"userinfo_endpoint":                     p.issuer + "/oauth2/userinfo",
		"jwks_uri":                              p.issuer + "/oauth2/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported": []string{
			domain.ScopeOpenID, domain.ScopeProfile, domain.ScopeEmail,
			domain.ScopeGroups, domain.ScopeOfflineAccess,
		},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"preferred_username", "email", "name", "groups",
		},
		"code_challenge_methods_supported": []string{"S256", "plain"},
	})
}

// HandleJWKS implements domain.OIDCProvider: the single active RSA key.
func (p *Provider) HandleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(uint32ToBytes(uint32(pub.E)))
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "kid": p.kid, "alg": "RS256", "n": n, "e": e,
		}},
	})
}

// newSession builds the fosite session from the login+consent decision.
// Claims follow TECH_SPEC §6.2: sub = stable user UUID, plus
// preferred_username/email/name/groups in both ID token and userinfo.
// The kid header binds the token to the JWKS entry.
func (p *Provider) newSession(d domain.OIDCDecision) *openid.DefaultSession {
	s := openid.NewDefaultSession()
	now := time.Now().UTC()
	s.Subject = d.Subject
	s.Username = d.Username
	s.IDTokenHeaders().Add("kid", p.kid)
	claims := s.IDTokenClaims()
	claims.Subject = d.Subject
	claims.AuthTime = now
	claims.Extra = map[string]any{
		"preferred_username": d.Username,
		"email":              d.Email,
		"name":               d.Name,
		"groups":             d.Groups,
	}
	return s
}

func uint32ToBytes(v uint32) []byte {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	i := 0
	for i < 3 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// compile-time assertion: Provider serves delivery through the domain port.
var _ domain.OIDCProvider = (*Provider)(nil)
