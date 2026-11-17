package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// ProviderService registers protocol credentials for catalog
// applications: OIDC clients, SAML SPs (metadata import) and RADIUS NAS
// secrets (PRD §6.3/§6.4, TECH_SPEC §5). Each protocol holds at most one
// row per application; secrets are returned once at creation and never
// readable again (bcrypt hash for OIDC, sealed bytes for RADIUS).
type ProviderService struct {
	apps   domain.ApplicationStore
	oidc   domain.OIDCClientStore
	sps    domain.SAMLSPStore
	radius domain.RADIUSClientStore
	hasher domain.ClientSecretHasher
	sealer domain.SecretSealer
	parser domain.SAMLMetadataParser
}

// ProviderDeps wires a ProviderService. All fields are required.
type ProviderDeps struct {
	Apps        domain.ApplicationStore
	OIDCClients domain.OIDCClientStore
	SAMLSPs     domain.SAMLSPStore
	RADIUS      domain.RADIUSClientStore
	Hasher      domain.ClientSecretHasher
	Sealer      domain.SecretSealer
	Parser      domain.SAMLMetadataParser
}

// NewProviders validates Deps and builds a ProviderService.
func NewProviders(d ProviderDeps) (*ProviderService, error) {
	if d.Apps == nil || d.OIDCClients == nil || d.SAMLSPs == nil || d.RADIUS == nil ||
		d.Hasher == nil || d.Sealer == nil || d.Parser == nil {
		return nil, errors.New("app: all ProviderDeps stores and ports are required")
	}
	return &ProviderService{
		apps: d.Apps, oidc: d.OIDCClients, sps: d.SAMLSPs, radius: d.RADIUS,
		hasher: d.Hasher, sealer: d.Sealer, parser: d.Parser,
	}, nil
}

// DefaultOIDCScopes is the scope set for clients that name none.
var DefaultOIDCScopes = []string{domain.ScopeOpenID, domain.ScopeProfile, domain.ScopeEmail}

var knownScopes = map[string]bool{
	domain.ScopeOpenID: true, domain.ScopeProfile: true, domain.ScopeEmail: true,
	domain.ScopeGroups: true, domain.ScopeOfflineAccess: true, domain.ScopeOffline: true,
}

// clientIDPattern keeps admin-supplied client ids URL-path-safe (no
// slashes) so DELETE /api/admin/oidc/clients/{clientID} routes cleanly.
var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{3,128}$`)

// RegisterOIDCClientInput carries one client registration. ClientID is
// generated when empty; Scopes default to openid/profile/email.
type RegisterOIDCClientInput struct {
	ApplicationID uuid.UUID
	ClientID      string
	RedirectURIs  []string
	Scopes        []string
	// Public marks a PKCE-only client (mobile/SPA): no secret is issued
	// and the token endpoint never accepts one for it.
	Public bool
}

// RegisterOIDCClient validates and persists a client. It returns the
// stored row plus the plaintext secret ("" for public clients); the
// secret is shown once and cannot be recovered later.
func (s *ProviderService) RegisterOIDCClient(ctx context.Context, in RegisterOIDCClientInput) (domain.OIDCClient, string, error) {
	if _, err := s.apps.ByID(ctx, in.ApplicationID); err != nil {
		return domain.OIDCClient{}, "", err
	}
	clientID := strings.TrimSpace(in.ClientID)
	if clientID == "" {
		var err error
		clientID, err = randomHex("oidc-", 6)
		if err != nil {
			return domain.OIDCClient{}, "", err
		}
	} else if !clientIDPattern.MatchString(clientID) {
		return domain.OIDCClient{}, "", fmt.Errorf("%w: client_id must be 3-128 chars of letters, digits, '.', '_' or '-'", domain.ErrValidation)
	}
	uris, err := cleanRedirectURIs(in.RedirectURIs)
	if err != nil {
		return domain.OIDCClient{}, "", err
	}
	scopes, err := cleanScopes(in.Scopes)
	if err != nil {
		return domain.OIDCClient{}, "", err
	}
	c := domain.OIDCClient{
		ApplicationID: in.ApplicationID, ClientID: clientID,
		RedirectURIs: uris, Scopes: scopes,
	}
	secret := ""
	if !in.Public {
		secret, err = randomSecret()
		if err != nil {
			return domain.OIDCClient{}, "", err
		}
		hash, err := s.hasher.HashSecret(secret)
		if err != nil {
			return domain.OIDCClient{}, "", err
		}
		c.ClientSecretHash = hash
	}
	created, err := s.oidc.Create(ctx, c)
	if err != nil {
		return domain.OIDCClient{}, "", err
	}
	created.ClientSecretHash = nil // never echo the hash
	return created, secret, nil
}

// ListOIDCClients pages registered clients. Hashes are stripped: the
// list answers "which clients exist", never their secrets.
func (s *ProviderService) ListOIDCClients(ctx context.Context, limit, offset int) ([]domain.OIDCClient, int, error) {
	out, total, err := s.oidc.List(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].ClientSecretHash = nil
	}
	return out, total, nil
}

// DeleteOIDCClient removes a client by its public client_id.
func (s *ProviderService) DeleteOIDCClient(ctx context.Context, clientID string) error {
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("%w: client_id is required", domain.ErrValidation)
	}
	return s.oidc.Delete(ctx, clientID)
}

// cleanRedirectURIs requires at least one URI and enforces the OAuth
// transport rule: https everywhere, with http allowed only for loopback
// (local development). Fragments are refused: they never reach the
// server, so they cannot be matched safely.
func cleanRedirectURIs(raw []string) ([]string, error) {
	uris := make([]string, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		u, err := url.Parse(r)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("%w: redirect_uri %q is not an absolute URL", domain.ErrValidation, r)
		}
		if u.Fragment != "" {
			return nil, fmt.Errorf("%w: redirect_uri %q must not carry a fragment", domain.ErrValidation, r)
		}
		switch u.Scheme {
		case "https":
		case "http":
			host := u.Hostname()
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
				return nil, fmt.Errorf("%w: redirect_uri %q must use https outside loopback", domain.ErrValidation, r)
			}
		default:
			return nil, fmt.Errorf("%w: redirect_uri %q must use https", domain.ErrValidation, r)
		}
		uris = append(uris, r)
	}
	if len(uris) == 0 {
		return nil, fmt.Errorf("%w: at least one redirect_uri is required", domain.ErrValidation)
	}
	return uris, nil
}

// cleanScopes defaults an empty set and requires every scope to be known
// with openid present (fosite's OIDC flows need it).
func cleanScopes(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return append([]string{}, DefaultOIDCScopes...), nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, sc := range raw {
		sc = strings.TrimSpace(sc)
		if sc == "" || seen[sc] {
			continue
		}
		if !knownScopes[sc] {
			return nil, fmt.Errorf("%w: unknown scope %q", domain.ErrValidation, sc)
		}
		seen[sc] = true
		out = append(out, sc)
	}
	if !seen[domain.ScopeOpenID] {
		return nil, fmt.Errorf("%w: scopes must include %q", domain.ErrValidation, domain.ScopeOpenID)
	}
	return out, nil
}

// ImportSAMLSP registers an SP by importing its metadata XML (PRD §6.4).
// The adapter picks the default POST ACS, the preferred SLO endpoint
// and the signing certificate; the raw XML is kept for audit.
func (s *ProviderService) ImportSAMLSP(ctx context.Context, applicationID uuid.UUID, metadataXML string) (domain.SAMLServiceProvider, error) {
	if _, err := s.apps.ByID(ctx, applicationID); err != nil {
		return domain.SAMLServiceProvider{}, err
	}
	sp, err := s.parser.ParseSPMetadata(metadataXML)
	if err != nil {
		return domain.SAMLServiceProvider{}, err
	}
	sp.ApplicationID = applicationID
	return s.sps.Create(ctx, sp)
}

// ListSAMLSPs pages registered SPs.
func (s *ProviderService) ListSAMLSPs(ctx context.Context, limit, offset int) ([]domain.SAMLServiceProvider, int, error) {
	return s.sps.List(ctx, limit, offset)
}

// DeleteSAMLSP removes an SP by entityID.
func (s *ProviderService) DeleteSAMLSP(ctx context.Context, entityID string) error {
	if strings.TrimSpace(entityID) == "" {
		return fmt.Errorf("%w: entity_id is required", domain.ErrValidation)
	}
	return s.sps.Delete(ctx, entityID)
}

// RegisterRADIUSClientInput carries one NAS registration. SharedSecret
// is generated when empty (32 hex chars, RADIUS-safe printable).
type RegisterRADIUSClientInput struct {
	ApplicationID uuid.UUID
	NASIdentifier string
	SharedSecret  string
}

// RegisterRADIUSClient validates and persists a NAS client. It returns
// the stored row plus the plaintext secret (shown once); only the sealed
// bytes are stored.
func (s *ProviderService) RegisterRADIUSClient(ctx context.Context, in RegisterRADIUSClientInput) (domain.RADIUSClient, string, error) {
	if _, err := s.apps.ByID(ctx, in.ApplicationID); err != nil {
		return domain.RADIUSClient{}, "", err
	}
	nas := strings.TrimSpace(in.NASIdentifier)
	if net.ParseIP(nas) == nil {
		return domain.RADIUSClient{}, "", fmt.Errorf("%w: nas_identifier must be the NAS source IP", domain.ErrValidation)
	}
	secret := in.SharedSecret
	if secret == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return domain.RADIUSClient{}, "", fmt.Errorf("app: random RADIUS secret: %w", err)
		}
		secret = hex.EncodeToString(raw)
	} else if len(secret) < 8 {
		return domain.RADIUSClient{}, "", fmt.Errorf("%w: shared_secret must be at least 8 characters", domain.ErrValidation)
	}
	sealed, err := s.sealer.Seal([]byte(secret))
	if err != nil {
		return domain.RADIUSClient{}, "", err
	}
	created, err := s.radius.Create(ctx, domain.RADIUSClient{
		ApplicationID: in.ApplicationID, NASIdentifier: nas, SharedSecretEnc: sealed,
	})
	if err != nil {
		return domain.RADIUSClient{}, "", err
	}
	created.SharedSecretEnc = nil // never echo sealed bytes
	return created, secret, nil
}

// ListRADIUSClients pages NAS clients with sealed secrets stripped.
func (s *ProviderService) ListRADIUSClients(ctx context.Context, limit, offset int) ([]domain.RADIUSClient, int, error) {
	out, total, err := s.radius.List(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].SharedSecretEnc = nil
	}
	return out, total, nil
}

// DeleteRADIUSClient removes a NAS client by its identifier.
func (s *ProviderService) DeleteRADIUSClient(ctx context.Context, nasIdentifier string) error {
	if strings.TrimSpace(nasIdentifier) == "" {
		return fmt.Errorf("%w: nas_identifier is required", domain.ErrValidation)
	}
	return s.radius.Delete(ctx, nasIdentifier)
}

// randomHex builds a prefixed random id ("oidc-<12 hex>").
func randomHex(prefix string, nbytes int) (string, error) {
	raw := make([]byte, nbytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("app: random id: %w", err)
	}
	return prefix + hex.EncodeToString(raw), nil
}

// randomSecret builds a 32-byte secret in base64url (43 chars).
func randomSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("app: random secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
