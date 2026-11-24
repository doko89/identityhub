package saml

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	csaml "github.com/crewjam/saml"
	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// Config wires the provider. Issuer is the public origin (APP_BASE_URL);
// the IdP entity ID is Issuer + "/saml/metadata". Logger receives a
// warning whenever an SP without a registered signing key skips
// request-signature verification; nil means slog.Default().
type Config struct {
	Issuer string
	Logger *slog.Logger
}

// Provider implements domain.SAMLProvider with crewjam/saml. Request
// parsing, ACS/audience validation, AuthnRequest signature checks and
// assertion/response signing all come from the library; the SP registry
// and the session behind each assertion are ours.
type Provider struct {
	idp    *csaml.IdentityProvider
	replay *replayCache
	sps    domain.SAMLSPStore
	log    *slog.Logger
}

// New builds the IdP: persistent signing identity from saml_keys, endpoint
// URLs under Issuer, and the Postgres SP registry as the metadata source.
// Unsigned AuthnRequests are accepted; signed ones are verified against
// the registered SP certificate and answered at most once (replay cache).
// SPs without a registered key (e.g. SendGrid, which publishes none) skip
// signature verification — Authentik parity — while every other check
// (issuer, ACS, freshness, replay) still applies.
func New(ctx context.Context, q Querier, sps domain.SAMLSPStore, cfg Config) (*Provider, error) {
	issuer := strings.TrimRight(cfg.Issuer, "/")
	if issuer == "" {
		return nil, errors.New("saml: Issuer is required")
	}
	if sps == nil {
		return nil, errors.New("saml: SP store is required")
	}
	kp, err := LoadOrGenerateKey(ctx, q)
	if err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(issuer + "/saml/metadata")
	ssoURL, _ := url.Parse(issuer + "/saml/sso")
	logoutURL, _ := url.Parse(issuer + "/saml/slo")
	idp := &csaml.IdentityProvider{
		Key:                     kp.Key,
		Certificate:             kp.Cert,
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		LogoutURL:               *logoutURL,
		ServiceProviderProvider: &registry{store: sps},
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Provider{
		idp:    idp,
		replay: newReplayCache(10000),
		sps:    sps,
		log:    log,
	}, nil
}

// registry adapts the Postgres SP registry to crewjam's metadata lookup.
// Unknown SPs report os.ErrNotExist so the library answers accordingly.
type registry struct {
	store domain.SAMLSPStore
}

func (r *registry) GetServiceProvider(req *http.Request, serviceProviderID string) (*csaml.EntityDescriptor, error) {
	sp, err := r.store.GetByEntityID(req.Context(), serviceProviderID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, errUnknownSP(serviceProviderID)
		}
		return nil, err
	}
	return SPEntityDescriptor(sp)
}

// errUnknownSP reports an unregistered issuer the way crewjam expects:
// os.ErrNotExist, so validation classifies it as an unknown-SP error.
func errUnknownSP(entityID string) error {
	return fmt.Errorf("saml: unknown service provider %q: %w", entityID, os.ErrNotExist)
}

// HandleMetadata implements domain.SAMLProvider.
func (p *Provider) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	p.idp.ServeMetadata(w, r)
}

// ParseAuthnRequest implements domain.SAMLProvider.
func (p *Provider) ParseAuthnRequest(ctx context.Context, r *http.Request) (domain.SAMLAuthnRequest, error) {
	creq, err := p.validatedAuthnRequest(ctx, r)
	if err != nil {
		return domain.SAMLAuthnRequest{}, err
	}
	return mapAuthnRequest(creq), nil
}

// FinishAuthnRequest implements domain.SAMLProvider: it re-parses and
// re-validates (fresh crewjam checks on every issuance), consumes the
// request ID against replay, and answers with a doubly-signed Response.
func (p *Provider) FinishAuthnRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, d domain.SAMLDecision) error {
	creq, err := p.validatedAuthnRequest(ctx, r)
	if err != nil {
		return err
	}
	if err := p.consume(creq.Request.Issuer.Value, creq.Request.ID, creq.Request.IssueInstant); err != nil {
		return err
	}
	maker := csaml.DefaultAssertionMaker{}
	if err := maker.MakeAssertion(creq, mapSession(d)); err != nil {
		return err
	}
	return creq.WriteResponse(w)
}

// WriteAuthnError implements domain.SAMLProvider: a signed error Response
// to the SP's ACS (e.g. Responder/NoPassive for IsPassive without a
// session). Unparseable requests cannot be answered this way — the caller
// falls back to HTTP 400.
func (p *Provider) WriteAuthnError(ctx context.Context, w http.ResponseWriter, r *http.Request, topLevel, secondLevel, message string) {
	creq, err := p.validatedAuthnRequest(ctx, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := p.idp.SendErrorResponse(w, creq, &csaml.StatusError{
		TopLevel: topLevel, SecondLevel: secondLevel, Message: message,
	}); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// ParseIdPInitiated implements domain.SAMLProvider.
func (p *Provider) ParseIdPInitiated(_ context.Context, r *http.Request, entityID, relayState string) (domain.SAMLAuthnRequest, error) {
	creq, err := p.idp.NewIdpInitiatedRequest(r, entityID, relayState)
	if err != nil {
		return domain.SAMLAuthnRequest{}, err
	}
	return mapAuthnRequest(creq), nil
}

// FinishIdPInitiated implements domain.SAMLProvider: an unsolicited signed
// Response to the SP's default ACS (PRD §5.3 dashboard launch).
func (p *Provider) FinishIdPInitiated(_ context.Context, w http.ResponseWriter, r *http.Request, entityID, relayState string, d domain.SAMLDecision) error {
	creq, err := p.idp.NewIdpInitiatedRequest(r, entityID, relayState)
	if err != nil {
		return err
	}
	maker := csaml.DefaultAssertionMaker{}
	if err := maker.MakeAssertion(creq, mapSession(d)); err != nil {
		return err
	}
	return creq.WriteResponse(w)
}

// ParseLogoutRequest implements domain.SAMLProvider.
func (p *Provider) ParseLogoutRequest(_ context.Context, r *http.Request) (domain.SAMLLogoutRequest, error) {
	creq, err := csaml.NewIdpLogoutRequest(p.idp, r)
	if err != nil {
		return domain.SAMLLogoutRequest{}, err
	}
	if err := creq.Validate(); err != nil {
		return domain.SAMLLogoutRequest{}, err
	}
	entityID := ""
	if creq.Request.Issuer != nil {
		entityID = creq.Request.Issuer.Value
	}
	return domain.SAMLLogoutRequest{
		RequestID: creq.Request.ID, EntityID: entityID, RelayState: creq.RelayState,
	}, nil
}

// FinishLogoutRequest implements domain.SAMLProvider: a signed success
// LogoutResponse to the SP's SLO endpoint. The caller destroys the local
// session first; this only speaks the protocol.
func (p *Provider) FinishLogoutRequest(_ context.Context, w http.ResponseWriter, r *http.Request) error {
	creq, err := csaml.NewIdpLogoutRequest(p.idp, r)
	if err != nil {
		return err
	}
	if err := creq.Validate(); err != nil {
		return err
	}
	return creq.WriteLogoutResponse(w, creq.MakeLogoutResponse(csaml.StatusSuccess))
}

// validatedAuthnRequest parses and validates an AuthnRequest: well-formed
// XML, fresh IssueInstant, known issuer, ACS matching the registered
// metadata, and a valid signature when the request is signed. The registry
// advertises a single POST ACS per SP, so the selected endpoint is always
// POST-sendable.
//
// When validation fails for an SP without a registered signing key, the
// request is retried with its signature inputs removed: such SPs cannot
// be verified against anything, so they are treated as unsigned
// (Authentik parity). The retry re-runs the full validation, so only
// the signature check is excused — any other failure still rejects with
// the original error.
func (p *Provider) validatedAuthnRequest(ctx context.Context, r *http.Request) (*csaml.IdpAuthnRequest, error) {
	raw := p.bufferBody(r)
	creq, err := csaml.NewIdpAuthnRequest(p.idp, r)
	if err != nil {
		return nil, err
	}
	if verr := creq.Validate(); verr == nil {
		return creq, nil
	} else {
		err = verr
	}
	if retry, ok := p.unsignedRetry(ctx, r, raw, creq); ok {
		return retry, nil
	}
	return nil, err
}

// bufferBody preserves POST bytes for a signature-stripped retry: the
// first parse drains the body, so without a copy there is nothing to
// rebuild from. GET requests carry everything in the URL.
func (p *Provider) bufferBody(r *http.Request) []byte {
	if r.Method != http.MethodPost || r.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxAuthnBodyBytes+1))
	_ = r.Body.Close()
	if err != nil || len(raw) > maxAuthnBodyBytes {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return raw
}

// unsignedRetry re-validates a rejected request with its signature
// inputs removed. It applies only to SPs without a registered signing
// key; SPs with a key fail closed on the original error, as do requests
// with nothing to strip.
func (p *Provider) unsignedRetry(ctx context.Context, r *http.Request, raw []byte, creq *csaml.IdpAuthnRequest) (*csaml.IdpAuthnRequest, bool) {
	if creq.Request.Issuer == nil || creq.Request.Issuer.Value == "" {
		return nil, false
	}
	sp, err := p.sps.GetByEntityID(ctx, creq.Request.Issuer.Value)
	if err != nil || sp.CertPEM != "" {
		return nil, false
	}
	var stripped *http.Request
	var ok bool
	if r.Method == http.MethodPost {
		body := raw
		if len(body) == 0 && len(r.PostForm) > 0 {
			// Issuance re-validates the same request: the body is
			// drained but the parsed form survives, and its values
			// are exactly what the first parse saw.
			body = []byte(r.PostForm.Encode())
		}
		if len(body) == 0 {
			return nil, false
		}
		stripped, ok = stripPOSTSignature(body, r)
	} else {
		stripped, ok = stripRedirectSignature(r)
	}
	if !ok {
		return nil, false
	}
	retry, err := csaml.NewIdpAuthnRequest(p.idp, stripped)
	if err != nil {
		return nil, false
	}
	if err := retry.Validate(); err != nil {
		return nil, false
	}
	p.log.Warn("saml authn signature skipped, SP has no registered signing key",
		"entity_id", sp.EntityID)
	return retry, true
}

func mapAuthnRequest(creq *csaml.IdpAuthnRequest) domain.SAMLAuthnRequest {
	out := domain.SAMLAuthnRequest{RelayState: creq.RelayState}
	if creq.Request.Issuer != nil {
		out.EntityID = creq.Request.Issuer.Value
	}
	out.RequestID = creq.Request.ID
	if creq.ACSEndpoint != nil {
		out.ACSURL = creq.ACSEndpoint.Location
	}
	if creq.Request.ForceAuthn != nil {
		out.ForceAuthn = *creq.Request.ForceAuthn
	}
	if creq.Request.IsPassive != nil {
		out.IsPassive = *creq.Request.IsPassive
	}
	// IdP-initiated requests carry no AuthnRequest: the SP is already
	// resolved in ServiceProviderMetadata.
	if out.EntityID == "" && creq.ServiceProviderMetadata != nil {
		out.EntityID = creq.ServiceProviderMetadata.EntityID
	}
	return out
}

// mapSession builds the crewjam session from the login decision
// (TECH_SPEC §6.3): NameID + format from the decision (username/
// unspecified by default); email, displayName and groups as
// attributes. CustomAttributes guarantee the contract names regardless of
// what the SP's AttributeConsumingService requests. Custom attributes
// append after the built-ins, sorted by key for stable assertions.
func mapSession(d domain.SAMLDecision) *csaml.Session {
	groupValues := make([]csaml.AttributeValue, 0, len(d.Groups))
	for _, g := range d.Groups {
		groupValues = append(groupValues, csaml.AttributeValue{Type: "xs:string", Value: g})
	}
	attrs := []csaml.Attribute{
		{
			FriendlyName: domain.SAMLAttrEmail, Name: domain.SAMLAttrEmail,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     []csaml.AttributeValue{{Type: "xs:string", Value: d.Email}},
		},
		{
			FriendlyName: domain.SAMLAttrDisplayName, Name: domain.SAMLAttrDisplayName,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     []csaml.AttributeValue{{Type: "xs:string", Value: d.DisplayName}},
		},
		{
			FriendlyName: domain.SAMLAttrGroups, Name: domain.SAMLAttrGroups,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     groupValues,
		},
	}
	keys := make([]string, 0, len(d.Attributes))
	for k, v := range d.Attributes {
		if len(v) > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals := make([]csaml.AttributeValue, 0, len(d.Attributes[k]))
		for _, v := range d.Attributes[k] {
			vals = append(vals, csaml.AttributeValue{Type: "xs:string", Value: v})
		}
		attrs = append(attrs, csaml.Attribute{
			FriendlyName: k, Name: k,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     vals,
		})
	}
	nameIDFormat := d.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = domain.SAMLNameIDFormatUnspecified
	}
	index := uuid.NewString()
	return &csaml.Session{
		ID:               index,
		Index:            index,
		NameID:           d.NameID,
		NameIDFormat:     nameIDFormat,
		UserName:         d.NameID,
		UserEmail:        d.Email,
		UserCommonName:   d.DisplayName,
		Groups:           d.Groups,
		CustomAttributes: attrs,
	}
}

// consume answers each AuthnRequest ID at most once: a replayed request
// (same issuer + ID) fails closed. The window follows the library's issue
// delay plus clock skew.
func (p *Provider) consume(issuer, requestID string, issued time.Time) error {
	key := "saml-authn:" + issuer + " " + requestID
	return p.replay.consume(key, issued.Add(csaml.MaxIssueDelay+csaml.MaxClockSkew))
}
