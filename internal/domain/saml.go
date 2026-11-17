package domain

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// SAML attribute names in assertions (TECH_SPEC §6.3): NameID carries the
// username; email, displayName and groups ride as attributes.
const (
	SAMLAttrEmail       = "email"
	SAMLAttrDisplayName = "displayName"
	SAMLAttrGroups      = "groups"
)

// SAMLAuthnRequest is the crewjam-free view of an AuthnRequest: what the
// service provider asks for. Produced by SAMLProvider.ParseAuthnRequest,
// consumed by usecase/samlflow.
type SAMLAuthnRequest struct {
	RequestID  string
	EntityID   string // SP issuer
	ACSURL     string // selected assertion consumer service
	RelayState string
	ForceAuthn bool
	IsPassive  bool
}

// SAMLDecision is the authenticated user's assertion content: identity plus
// the attributes every SP receives. The adapter turns it into a signed
// assertion; it never sees passwords.
type SAMLDecision struct {
	NameID      string // username (TECH_SPEC §6.3)
	Email       string
	DisplayName string
	Groups      []string
	// Attributes carries custom attributes (all strings on the wire).
	Attributes map[string][]string
}

// SAMLSPStore is the port for the per-app SP registry (PRD §6.4). SPs are
// registered by importing their metadata XML (parsed by the adapter into
// SAMLServiceProvider fields); the raw XML is kept for audit.
type SAMLSPStore interface {
	GetByEntityID(ctx context.Context, entityID string) (SAMLServiceProvider, error)
	// Create persists an SP; EntityID and ACSURL are required.
	Create(ctx context.Context, sp SAMLServiceProvider) (SAMLServiceProvider, error)
	Delete(ctx context.Context, entityID string) error
	List(ctx context.Context, limit, offset int) ([]SAMLServiceProvider, int, error)
}

// SAMLMetadataParser imports an SP metadata document into registry
// fields (entityID, default POST ACS, preferred SLO, signing cert).
// Implemented in internal/adapter/saml (crewjam); registration flows
// parse through this port so usecases never touch the SAML library.
type SAMLMetadataParser interface {
	ParseSPMetadata(raw string) (SAMLServiceProvider, error)
}

// SAMLRequest carries an SSO request across the login round trip. The raw
// bytes are stored verbatim (query string for Redirect binding, body for
// POST) so signature validation replays exactly what the SP sent.
type SAMLRequest struct {
	Challenge   string
	Method      string // GET or POST
	Target      string // raw query (GET) or raw body (POST)
	ContentType string // POST content type for form replay
	ExpiresAt   time.Time
	CreatedAt   time.Time // stash time; ForceAuthn compares auth time to it
}

// SAMLRequestStore persists SSO requests with a short TTL.
type SAMLRequestStore interface {
	Create(ctx context.Context, r SAMLRequest) error
	// Get loads a live request; expired or missing ones report ErrNotFound.
	Get(ctx context.Context, challenge string) (SAMLRequest, error)
	Delete(ctx context.Context, challenge string) error
}

// SAML error-response statuses (saml-core §3.2.2.2) for WriteAuthnError.
// Plain URIs so delivery never imports crewjam/saml.
const (
	SAMLStatusRequester     = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	SAMLStatusResponder     = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	SAMLStatusNoPassive     = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	SAMLStatusRequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
)

// SAMLLogoutRequest is the crewjam-free view of a LogoutRequest.
type SAMLLogoutRequest struct {
	RequestID  string
	EntityID   string // SP issuer
	RelayState string
}

// SAMLProvider is the domain-owned SAML port (TECH_SPEC §2): crewjam/saml
// sits behind it in internal/adapter/saml and can be swapped without
// touching usecases or delivery.
type SAMLProvider interface {
	// HandleMetadata serves GET /saml/metadata.
	HandleMetadata(w http.ResponseWriter, r *http.Request)
	// ParseAuthnRequest validates an AuthnRequest (issuer known, ACS
	// matches the registered metadata, signature valid when present)
	// and returns its public parameters for the login flow.
	ParseAuthnRequest(ctx context.Context, r *http.Request) (SAMLAuthnRequest, error)
	// FinishAuthnRequest re-validates and answers with a signed Response
	// (assertion + response signatures) posted to the SP's ACS.
	FinishAuthnRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, d SAMLDecision) error
	// WriteAuthnError answers a validated request with a signed error
	// Response (e.g. Responder/NoPassive) instead of an assertion.
	WriteAuthnError(ctx context.Context, w http.ResponseWriter, r *http.Request, topLevel, secondLevel, message string)
	// ParseIdPInitiated validates an IdP-initiated login target.
	ParseIdPInitiated(ctx context.Context, r *http.Request, entityID, relayState string) (SAMLAuthnRequest, error)
	// FinishIdPInitiated answers an IdP-initiated login with a signed
	// unsolicited Response to the SP's default ACS.
	FinishIdPInitiated(ctx context.Context, w http.ResponseWriter, r *http.Request, entityID, relayState string, d SAMLDecision) error
	// ParseLogoutRequest validates a LogoutRequest and returns its
	// public parameters.
	ParseLogoutRequest(ctx context.Context, r *http.Request) (SAMLLogoutRequest, error)
	// FinishLogoutRequest answers a validated LogoutRequest with a
	// signed success LogoutResponse to the SP's SLO endpoint.
	FinishLogoutRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) error
}

// SAMLAppLinker optionally resolves the application row of an SP for audit.
// Repositories that join saml_sps to applications implement it.
type SAMLAppLinker interface {
	SAMLSPStore
	ApplicationID(ctx context.Context, entityID string) (uuid.UUID, error)
}
