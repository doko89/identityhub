package domain

import (
	"context"

	"github.com/google/uuid"
)

// ProviderType is the single primary protocol of an application (PRD §5.2).
type ProviderType string

const (
	ProviderOIDC   ProviderType = "oidc"
	ProviderSAML   ProviderType = "saml"
	ProviderLDAP   ProviderType = "ldap"
	ProviderRADIUS ProviderType = "radius"
)

// Valid reports whether p is a known provider type.
func (p ProviderType) Valid() bool {
	switch p {
	case ProviderOIDC, ProviderSAML, ProviderLDAP, ProviderRADIUS:
		return true
	}
	return false
}

// Application is one row of the applications table (TECH_SPEC §5).
type Application struct {
	ID           uuid.UUID
	Slug         string
	Name         string
	Description  string
	IconURL      string
	LaunchURL    string
	GroupLabel   string
	ProviderType ProviderType
	IsVisible    bool
	SortOrder    int
	// MFARequired marks apps whose non-admin users must pass a second
	// factor (PRD §6.6). Admins always require MFA regardless.
	MFARequired bool
	// OpenInNewTab makes the dashboard launch the app in a new tab
	// instead of navigating away.
	OpenInNewTab bool
}

// Validate checks constructor-level invariants shared by all writers.
func (a Application) Validate() error {
	if a.Slug == "" || a.Name == "" {
		return wrapValidation("application slug and name are required")
	}
	if !a.ProviderType.Valid() {
		return wrapValidation("unknown provider type")
	}
	return nil
}

// OIDCClient is one row of oidc_clients. The secret itself is never stored:
// only its hash, and only shown once at registration.
type OIDCClient struct {
	ID               uuid.UUID
	ApplicationID    uuid.UUID
	ClientID         string
	ClientSecretHash []byte // nil for public (PKCE-only) clients
	RedirectURIs     []string
	Scopes           []string
}

// SAMLServiceProvider is one row of saml_sps.
type SAMLServiceProvider struct {
	ID            uuid.UUID
	ApplicationID uuid.UUID
	EntityID      string
	ACSURL        string
	SLOURL        string
	MetadataXML   string
	CertPEM       string
}

// LDAPProviderConfig is one row of ldap_provider_config.
type LDAPProviderConfig struct {
	ID             uuid.UUID
	ApplicationID  uuid.UUID
	BindDNTemplate string
	BaseDN         string
	UserFilter     string
}

// RADIUSClient is one row of radius_clients. The shared secret is stored
// encrypted with ENC_KEY and decrypted only in memory during verification.
type RADIUSClient struct {
	ID              uuid.UUID
	ApplicationID   uuid.UUID
	NASIdentifier   string
	SharedSecretEnc []byte
}

// RADIUSClientStore is the port for the NAS shared-secret registry
// (TECH_SPEC §5, §6.5). Secrets are stored sealed with ENC_KEY
// (crypto.Seal); callers seal before Create and open after read.
type RADIUSClientStore interface {
	Create(ctx context.Context, c RADIUSClient) (RADIUSClient, error)
	ByNASIdentifier(ctx context.Context, nasIdentifier string) (RADIUSClient, error)
	Delete(ctx context.Context, nasIdentifier string) error
	List(ctx context.Context, limit, offset int) ([]RADIUSClient, int, error)
}

// SecretSealer encrypts provider secrets at rest with ENC_KEY
// (TECH_SPEC §5): RADIUS shared secrets (and, behind the same method
// set, TOTP seeds via SeedSealer). Implemented in
// internal/adapter/crypto.
type SecretSealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// ApplicationStore is the port for the app catalog and provider configs.
type ApplicationStore interface {
	Create(ctx context.Context, a Application) (Application, error)
	ByID(ctx context.Context, id uuid.UUID) (Application, error)
	BySlug(ctx context.Context, slug string) (Application, error)
	List(ctx context.Context, limit, offset int) ([]Application, int, error)
	Update(ctx context.Context, a Application) (Application, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
