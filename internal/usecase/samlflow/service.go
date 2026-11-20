// Package samlflow holds the assertion decisions for SAML AuthnRequests
// (TECH_SPEC §6.3): SP registration checks, claim building, and group
// membership mapping. It knows no HTTP, SQL or crewjam/saml — all outer
// details arrive as domain ports.
package samlflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// AccessChecker answers whether a user may open an app. *app.Service
// implements it; nil skips the check (tests that predate bindings).
type AccessChecker interface {
	CanAccess(ctx context.Context, user domain.User, appID uuid.UUID) (bool, error)
}

// Service evaluates AuthnRequests for authenticated users.
type Service struct {
	sps    domain.SAMLSPStore
	groups domain.GroupStore
	access AccessChecker
	clock  domain.Clock
	attrs  domain.UserAttrStore
}

// Deps wires a Service. SPs and Groups are required; Access is optional
// (nil skips the binding check); Attrs is optional (nil omits custom
// attributes).
type Deps struct {
	SPs    domain.SAMLSPStore
	Groups domain.GroupStore
	Access AccessChecker
	Clock  domain.Clock
	Attrs  domain.UserAttrStore
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.SPs == nil || d.Groups == nil {
		return nil, errors.New("samlflow: SPs and Groups are required")
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock{}
	}
	return &Service{sps: d.SPs, groups: d.Groups, access: d.Access, clock: d.Clock, attrs: d.Attrs}, nil
}

// Evaluate checks an AuthnRequest for an authenticated user: the account
// must be active, the SP must still be registered (an SP deleted after
// the login round trip started fails closed here), the app's bindings
// must admit the user, and the assertion content is built from the user +
// group memberships: NameID = username, attributes email/displayName/groups.
func (s *Service) Evaluate(ctx context.Context, user domain.User, req domain.SAMLAuthnRequest) (domain.SAMLDecision, error) {
	if !user.IsActive {
		return domain.SAMLDecision{}, fmt.Errorf("%w: account disabled", domain.ErrForbidden)
	}
	if req.EntityID == "" {
		return domain.SAMLDecision{}, fmt.Errorf("%w: SP entity ID is required", domain.ErrValidation)
	}
	sp, err := s.sps.GetByEntityID(ctx, req.EntityID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.SAMLDecision{}, fmt.Errorf("%w: unknown service provider", domain.ErrValidation)
		}
		return domain.SAMLDecision{}, err
	}
	if s.access != nil {
		ok, err := s.access.CanAccess(ctx, user, sp.ApplicationID)
		if err != nil {
			return domain.SAMLDecision{}, err
		}
		if !ok {
			return domain.SAMLDecision{}, fmt.Errorf("%w: no access to this application", domain.ErrForbidden)
		}
	}
	groups, err := s.groups.GroupsOfUser(ctx, user.ID)
	if err != nil {
		return domain.SAMLDecision{}, err
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	custom, err := s.customAttributes(ctx, user.ID)
	if err != nil {
		return domain.SAMLDecision{}, err
	}
	// phpIPAM compatibility attributes. phpIPAM's SAML JIT requires
	// display_name (underscore) and derives the Administrator role from
	// is_admin, mirroring the Authentik mapping (it-membership).
	// Explicit per-user custom attributes take precedence over these
	// computed defaults.
	if custom == nil {
		custom = map[string][]string{}
	}
	if _, ok := custom["display_name"]; !ok {
		custom["display_name"] = []string{user.DisplayName}
	}
	if _, ok := custom["is_admin"]; !ok {
		admin := "false"
		for _, g := range names {
			if g == "it" {
				admin = "true"
				break
			}
		}
		custom["is_admin"] = []string{admin}
	}
	return domain.SAMLDecision{
		NameID:      user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Groups:      names,
		Attributes:  custom,
	}, nil
}

// customAttributes loads the user's custom attributes for the
// assertion. A nil store (or no defs) issues no custom attributes.
func (s *Service) customAttributes(ctx context.Context, userID uuid.UUID) (map[string][]string, error) {
	if s.attrs == nil {
		return nil, nil
	}
	defs, err := s.attrs.ListDefs(ctx)
	if err != nil {
		return nil, err
	}
	if len(defs) == 0 {
		return nil, nil
	}
	return s.attrs.ValuesOfUser(ctx, userID)
}
