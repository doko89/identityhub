// Package samlflow holds the assertion decisions for SAML AuthnRequests
// (TECH_SPEC §6.3): SP registration checks, claim building, and group
// membership mapping. It knows no HTTP, SQL or crewjam/saml — all outer
// details arrive as domain ports.
package samlflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/identityhub/identityhub/internal/domain"
)

// Service evaluates AuthnRequests for authenticated users.
type Service struct {
	sps    domain.SAMLSPStore
	groups domain.GroupStore
	clock  domain.Clock
}

// Deps wires a Service. All stores are required.
type Deps struct {
	SPs    domain.SAMLSPStore
	Groups domain.GroupStore
	Clock  domain.Clock
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.SPs == nil || d.Groups == nil {
		return nil, errors.New("samlflow: SPs and Groups are required")
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock{}
	}
	return &Service{sps: d.SPs, groups: d.Groups, clock: d.Clock}, nil
}

// Evaluate checks an AuthnRequest for an authenticated user: the account
// must be active, the SP must still be registered (an SP deleted after
// the login round trip started fails closed here), and the assertion
// content is built from the user + group memberships: NameID = username,
// attributes email/displayName/groups.
//
// App-access bindings (all-or-any evaluation) belong to the dashboard
// milestone (T6): until then every active user may SSO into any SP.
func (s *Service) Evaluate(ctx context.Context, user domain.User, req domain.SAMLAuthnRequest) (domain.SAMLDecision, error) {
	if !user.IsActive {
		return domain.SAMLDecision{}, fmt.Errorf("%w: account disabled", domain.ErrForbidden)
	}
	if req.EntityID == "" {
		return domain.SAMLDecision{}, fmt.Errorf("%w: SP entity ID is required", domain.ErrValidation)
	}
	if _, err := s.sps.GetByEntityID(ctx, req.EntityID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.SAMLDecision{}, fmt.Errorf("%w: unknown service provider", domain.ErrValidation)
		}
		return domain.SAMLDecision{}, err
	}
	groups, err := s.groups.GroupsOfUser(ctx, user.ID)
	if err != nil {
		return domain.SAMLDecision{}, err
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	return domain.SAMLDecision{
		NameID:      user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Groups:      names,
	}, nil
}
