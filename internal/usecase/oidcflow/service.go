// Package oidcflow holds the login+consent decisions for OIDC authorize
// requests (TECH_SPEC §6.2): scope validation against the client
// registration, claim building, and remembered-consent checks. It knows
// no HTTP, SQL or fosite — all outer details arrive as domain ports.
package oidcflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// Service evaluates authorize requests for authenticated users.
type Service struct {
	clients  domain.OIDCClientStore
	groups   domain.GroupStore
	consents domain.OIDCConsentStore
	clock    domain.Clock
}

// Deps wires a Service. All stores are required.
type Deps struct {
	Clients  domain.OIDCClientStore
	Groups   domain.GroupStore
	Consents domain.OIDCConsentStore
	Clock    domain.Clock
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Clients == nil || d.Groups == nil || d.Consents == nil {
		return nil, errors.New("oidcflow: Clients, Groups and Consents are required")
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock{}
	}
	return &Service{clients: d.Clients, groups: d.Groups, consents: d.Consents, clock: d.Clock}, nil
}

// Outcome is the evaluated authorize request: the claims to issue plus
// whether the consent page must be shown.
type Outcome struct {
	Decision    domain.OIDCDecision
	NeedConsent bool
}

// Evaluate checks an authorize request for an authenticated user: the
// account must be active, every requested scope must be registered on
// the client, and claims are built from the user + group memberships.
// Consent is needed unless a remembered grant covers all requested scopes.
//
// App-access bindings (all-or-any evaluation) belong to the dashboard
// milestone (T6): until then every active user may authorize any client.
func (s *Service) Evaluate(ctx context.Context, user domain.User, req domain.OIDCAuthRequest) (Outcome, error) {
	if !user.IsActive {
		return Outcome{}, fmt.Errorf("%w: account disabled", domain.ErrForbidden)
	}
	client, err := s.clients.GetByClientID(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return Outcome{}, fmt.Errorf("%w: unknown client", domain.ErrValidation)
		}
		return Outcome{}, err
	}
	allowed := map[string]bool{}
	for _, sc := range client.Scopes {
		allowed[sc] = true
	}
	for _, sc := range req.RequestedScopes {
		if !allowed[sc] {
			return Outcome{}, fmt.Errorf("%w: scope %q is not registered for this client", domain.ErrValidation, sc)
		}
	}
	groups, err := s.groups.GroupsOfUser(ctx, user.ID)
	if err != nil {
		return Outcome{}, err
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	granted := append([]string(nil), req.RequestedScopes...)
	needConsent := true
	if remembered, err := s.consents.Get(ctx, user.ID, req.ClientID); err == nil {
		needConsent = !covers(remembered.Scopes, granted)
	} else if !errors.Is(err, domain.ErrNotFound) {
		return Outcome{}, err
	}
	return Outcome{
		Decision: domain.OIDCDecision{
			Subject:       user.ID.String(),
			Username:      user.Username,
			Email:         user.Email,
			Name:          user.DisplayName,
			Groups:        names,
			GrantedScopes: granted,
		},
		NeedConsent: needConsent,
	}, nil
}

// GrantConsent remembers the user's scope grant after the consent page.
func (s *Service) GrantConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	if userID == uuid.Nil || clientID == "" {
		return fmt.Errorf("%w: user and client are required", domain.ErrValidation)
	}
	return s.consents.Grant(ctx, userID, clientID, scopes)
}

// covers reports whether every scope in want appears in have.
func covers(have, want []string) bool {
	set := map[string]bool{}
	for _, sc := range have {
		set[sc] = true
	}
	for _, sc := range want {
		if !set[sc] {
			return false
		}
	}
	return true
}
