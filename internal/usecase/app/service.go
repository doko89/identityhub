// Package app implements the application catalog, visibility bindings,
// and the dashboard launch flow (PRD §6.7): users only see apps they may
// access; clicking an app SSOs straight in while the session lasts.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// Service holds the app catalog rules. All outer details arrive as
// domain interfaces.
type Service struct {
	apps     domain.ApplicationStore
	bindings domain.BindingStore
	users    domain.UserStore
	groups   domain.GroupStore
}

// Deps wires a Service. All stores are required.
type Deps struct {
	Apps     domain.ApplicationStore
	Bindings domain.BindingStore
	Users    domain.UserStore
	Groups   domain.GroupStore
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Apps == nil || d.Bindings == nil || d.Users == nil || d.Groups == nil {
		return nil, errors.New("app: Apps, Bindings, Users and Groups are required")
	}
	return &Service{apps: d.Apps, bindings: d.Bindings, users: d.Users, groups: d.Groups}, nil
}

// MyApps returns the dashboard list: visible apps the user may access,
// in catalog order (sort_order, name). Invisible apps never appear here;
// admins use ListApps.
func (s *Service) MyApps(ctx context.Context, userID uuid.UUID) ([]domain.Application, error) {
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !u.IsActive {
		return nil, fmt.Errorf("%w: account disabled", domain.ErrForbidden)
	}
	all, err := s.listAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Application, 0, len(all))
	for _, a := range all {
		if !a.IsVisible {
			continue
		}
		ok, err := s.CanAccess(ctx, u, a.ID)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// Launch resolves an app for SSO start: the slug must exist, be visible,
// and pass the caller's bindings. The returned LaunchURL is
// admin-provided (the app's SSO entry; for SAML typically
// /saml/sso?sp=<entityID>); empty means the admin has not configured one
// yet and the client shows the app without a launch button.
func (s *Service) Launch(ctx context.Context, userID uuid.UUID, slug string) (domain.Application, error) {
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		return domain.Application{}, err
	}
	if !u.IsActive {
		return domain.Application{}, fmt.Errorf("%w: account disabled", domain.ErrForbidden)
	}
	a, err := s.apps.BySlug(ctx, strings.TrimSpace(slug))
	if err != nil {
		return domain.Application{}, err
	}
	if !a.IsVisible {
		return domain.Application{}, domain.ErrNotFound
	}
	ok, err := s.CanAccess(ctx, u, a.ID)
	if err != nil {
		return domain.Application{}, err
	}
	if !ok {
		return domain.Application{}, fmt.Errorf("%w: no access to this application", domain.ErrForbidden)
	}
	return a, nil
}

// CanAccess evaluates an app's bindings for a user (PRD §6.7): no
// bindings means every active user is allowed; with bindings, the
// evaluation mode decides — any binding match (EvalAny) or every binding
// match (EvalAll). The mode is strictest-wins across the app's rows: one
// EvalAll binding makes the whole app require-all, so a mixed config
// fails closed instead of silently widening access.
func (s *Service) CanAccess(ctx context.Context, user domain.User, appID uuid.UUID) (bool, error) {
	bindings, err := s.bindings.ForApplication(ctx, appID)
	if err != nil {
		return false, err
	}
	if len(bindings) == 0 {
		return true, nil
	}
	requireAll := false
	for _, b := range bindings {
		if b.EvalMode == domain.EvalAll {
			requireAll = true
			break
		}
	}
	if requireAll {
		for _, b := range bindings {
			ok, err := s.match(ctx, user, b)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	}
	for _, b := range bindings {
		ok, err := s.match(ctx, user, b)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// match evaluates one binding against the user.
func (s *Service) match(ctx context.Context, user domain.User, b domain.AppBinding) (bool, error) {
	switch b.BindingType {
	case domain.BindingUser:
		return b.UserID != nil && *b.UserID == user.ID, nil
	case domain.BindingGroup:
		if b.GroupID == nil {
			return false, nil
		}
		g, err := s.groups.ByID(ctx, *b.GroupID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
		return s.groups.IsMember(ctx, user.ID, g.Name)
	case domain.BindingPolicy:
		return matchPolicy(ctx, s.groups, user, b.PolicyExpr)
	default:
		return false, fmt.Errorf("%w: unknown binding type %q", domain.ErrValidation, b.BindingType)
	}
}

// matchPolicy evaluates a policy expression (see ValidatePolicyExpr for
// the grammar): clauses joined by | (OR).
func matchPolicy(ctx context.Context, groups domain.GroupStore, user domain.User, expr string) (bool, error) {
	clauses, err := parsePolicy(expr)
	if err != nil {
		return false, err
	}
	for _, c := range clauses {
		switch c.kind {
		case "group":
			ok, err := groups.IsMember(ctx, user.ID, c.value)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		case "email_domain":
			if emailDomain(user.Email) == strings.ToLower(c.value) {
				return true, nil
			}
		}
	}
	return false, nil
}

type policyClause struct {
	kind  string
	value string
}

// parsePolicy parses the v1 policy grammar: one or more clauses joined
// by | (OR). A clause is group:<name> (membership in the named group)
// or email_domain:<domain> (user email domain, case-insensitive).
// Examples: "group:engineering", "group:eng|email_domain:example.com".
func parsePolicy(expr string) ([]policyClause, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("%w: policy expression is required", domain.ErrValidation)
	}
	var out []policyClause
	for _, part := range strings.Split(expr, "|") {
		part = strings.TrimSpace(part)
		kind, value, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("%w: bad policy clause %q (want kind:value)", domain.ErrValidation, part)
		}
		kind, value = strings.TrimSpace(kind), strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("%w: bad policy clause %q (empty value)", domain.ErrValidation, part)
		}
		switch kind {
		case "group", "email_domain":
			out = append(out, policyClause{kind: kind, value: value})
		default:
			return nil, fmt.Errorf("%w: unknown policy kind %q (want group or email_domain)", domain.ErrValidation, kind)
		}
	}
	return out, nil
}

// ValidatePolicyExpr reports whether expr parses under the v1 grammar.
func ValidatePolicyExpr(expr string) error {
	_, err := parsePolicy(expr)
	return err
}

func emailDomain(email string) string {
	_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	if !ok {
		return ""
	}
	return domain
}

// ---------- admin: app catalog ----------

// CreateApp validates and stores a new application.
func (s *Service) CreateApp(ctx context.Context, a domain.Application) (domain.Application, error) {
	if err := checkURLs(a); err != nil {
		return domain.Application{}, err
	}
	return s.apps.Create(ctx, a)
}

// GetApp loads one application by id.
func (s *Service) GetApp(ctx context.Context, id uuid.UUID) (domain.Application, error) {
	return s.apps.ByID(ctx, id)
}

// ListApps pages the whole catalog including invisible apps (admin
// console). The dashboard uses MyApps instead.
func (s *Service) ListApps(ctx context.Context, limit, offset int) ([]domain.Application, int, error) {
	return s.apps.List(ctx, limit, offset)
}

// UpdateApp validates and rewrites an application.
func (s *Service) UpdateApp(ctx context.Context, a domain.Application) (domain.Application, error) {
	if err := checkURLs(a); err != nil {
		return domain.Application{}, err
	}
	return s.apps.Update(ctx, a)
}

// DeleteApp removes an application (bindings and provider configs
// cascade in SQL).
func (s *Service) DeleteApp(ctx context.Context, id uuid.UUID) error {
	return s.apps.Delete(ctx, id)
}

// checkURLs validates the admin-provided URLs: empty, an absolute
// http(s) URL, or a same-origin /path (e.g. /saml/sso?sp=...).
func checkURLs(a domain.Application) error {
	for name, raw := range map[string]string{"icon_url": a.IconURL, "launch_url": a.LaunchURL} {
		if raw == "" || strings.HasPrefix(raw, "/") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%w: %s must be an http(s) URL or a /path", domain.ErrValidation, name)
		}
	}
	return nil
}

// ---------- admin: bindings ----------

// CreateBinding validates and stores one binding. Exactly one target
// must be set, matching BindingType; the referenced user/group/app must
// exist so bindings never dangle.
func (s *Service) CreateBinding(ctx context.Context, b domain.AppBinding) (domain.AppBinding, error) {
	if _, err := s.apps.ByID(ctx, b.ApplicationID); err != nil {
		return domain.AppBinding{}, err
	}
	switch b.BindingType {
	case domain.BindingUser:
		if b.UserID == nil || b.GroupID != nil || b.PolicyExpr != "" {
			return domain.AppBinding{}, fmt.Errorf("%w: user bindings need exactly user_id", domain.ErrValidation)
		}
		if _, err := s.users.ByID(ctx, *b.UserID); err != nil {
			return domain.AppBinding{}, err
		}
	case domain.BindingGroup:
		if b.GroupID == nil || b.UserID != nil || b.PolicyExpr != "" {
			return domain.AppBinding{}, fmt.Errorf("%w: group bindings need exactly group_id", domain.ErrValidation)
		}
		if _, err := s.groups.ByID(ctx, *b.GroupID); err != nil {
			return domain.AppBinding{}, err
		}
	case domain.BindingPolicy:
		if b.UserID != nil || b.GroupID != nil {
			return domain.AppBinding{}, fmt.Errorf("%w: policy bindings need exactly policy_expr", domain.ErrValidation)
		}
		if err := ValidatePolicyExpr(b.PolicyExpr); err != nil {
			return domain.AppBinding{}, err
		}
	default:
		return domain.AppBinding{}, fmt.Errorf("%w: unknown binding type %q", domain.ErrValidation, b.BindingType)
	}
	if b.EvalMode == "" {
		b.EvalMode = domain.EvalAny
	}
	if b.EvalMode != domain.EvalAny && b.EvalMode != domain.EvalAll {
		return domain.AppBinding{}, fmt.Errorf("%w: eval_mode must be any or all", domain.ErrValidation)
	}
	return s.bindings.Create(ctx, b)
}

// ListBindings returns every binding of one application.
func (s *Service) ListBindings(ctx context.Context, appID uuid.UUID) ([]domain.AppBinding, error) {
	if _, err := s.apps.ByID(ctx, appID); err != nil {
		return nil, err
	}
	return s.bindings.ForApplication(ctx, appID)
}

// DeleteBinding removes one binding.
func (s *Service) DeleteBinding(ctx context.Context, id uuid.UUID) error {
	return s.bindings.Delete(ctx, id)
}

// listAll pages through the whole catalog (dashboards stay small —
// PRD §7 budgets 100 apps — but correctness must not depend on it).
func (s *Service) listAll(ctx context.Context) ([]domain.Application, error) {
	var all []domain.Application
	for offset := 0; ; offset += 200 {
		page, total, err := s.apps.List(ctx, 200, offset)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(all) >= total {
			return all, nil
		}
	}
}
