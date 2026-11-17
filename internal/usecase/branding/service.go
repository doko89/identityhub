// Package branding serves the singleton brand/theme row (PRD §6.8,
// TECH_SPEC §7): public reads for the login page and SPA theme provider,
// admin-only writes. The row is cached in memory and the cache is
// refreshed on every admin update, so reads never touch the database in
// the steady state.
package branding

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

// Service holds the branding rules. All outer details arrive as domain
// interfaces plus the shared audit service.
type Service struct {
	store domain.BrandingStore
	audit *audit.Service

	mu     sync.RWMutex
	cached *domain.Branding
}

// Deps wires a Service. Store and Audit are required.
type Deps struct {
	Store domain.BrandingStore
	Audit *audit.Service
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Audit == nil {
		return nil, errors.New("branding: Store and Audit are required")
	}
	return &Service{store: d.Store, audit: d.Audit}, nil
}

// Get returns the active brand, serving the in-memory copy after the first
// load. A failed load is never cached: the next call retries the store.
func (s *Service) Get(ctx context.Context) (domain.Branding, error) {
	s.mu.RLock()
	if s.cached != nil {
		out := *s.cached
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	b, err := s.store.Get(ctx)
	if err != nil {
		return domain.Branding{}, err
	}
	s.mu.Lock()
	s.cached = &b
	s.mu.Unlock()
	return b, nil
}

// Update rewrites the singleton row (id is forced to 1), refreshes the
// cache, and records an audit entry. Validation — hex colors, known
// themes, custom_css safety (no @import/url(</style>, max 10 KB) —
// rejects bad input before anything is stored.
func (s *Service) Update(ctx context.Context, actorID uuid.UUID, b domain.Branding) (domain.Branding, error) {
	b.ID = domain.BrandingID
	if err := b.Validate(); err != nil {
		return domain.Branding{}, err
	}
	out, err := s.store.Update(ctx, b)
	if err != nil {
		return domain.Branding{}, err
	}
	s.mu.Lock()
	s.cached = &out
	s.mu.Unlock()
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionBrandingUpdate},
	})
	return out, nil
}

// Invalidate drops the cached copy so the next Get reloads from the
// store. Admin updates refresh the cache themselves; this covers out-of-
// band row changes (manual SQL during incident recovery).
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}
