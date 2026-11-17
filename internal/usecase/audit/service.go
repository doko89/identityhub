// Package audit records and reads the audit log (PRD §6.9, TECH_SPEC §5).
//
// Every login — success or failure — produces exactly one entry; account
// actions (password change/reset, admin password set, group membership
// changes) are recorded with the same method vocabulary plus a
// detail.action discriminator so the method column stays tight.
package audit

import (
	"context"
	"fmt"

	"github.com/identityhub/identityhub/internal/domain"
)

// Detail actions for non-login entries (stored in detail.action).
const (
	ActionPasswordChange     = "password_change"
	ActionPasswordReset      = "password_reset"
	ActionAdminPasswordReset = "admin_password_reset"
	ActionMemberAdd          = "member_add"
	ActionMemberRemove       = "member_remove"
	ActionUserCreate         = "user_create"
	ActionUserDeactivate     = "user_deactivate"
	ActionUserReactivate     = "user_reactivate"
	ActionMFAEnroll          = "mfa_enroll"
	ActionMFADisable         = "mfa_disable"
	ActionMFARecoveryRegen   = "mfa_recovery_regenerate"
	ActionMFAReset           = "mfa_reset"
	ActionBrandingUpdate     = "branding_update"
)

// Service validates and persists audit entries.
type Service struct {
	store domain.AuditStore
	clock domain.Clock
}

// New builds a Service. Clock may be nil (takes domain.SystemClock) so
// wiring sites without a custom clock stay one-liners.
func New(store domain.AuditStore, clock domain.Clock) *Service {
	if clock == nil {
		clock = domain.SystemClock{}
	}
	return &Service{store: store, clock: clock}
}

// Record validates entry and appends it. At is stamped when zero; Detail
// defaults to an empty object. Callers fail the login when Record fails
// so the log stays complete (PRD §10: 100% of logins recorded).
func (s *Service) Record(ctx context.Context, e domain.AuditEntry) error {
	if e.Method == "" {
		return fmt.Errorf("%w: audit method is required", domain.ErrValidation)
	}
	if e.Result != domain.ResultSuccess && e.Result != domain.ResultFailure {
		return fmt.Errorf("%w: audit result must be success or failure", domain.ErrValidation)
	}
	if e.At.IsZero() {
		e.At = s.clock.Now()
	}
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	return s.store.Append(ctx, e)
}

// List returns a page of entries, newest first, plus the total count.
func (s *Service) List(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	return s.store.List(ctx, f)
}
