// Package audit records and reads the audit log (PRD §6.9, TECH_SPEC §5).
//
// Every login — success or failure — produces exactly one entry; account
// actions (password change/reset, admin password set, group membership
// changes) are recorded with the same method vocabulary plus a
// detail.action discriminator so the method column stays tight.
package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

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
	ActionAPIKeyCreate       = "api_key_create"
	ActionAPIKeyRevoke       = "api_key_revoke"
	ActionAttrDefCreate      = "attr_def_create"
	ActionAttrDefDelete      = "attr_def_delete"
	ActionUserAttrsUpdate    = "user_attrs_update"
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

// MaxExportRows caps CSV exports so one download cannot exhaust memory.
// Admins narrow large windows with the since/until filters.
const MaxExportRows = 10000

// ExportCSV writes up to MaxExportRows matching entries, newest first, as
// RFC 4180 CSV (encoding/csv quoting). The filter's pagination is
// ignored: exports always start from the newest row. It returns the
// number of data rows written.
func (s *Service) ExportCSV(ctx context.Context, f domain.AuditFilter, w io.Writer) (int, error) {
	f.Limit = MaxExportRows
	f.Offset = 0
	entries, _, err := s.store.List(ctx, f)
	if err != nil {
		return 0, err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"id", "at", "actor_user_id", "application_id", "method", "result", "ip", "detail"}); err != nil {
		return 0, err
	}
	for _, e := range entries {
		detail := e.Detail
		if detail == nil {
			detail = map[string]any{}
		}
		raw, err := json.Marshal(detail)
		if err != nil {
			return 0, err
		}
		var actor, app string
		if e.ActorUserID != nil {
			actor = e.ActorUserID.String()
		}
		if e.ApplicationID != nil {
			app = e.ApplicationID.String()
		}
		rec := []string{
			strconv.FormatInt(e.ID, 10), e.At.UTC().Format(time.RFC3339),
			actor, app, e.Method, e.Result, e.IP, string(raw),
		}
		if err := cw.Write(rec); err != nil {
			return 0, err
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return 0, err
	}
	return len(entries), nil
}
