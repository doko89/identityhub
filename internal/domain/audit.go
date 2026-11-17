package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Login methods recorded in audit_log.method (PRD §6.9).
const (
	MethodPassword = "password"
	MethodTOTP     = "totp"
	MethodWebAuthn = "webauthn"
	MethodLDAP     = "ldap"
	MethodRADIUS   = "radius"
	MethodOIDC     = "oidc"
	MethodSAML     = "saml"
	MethodAPIKey   = "apikey"
)

// Audit results recorded in audit_log.result.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// AuditEntry is one row of audit_log. Every login — success or failure —
// produces exactly one entry (PRD §6.9).
type AuditEntry struct {
	ID            int64
	At            time.Time
	ActorUserID   *uuid.UUID
	ApplicationID *uuid.UUID
	Method        string
	Result        string
	IP            string
	Detail        map[string]any
}

// AuditFilter narrows List calls for the admin console + CSV export.
type AuditFilter struct {
	ActorUserID   *uuid.UUID
	ApplicationID *uuid.UUID
	Method        string
	Result        string
	Since         *time.Time
	Until         *time.Time
	Limit         int
	Offset        int
}

// AuditStore is the port for audit writes and reads.
type AuditStore interface {
	Append(ctx context.Context, e AuditEntry) error
	List(ctx context.Context, f AuditFilter) ([]AuditEntry, int, error)
}
