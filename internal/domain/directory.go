package domain

import (
	"context"

	"github.com/google/uuid"
)

// LDAPUser is one directory entry mapped to a local user row (PRD §6.2).
// MemberOf carries the entry's group DNs and backs the LDAP_ADMIN_GROUP_DN
// mapping (members auto-join ih_admin on sync).
type LDAPUser struct {
	Username    string
	Email       string
	DisplayName string
	DN          string
	MemberOf    []string
}

// LDAPGroup is one directory group.
type LDAPGroup struct {
	Name    string
	DN      string
	Members []string // member DNs
}

// DirectorySnapshot is one full pull of the upstream directory.
type DirectorySnapshot struct {
	Users  []LDAPUser
	Groups []LDAPGroup
}

// Directory is the port for the upstream LDAP connector (TECH_SPEC §2).
// Implemented by internal/adapter/ldapclient with go-ldap. All calls must
// have timeouts: LDAP failures surface explicit errors, never a hang
// (PRD §5.1).
type Directory interface {
	// Authenticate binds to the directory as username. It returns
	// ErrUnauthorized for bad credentials and ErrNotFound when username is
	// unknown to the directory.
	Authenticate(ctx context.Context, username, password string) (LDAPUser, error)
	// Snapshot pulls all users and groups for periodic sync.
	Snapshot(ctx context.Context) (DirectorySnapshot, error)
	// Ping verifies the connector can reach the directory (used by the
	// admin connection test and the worker).
	Ping(ctx context.Context) error
}

// PasswordHistoryStore persists previous password hashes for the
// "not equal to the last 10" policy rule (PRD §6.10).
type PasswordHistoryStore interface {
	// Add records hash and trims the user's history to the newest 10.
	Add(ctx context.Context, userID uuid.UUID, hash []byte) error
	// Recent returns up to limit newest hashes, newest first.
	Recent(ctx context.Context, userID uuid.UUID, limit int) ([][]byte, error)
}

// SessionRegistry tracks which login sessions belong to which user so a
// password change/reset can terminate all other sessions (PRD §6.10).
// Tokens are the scs session tokens; revoking deletes the matching rows
// from the scs sessions table.
type SessionRegistry interface {
	// Register links a fresh session token to a user (idempotent).
	Register(ctx context.Context, userID uuid.UUID, token string) error
	// Unregister drops one token (logout, idempotent).
	Unregister(ctx context.Context, token string) error
	// RevokeOthers deletes every session of userID except keepToken and
	// returns the revoked count.
	RevokeOthers(ctx context.Context, userID uuid.UUID, keepToken string) (int64, error)
	// RevokeAll deletes every session of userID (admin disable, ...).
	RevokeAll(ctx context.Context, userID uuid.UUID) (int64, error)
}
