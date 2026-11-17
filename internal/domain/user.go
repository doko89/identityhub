package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserSource tells where a password lives. Local users authenticate against
// password_hash; LDAP users bind against the directory (PRD §6.10: password
// management endpoints reject LDAP users explicitly).
type UserSource string

const (
	SourceLocal UserSource = "local"
	SourceLDAP  UserSource = "ldap"
)

// User is one row of the users table (TECH_SPEC §5).
type User struct {
	ID          uuid.UUID
	Username    string
	Email       string
	DisplayName string
	// PasswordHash is nil for LDAP users; argon2id (bcrypt accepted only as
	// a verification fallback) for local users. A local user with no hash
	// is invite-pending: it cannot authenticate until a password is set
	// through the invite/reset flow.
	PasswordHash []byte
	Source       UserSource
	ExternalDN   string
	IsActive     bool
	AvatarURL    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Validate checks constructor-level invariants shared by all writers.
func (u User) Validate() error {
	if u.Username == "" {
		return wrapValidation("username is required")
	}
	if u.Source != SourceLocal && u.Source != SourceLDAP {
		return wrapValidation("source must be local or ldap")
	}
	return nil
}

// UserFilter narrows List/Search calls.
type UserFilter struct {
	Query  string // matches username/email/display name, empty = no filter
	Source UserSource
	Active *bool
	Limit  int
	Offset int
}

// UserStore is the port every user repository implements.
type UserStore interface {
	Create(ctx context.Context, u User) (User, error)
	ByID(ctx context.Context, id uuid.UUID) (User, error)
	ByUsername(ctx context.Context, username string) (User, error)
	// ByUsernameFold is the case-insensitive exact-match variant backing
	// the LDAP (uid=...) search short-circuit (caseIgnoreMatch). Prefer
	// ByUsername everywhere else; deployments must avoid usernames that
	// differ only by case (the first match wins).
	ByUsernameFold(ctx context.Context, username string) (User, error)
	ByEmail(ctx context.Context, email string) (User, error)
	List(ctx context.Context, f UserFilter) ([]User, int, error)
	// AllActive lists every active user in one query (LDAP tree
	// serving); paginated views keep using List. Only the served fields
	// are filled (id, username, email, display name, active flag) —
	// never password hashes.
	AllActive(ctx context.Context) ([]User, error)
	Update(ctx context.Context, u User) (User, error)
	SetActive(ctx context.Context, id uuid.UUID, active bool) error
	SetPasswordHash(ctx context.Context, id uuid.UUID, hash []byte) error
}
