package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AdminGroup is the reserved group whose members are IdentityHub admins
// (PRD §6.1). It is seeded by the initial migration and can neither be
// deleted nor renamed.
const AdminGroup = "ih_admin"

// Group is one row of the groups table.
type Group struct {
	ID          uuid.UUID
	Name        string
	Description string
}

// Validate rejects empty names and any attempt to rename the reserved group.
func (g Group) Validate() error {
	if g.Name == "" {
		return wrapValidation("group name is required")
	}
	return nil
}

// Membership is one row of user_groups.
type Membership struct {
	UserID  uuid.UUID
	GroupID uuid.UUID
}

// GroupStore is the port for groups and memberships.
type GroupStore interface {
	Create(ctx context.Context, g Group) (Group, error)
	ByID(ctx context.Context, id uuid.UUID) (Group, error)
	ByName(ctx context.Context, name string) (Group, error)
	List(ctx context.Context, limit, offset int) ([]Group, int, error)
	// Delete refuses the reserved ih_admin group (enforced in usecase AND
	// at the SQL level via a trigger/rule in later milestones; the
	// repository returns ErrForbidden for defense in depth).
	Delete(ctx context.Context, id uuid.UUID) error
	AddMember(ctx context.Context, userID, groupID uuid.UUID) error
	RemoveMember(ctx context.Context, userID, groupID uuid.UUID) error
	MemberIDs(ctx context.Context, groupID uuid.UUID) ([]uuid.UUID, error)
	GroupsOfUser(ctx context.Context, userID uuid.UUID) ([]Group, error)
	IsMember(ctx context.Context, userID uuid.UUID, groupName string) (bool, error)
}

// PasswordResetToken is one row of password_reset_tokens (PRD §6.10):
// single-use, 15-minute TTL, one active token per user, stored hashed.
type PasswordResetToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedIP string
	CreatedAt time.Time
}

// IsUsable reports whether the token may still be redeemed.
func (t PasswordResetToken) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && now.Before(t.ExpiresAt)
}

// PasswordResetStore persists reset tokens.
type PasswordResetStore interface {
	// Create revokes any previous active token for the user first.
	Create(ctx context.Context, tok PasswordResetToken) (PasswordResetToken, error)
	ByHash(ctx context.Context, hash []byte) (PasswordResetToken, error)
	MarkUsed(ctx context.Context, id uuid.UUID, at time.Time) error
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

// PasswordHistoryEntry is one row of password_history (PRD §6.10: last 10).
type PasswordHistoryEntry struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	PasswordHash []byte
	CreatedAt    time.Time
}

func wrapValidation(msg string) error {
	return fmt.Errorf("%w: %s", ErrValidation, msg)
}
