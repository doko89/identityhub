package domain

import (
	"context"

	"github.com/google/uuid"
)

// BindingType selects what an AppBinding points at (TECH_SPEC §5).
type BindingType string

const (
	BindingUser   BindingType = "user"
	BindingGroup  BindingType = "group"
	BindingPolicy BindingType = "policy"
)

// EvalMode controls how multiple bindings combine (PRD §6.7).
type EvalMode string

const (
	// EvalAny grants access when at least one binding matches.
	EvalAny EvalMode = "any"
	// EvalAll grants access only when every binding matches.
	EvalAll EvalMode = "all"
)

// AppBinding is one row of app_bindings. Exactly one of UserID/GroupID/
// PolicyExpr is set, matching BindingType.
type AppBinding struct {
	ID            uuid.UUID
	ApplicationID uuid.UUID
	BindingType   BindingType
	UserID        *uuid.UUID
	GroupID       *uuid.UUID
	PolicyExpr    string
	EvalMode      EvalMode
}

// BindingStore persists visibility bindings.
type BindingStore interface {
	Create(ctx context.Context, b AppBinding) (AppBinding, error)
	ForApplication(ctx context.Context, appID uuid.UUID) ([]AppBinding, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
