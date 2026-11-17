// Package domain holds IdentityHub entities and ports (interfaces).
//
// Dependency rule (TECH_SPEC §4): domain imports no other internal package.
// Adapters implement the interfaces declared here; usecases depend only on
// these interfaces, never on concrete adapters.
package domain

import "errors"

// Sentinel errors shared by usecases and delivery. Repositories wrap them
// with %w so errors.Is keeps working across layers.
var (
	// ErrNotFound means the requested record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means the request collides with existing state
	// (duplicate username, username already taken by LDAP sync, ...).
	ErrConflict = errors.New("conflict")
	// ErrValidation means the input itself is invalid.
	ErrValidation = errors.New("validation failed")
	// ErrUnauthorized means no valid session/credential was presented.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrForbidden means the authenticated actor may not do this
	// (e.g. not an ih_admin member).
	ErrForbidden = errors.New("forbidden")
	// ErrRateLimited means a rate limit or lockout rejected the request.
	ErrRateLimited = errors.New("rate limited")
)
