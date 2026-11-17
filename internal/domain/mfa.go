package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TOTPCredential is one row of mfa_totp. The seed is stored encrypted with
// ENC_KEY; LastStep is the TOTP time-step of the last accepted code and
// backs the atomic anti-replay rule (TECH_SPEC §8).
type TOTPCredential struct {
	UserID    uuid.UUID
	SeedEnc   []byte
	CreatedAt time.Time
	LastStep  int64
}

// RecoveryCode is one row of mfa_recovery_codes: single-use, stored hashed.
type RecoveryCode struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	CodeHash []byte
	UsedAt   *time.Time
}

// MFAPolicy answers "must this user pass a second factor for this app?"
// (PRD §6.6): admins always; regular users per app.
type MFAPolicy struct {
	// AppRequired marks per-application MFA for non-admin users.
	AppRequired map[uuid.UUID]bool
}

// RequiredFor reports whether MFA is mandatory.
func (p MFAPolicy) RequiredFor(isAdmin bool, appID uuid.UUID) bool {
	if isAdmin {
		return true
	}
	return p.AppRequired[appID]
}

// MFAStore persists TOTP credentials and recovery codes.
type MFAStore interface {
	EnrollTOTP(ctx context.Context, cred TOTPCredential) error
	TOTPOfUser(ctx context.Context, userID uuid.UUID) (TOTPCredential, error)
	// AcceptStep atomically records step as the last used step and fails
	// with ErrConflict when step <= the stored LastStep (anti-replay).
	AcceptStep(ctx context.Context, userID uuid.UUID, step int64) error
	DisableTOTP(ctx context.Context, userID uuid.UUID) error
	AddRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes [][]byte) error
	// ReplaceRecoveryCodes swaps the whole unused set (regeneration).
	ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes [][]byte) error
	UseRecoveryCode(ctx context.Context, userID uuid.UUID, hash []byte, at time.Time) error
	RemainingRecoveryCodes(ctx context.Context, userID uuid.UUID) (int, error)
}

// TOTP generates seeds and validates codes (PRD §6.6: 6 digits, 30s
// steps, current step + at most one previous). Implemented in
// internal/adapter/crypto on pquerna/otp; usecases see only this port so
// no protocol library leaks past the adapter layer (TECH_SPEC §4).
type TOTP interface {
	// NewSeed returns a fresh random seed and its otpauth:// URL for an
	// authenticator app. The seed is raw bytes; callers seal it before
	// storage and never return it after enroll.
	NewSeed(issuer, account string) (seed []byte, otpauthURL string, err error)
	// Verify matches code against the current or previous step at `at`
	// and returns the matched absolute step for the anti-replay record.
	// The next (future) step never matches: the window is narrow by
	// design (PRD §6.6).
	Verify(seed []byte, code string, at time.Time) (step int64, ok bool)
	// Code returns the code for one absolute step (tests, tooling).
	Code(seed []byte, step int64) (string, error)
	// QRCodePNG renders content as a PNG QR image of size px.
	QRCodePNG(content string, size int) ([]byte, error)
}

// SeedSealer encrypts TOTP seeds at rest with ENC_KEY (TECH_SPEC §5).
// Implemented in internal/adapter/crypto.
type SeedSealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}
