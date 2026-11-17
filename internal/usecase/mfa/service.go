// Package mfa implements TOTP enrollment/verification, single-use
// recovery codes, and the MFA policy (PRD §6.6, TECH_SPEC §8): admins
// always require a second factor; regular users per app or by opt-in.
//
// Anti-replay: every accepted code records its absolute 30s step, and the
// store accepts a step only when it is newer than the recorded one, in a
// single atomic UPDATE — a reused code fails even under concurrency.
package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

const (
	// DefaultIssuer names this IdP in authenticator apps.
	DefaultIssuer = "IdentityHub"
	// RecoveryCodeCount is the set size issued at enroll and regeneration.
	RecoveryCodeCount = 10
	// recoveryCodeBytes is 80 bits of entropy per code.
	recoveryCodeBytes = 10
)

// Service holds the MFA business rules. All outer details arrive as
// domain interfaces; Mailer may be nil (failure notifications skipped).
type Service struct {
	store  domain.MFAStore
	users  domain.UserStore
	groups domain.GroupStore
	apps   domain.ApplicationStore
	totp   domain.TOTP
	sealer domain.SeedSealer
	audit  *audit.Service
	clock  domain.Clock
	mailer domain.Mailer
	issuer string
	rand   func(n int) ([]byte, error)
}

// Deps wires a Service. Store, Users, Groups, Apps, TOTP, Sealer and
// Audit are required; Mailer is optional (nil skips the failure
// notification PRD §6.6 asks for).
type Deps struct {
	Store  domain.MFAStore
	Users  domain.UserStore
	Groups domain.GroupStore
	Apps   domain.ApplicationStore
	TOTP   domain.TOTP
	Sealer domain.SeedSealer
	Audit  *audit.Service
	Clock  domain.Clock
	Mailer domain.Mailer
	Issuer string
	Rand   func(n int) ([]byte, error)
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Users == nil || d.Groups == nil || d.Apps == nil ||
		d.TOTP == nil || d.Sealer == nil || d.Audit == nil {
		return nil, errors.New("mfa: Store, Users, Groups, Apps, TOTP, Sealer and Audit are required")
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock{}
	}
	rnd := d.Rand
	if rnd == nil {
		rnd = func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		}
	}
	issuer := d.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	return &Service{
		store: d.Store, users: d.Users, groups: d.Groups, apps: d.Apps,
		totp: d.TOTP, sealer: d.Sealer, audit: d.Audit, clock: d.Clock,
		mailer: d.Mailer, issuer: issuer, rand: rnd,
	}, nil
}

// EnrollChallenge is the in-progress enrollment: delivery holds Seed in
// the server-side session (never in the client) until Confirm burns it
// into the store. The QR image and URL are shown exactly once.
type EnrollChallenge struct {
	Seed       []byte
	OTPAuthURL string
	Secret     string // base32, for manual entry next to the QR
	QRCodePNG  []byte
}

// HasTOTP reports whether the user has an enrolled credential.
func (s *Service) HasTOTP(ctx context.Context, userID uuid.UUID) (bool, error) {
	_, err := s.store.TOTPOfUser(ctx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// EnrollStart generates a fresh seed for a user without MFA. The seed is
// returned for the pending session; nothing is stored until Confirm.
func (s *Service) EnrollStart(ctx context.Context, userID uuid.UUID) (EnrollChallenge, error) {
	u, err := s.activeUser(ctx, userID)
	if err != nil {
		return EnrollChallenge{}, err
	}
	if has, err := s.HasTOTP(ctx, userID); err != nil {
		return EnrollChallenge{}, err
	} else if has {
		return EnrollChallenge{}, fmt.Errorf("%w: TOTP is already enrolled; disable it first", domain.ErrConflict)
	}
	seed, url, err := s.totp.NewSeed(s.issuer, u.Username)
	if err != nil {
		return EnrollChallenge{}, fmt.Errorf("mfa: new seed: %w", err)
	}
	qr, err := s.totp.QRCodePNG(url, 256)
	if err != nil {
		return EnrollChallenge{}, fmt.Errorf("mfa: qr: %w", err)
	}
	return EnrollChallenge{
		Seed: seed, OTPAuthURL: url, QRCodePNG: qr,
		Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed),
	}, nil
}

// EnrollConfirm verifies the first code against the pending seed, stores
// the sealed credential, records the matched step (so the confirm code
// itself cannot be replayed as a login code), and issues the recovery
// set. The plaintext codes are returned exactly once.
func (s *Service) EnrollConfirm(ctx context.Context, userID uuid.UUID, seed []byte, code string) ([]string, error) {
	u, err := s.activeUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(seed) == 0 {
		return nil, fmt.Errorf("%w: enrollment expired; start again", domain.ErrValidation)
	}
	now := s.clock.Now()
	step, ok := s.totp.Verify(seed, normalizeCode(code), now)
	if !ok {
		_ = s.audit.Record(ctx, domain.AuditEntry{
			ActorUserID: &userID, Method: domain.MethodTOTP, Result: domain.ResultFailure,
			Detail: map[string]any{"action": audit.ActionMFAEnroll, "reason": "bad confirm code"},
		})
		return nil, fmt.Errorf("%w: invalid code", domain.ErrValidation)
	}
	sealed, err := s.sealer.Seal(seed)
	if err != nil {
		return nil, fmt.Errorf("mfa: seal seed: %w", err)
	}
	if err := s.store.EnrollTOTP(ctx, domain.TOTPCredential{UserID: userID, SeedEnc: sealed}); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, fmt.Errorf("%w: TOTP is already enrolled; disable it first", domain.ErrConflict)
		}
		return nil, fmt.Errorf("mfa: enroll: %w", err)
	}
	// Burn the confirm step: the same code must not double as a login.
	if err := s.store.AcceptStep(ctx, userID, step); err != nil {
		return nil, fmt.Errorf("mfa: burn confirm step: %w", err)
	}
	plain, hashes, err := s.newRecoverySet()
	if err != nil {
		return nil, err
	}
	if err := s.store.AddRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("mfa: store recovery codes: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &u.ID, Method: domain.MethodTOTP, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionMFAEnroll},
	})
	return plain, nil
}

// Verify checks a login-time TOTP code: narrow window, atomic
// anti-replay, fail-closed audit (PRD §10: 100% of logins recorded).
func (s *Service) Verify(ctx context.Context, userID uuid.UUID, code, ip string) error {
	u, err := s.activeUser(ctx, userID)
	if err != nil {
		return err
	}
	cred, err := s.store.TOTPOfUser(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("%w: TOTP is not enrolled", domain.ErrValidation)
		}
		return err
	}
	seed, err := s.sealer.Open(cred.SeedEnc)
	if err != nil {
		return fmt.Errorf("mfa: open seed: %w", err)
	}
	now := s.clock.Now()
	step, ok := s.totp.Verify(seed, normalizeCode(code), now)
	if !ok {
		s.notifyFailure(u)
		if err := s.audit.Record(ctx, domain.AuditEntry{
			ActorUserID: &userID, Method: domain.MethodTOTP, Result: domain.ResultFailure,
			IP: ip, Detail: map[string]any{"reason": "bad code"},
		}); err != nil {
			return fmt.Errorf("mfa: audit totp: %w", err)
		}
		return domain.ErrUnauthorized
	}
	if err := s.store.AcceptStep(ctx, userID, step); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			if err := s.audit.Record(ctx, domain.AuditEntry{
				ActorUserID: &userID, Method: domain.MethodTOTP, Result: domain.ResultFailure,
				IP: ip, Detail: map[string]any{"reason": "code reuse"},
			}); err != nil {
				return fmt.Errorf("mfa: audit totp: %w", err)
			}
			return domain.ErrUnauthorized
		}
		return fmt.Errorf("mfa: accept step: %w", err)
	}
	if err := s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &userID, Method: domain.MethodTOTP, Result: domain.ResultSuccess, IP: ip,
	}); err != nil {
		return fmt.Errorf("mfa: audit totp: %w", err)
	}
	return nil
}

// VerifyRecovery burns one recovery code for a login (the MFA-loss path,
// PRD §10). Unknown and already-used codes fail identically.
func (s *Service) VerifyRecovery(ctx context.Context, userID uuid.UUID, code, ip string) error {
	if _, err := s.activeUser(ctx, userID); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(normalizeRecovery(code)))
	if err := s.store.UseRecoveryCode(ctx, userID, sum[:], s.clock.Now()); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			if err := s.audit.Record(ctx, domain.AuditEntry{
				ActorUserID: &userID, Method: domain.MethodTOTP, Result: domain.ResultFailure,
				IP: ip, Detail: map[string]any{"reason": "bad recovery code"},
			}); err != nil {
				return fmt.Errorf("mfa: audit totp: %w", err)
			}
			return domain.ErrUnauthorized
		}
		return fmt.Errorf("mfa: use recovery code: %w", err)
	}
	if err := s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &userID, Method: domain.MethodTOTP, Result: domain.ResultSuccess,
		IP: ip, Detail: map[string]any{"via": "recovery_code"},
	}); err != nil {
		return fmt.Errorf("mfa: audit totp: %w", err)
	}
	return nil
}

// Status reports the user's factor state for /account/mfa.
type Status struct {
	HasTOTP                bool
	RemainingRecoveryCodes int
}

// Status loads the factor state.
func (s *Service) Status(ctx context.Context, userID uuid.UUID) (Status, error) {
	if _, err := s.users.ByID(ctx, userID); err != nil {
		return Status{}, err
	}
	has, err := s.HasTOTP(ctx, userID)
	if err != nil {
		return Status{}, err
	}
	st := Status{HasTOTP: has}
	if has {
		n, err := s.store.RemainingRecoveryCodes(ctx, userID)
		if err != nil {
			return Status{}, err
		}
		st.RemainingRecoveryCodes = n
	}
	return st, nil
}

// checkFactor re-authenticates with the old factor (TECH_SPEC §6.1):
// either the current TOTP code or an unused recovery code. Recovery
// codes presented here are burned — proving possession consumes them.
func (s *Service) checkFactor(ctx context.Context, userID uuid.UUID, code string) error {
	cred, err := s.store.TOTPOfUser(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("%w: TOTP is not enrolled", domain.ErrValidation)
		}
		return err
	}
	seed, err := s.sealer.Open(cred.SeedEnc)
	if err != nil {
		return fmt.Errorf("mfa: open seed: %w", err)
	}
	// TOTP first: unlike recovery codes, a successful check must not
	// consume anything besides the anti-replay step.
	if step, ok := s.totp.Verify(seed, normalizeCode(code), s.clock.Now()); ok {
		if err := s.store.AcceptStep(ctx, userID, step); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				return fmt.Errorf("%w: code already used", domain.ErrValidation)
			}
			return fmt.Errorf("mfa: accept step: %w", err)
		}
		return nil
	}
	sum := sha256.Sum256([]byte(normalizeRecovery(code)))
	if err := s.store.UseRecoveryCode(ctx, userID, sum[:], s.clock.Now()); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("%w: invalid code", domain.ErrValidation)
		}
		return fmt.Errorf("mfa: use recovery code: %w", err)
	}
	return nil
}

// ReAuth verifies one factor for step-up flows that are audited by
// their own action (password change, PRD §6.10): unlike Verify it
// writes no login audit entry — the caller's action audit is the record.
func (s *Service) ReAuth(ctx context.Context, userID uuid.UUID, code string) error {
	if _, err := s.activeUser(ctx, userID); err != nil {
		return err
	}
	return s.checkFactor(ctx, userID, code)
}

// DisableSelf removes the user's own factors after re-auth with the old
// factor (TECH_SPEC §6.1: changing factors requires the old one).
func (s *Service) DisableSelf(ctx context.Context, userID uuid.UUID, code string) error {
	u, err := s.activeUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.checkFactor(ctx, userID, code); err != nil {
		return err
	}
	if err := s.store.DisableTOTP(ctx, userID); err != nil {
		return fmt.Errorf("mfa: disable: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &u.ID, Method: domain.MethodTOTP, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionMFADisable},
	})
	return nil
}

// RegenerateRecovery swaps the recovery set after re-auth with the old
// factor. The plaintext codes are returned exactly once.
func (s *Service) RegenerateRecovery(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	u, err := s.activeUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := s.checkFactor(ctx, userID, code); err != nil {
		return nil, err
	}
	plain, hashes, err := s.newRecoverySet()
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("mfa: replace recovery codes: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &u.ID, Method: domain.MethodTOTP, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionMFARecoveryRegen},
	})
	return plain, nil
}

// AdminReset clears a user's factors without the old factor (the MFA-loss
// flow, PRD §10): the admin verifies identity out of band, the user
// re-enrolls at the next login. The acting admin and target are audited.
func (s *Service) AdminReset(ctx context.Context, actorID, targetID uuid.UUID) error {
	admin, err := s.groups.IsMember(ctx, actorID, domain.AdminGroup)
	if err != nil {
		return fmt.Errorf("mfa: admin check: %w", err)
	}
	if !admin {
		return fmt.Errorf("%w: administrator access required", domain.ErrForbidden)
	}
	if _, err := s.users.ByID(ctx, targetID); err != nil {
		return err
	}
	if err := s.store.DisableTOTP(ctx, targetID); err != nil {
		return fmt.Errorf("mfa: reset: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodTOTP, Result: domain.ResultSuccess,
		Detail: map[string]any{
			"action":         audit.ActionMFAReset,
			"target_user_id": targetID.String(),
		},
	})
	return nil
}

// RequiredForLogin answers whether the password login must continue to a
// second step: admins always (TECH_SPEC §8, no exceptions); regular
// users when they opted in by enrolling. Per-app requirements are
// enforced at launch/SSO time, not at login.
func (s *Service) RequiredForLogin(ctx context.Context, userID uuid.UUID) (required, enrolled bool, err error) {
	admin, err := s.groups.IsMember(ctx, userID, domain.AdminGroup)
	if err != nil {
		return false, false, fmt.Errorf("mfa: policy check: %w", err)
	}
	enrolled, err = s.HasTOTP(ctx, userID)
	if err != nil {
		return false, false, err
	}
	if admin {
		return true, enrolled, nil
	}
	return enrolled, enrolled, nil
}

// RequiredForApp answers whether the user must have passed a second
// factor in this session to open the app (PRD §6.6): admins always,
// regular users per the app's flag.
func (s *Service) RequiredForApp(ctx context.Context, userID, appID uuid.UUID) (bool, error) {
	admin, err := s.groups.IsMember(ctx, userID, domain.AdminGroup)
	if err != nil {
		return false, fmt.Errorf("mfa: policy check: %w", err)
	}
	if admin {
		return true, nil
	}
	app, err := s.apps.ByID(ctx, appID)
	if err != nil {
		return false, err
	}
	return app.MFARequired, nil
}

// activeUser loads the user and rejects disabled accounts.
func (s *Service) activeUser(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		return domain.User{}, err
	}
	if !u.IsActive {
		return domain.User{}, fmt.Errorf("%w: account disabled", domain.ErrForbidden)
	}
	return u, nil
}

// newRecoverySet generates RecoveryCodeCount plaintext codes plus their
// SHA-256 hashes. Only the hashes are stored; the plaintext is shown
// once and never logged.
func (s *Service) newRecoverySet() ([]string, [][]byte, error) {
	plain := make([]string, 0, RecoveryCodeCount)
	hashes := make([][]byte, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		raw, err := s.rand(recoveryCodeBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("mfa: recovery entropy: %w", err)
		}
		code := formatRecovery(raw)
		plain = append(plain, code)
		sum := sha256.Sum256([]byte(normalizeRecovery(code)))
		h := make([]byte, len(sum))
		copy(h, sum[:])
		hashes = append(hashes, h)
	}
	return plain, hashes, nil
}

// notifyFailure emails the user about a failed second-factor attempt
// (PRD §6.6). Delivery is best-effort: mail failures must not mask the
// invalid-code outcome, so they are swallowed deliberately after the
// audit entry — the audit log, not the inbox, is the record.
func (s *Service) notifyFailure(u domain.User) {
	if s.mailer == nil || u.Email == "" {
		return
	}
	subject := "Failed second-factor attempt on your IdentityHub account"
	text := "Someone entered a wrong second-factor code for your IdentityHub account (" + u.Username + ").\n\n" +
		"If this was you, try again. If it was not you, review your account security."
	_ = s.mailer.Send(u.Email, subject, text, "")
}

// normalizeCode trims spaces around a TOTP code.
func normalizeCode(code string) string {
	return strings.TrimSpace(code)
}

// formatRecovery renders raw bytes as XXXX-XXXX-XXXX-XXXX (base32).
func formatRecovery(raw []byte) string {
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// normalizeRecovery uppercases and strips separators so pasted codes
// compare equal regardless of formatting.
func normalizeRecovery(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
