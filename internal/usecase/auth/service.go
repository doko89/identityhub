// Package auth implements password login and password management
// (PRD §6.10, TECH_SPEC §6.1): login against local hashes or the upstream
// directory, self-service change, forgot/reset via single-use emailed
// tokens, and admin reset for local users.
//
// Audit rule: every login attempt produces exactly one audit entry, and a
// failed audit write fails the login (fail-closed) so the log stays
// complete (PRD §10). Non-login account actions are audited with
// detail.action discriminators (see usecase/audit).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

// ErrDirectoryUnavailable signals that the upstream directory itself is
// unreachable (distinct from bad credentials). Delivery maps it to 503
// with an explicit message (PRD §5.1).
var ErrDirectoryUnavailable = errors.New("directory unavailable")

// ErrMFARequired signals that a legacy bind was denied because the
// account must use MFA (TECH_SPEC §6.4–6.5). Legacy delivery maps it to
// a protocol-level invalid-credentials response with an explanatory
// diagnostic (there is no "MFA required" code in LDAP/RADIUS).
var ErrMFARequired = errors.New("multi-factor authentication is required for this account; legacy bind is not allowed")

const (
	// MinPasswordLength is the v1 password policy floor (PRD §6.10).
	MinPasswordLength = 12
	// HistoryDepth is how many previous passwords a new one must differ
	// from (PRD §6.10).
	HistoryDepth = 10
	// ResetTokenBytes is 256 bits of randomness (TECH_SPEC §8).
	ResetTokenBytes = 32
	// ResetTokenTTL bounds a reset link's life (PRD §6.10).
	ResetTokenTTL = 15 * time.Minute
)

// LegacyMFAPolicy answers whether a user must pass a second factor for
// an app. *mfa.Service implements it; auth holds it as an interface so
// the M4 admin-only gate stays intact when MFA is unwired (nil).
type LegacyMFAPolicy interface {
	RequiredForApp(ctx context.Context, userID, appID uuid.UUID) (bool, error)
}

// Service holds the auth business rules. All outer details arrive as
// domain interfaces; Directory may be nil (LDAP upstream disabled).
type Service struct {
	users    domain.UserStore
	groups   domain.GroupStore
	resets   domain.PasswordResetStore
	history  domain.PasswordHistoryStore
	sessions domain.SessionRegistry
	audit    *audit.Service
	hasher   domain.PasswordHasher
	clock    domain.Clock
	mailer   domain.Mailer
	dir      domain.Directory
	mfa      LegacyMFAPolicy
	baseURL  string
	tokenGen func(n int) ([]byte, error)
	attrs    domain.UserAttrStore
}

// Deps wires a Service. Users, Resets, History, Sessions, Audit, Hasher
// and Mailer are required; Directory is optional (nil disables LDAP).
type Deps struct {
	Users    domain.UserStore
	Groups   domain.GroupStore
	Resets   domain.PasswordResetStore
	History  domain.PasswordHistoryStore
	Sessions domain.SessionRegistry
	Audit    *audit.Service
	Hasher   domain.PasswordHasher
	Clock    domain.Clock
	Mailer   domain.Mailer
	// Directory is nil when LDAP_URL is unset.
	Directory domain.Directory
	// MFAPolicy is nil in tests that predate MFA; production wires
	// *mfa.Service so per-app policy reaches legacy binds.
	MFAPolicy LegacyMFAPolicy
	// BaseURL is the public origin for emailed reset links.
	BaseURL string
	// TokenGen overrides crypto/rand in tests.
	TokenGen func(n int) ([]byte, error)
	// Attrs is optional (nil skips upstream attribute application on
	// just-in-time provisioning).
	Attrs domain.UserAttrStore
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Users == nil || d.Groups == nil || d.Resets == nil || d.History == nil ||
		d.Sessions == nil || d.Audit == nil || d.Hasher == nil || d.Mailer == nil {
		return nil, errors.New("auth: Users, Groups, Resets, History, Sessions, Audit, Hasher and Mailer are required")
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock{}
	}
	gen := d.TokenGen
	if gen == nil {
		gen = func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		}
	}
	return &Service{
		users: d.Users, groups: d.Groups, resets: d.Resets, history: d.History,
		sessions: d.Sessions, audit: d.Audit, hasher: d.Hasher, clock: d.Clock,
		mailer: d.Mailer, dir: d.Directory, mfa: d.MFAPolicy,
		baseURL:  strings.TrimRight(d.BaseURL, "/"),
		tokenGen: gen, attrs: d.Attrs,
	}, nil
}

// LoginInput is one password-login attempt.
type LoginInput struct {
	Username string
	Password string
	IP       string
}

// LegacyLoginInput is one credential check from a legacy provider
// (TECH_SPEC §6.4–6.5): an LDAP bind or a RADIUS PAP Access-Request.
// Method names the protocol for the audit log; ApplicationID links the
// attempt to its app when the protocol identifies one (RADIUS NAS;
// nil for the global LDAP tree).
type LegacyLoginInput struct {
	Username      string
	Password      string
	IP            string
	Method        string
	ApplicationID *uuid.UUID
}

// credentialCheck is the unaudited outcome of checking username/password.
// Both Login and LoginLegacy verify through checkCredentials and differ
// only in how they audit (method/app) and in the legacy MFA gate.
type credentialCheck struct {
	user    domain.User
	hasUser bool
	// backend names the store that was consulted: MethodPassword for the
	// local hash, MethodLDAP for the directory. HTTP login audits with
	// it; legacy login audits with the protocol method instead.
	backend string
	// reason is the audit reason on failure; empty on success.
	reason string
	// err is nil on success, ErrUnauthorized/ErrForbidden on credential
	// failures, or a wrapped outage/infra error.
	err error
	// outage marks a directory failure (audit best-effort, explicit
	// error); infra marks a repository failure (no audit at all).
	outage bool
	infra  bool
}

// Login verifies username/password against the local hash (local users)
// or the directory (LDAP users, including just-in-time provisioning on
// first login after the account exists upstream). It returns
// domain.ErrUnauthorized for unknown users and bad passwords without
// distinguishing them, and a distinct explicit error when the directory
// itself is unreachable (PRD §5.1).
func (s *Service) Login(ctx context.Context, in LoginInput) (domain.User, error) {
	chk := s.checkCredentials(ctx, in.Username, in.Password)
	if chk.infra {
		return domain.User{}, chk.err
	}
	var actor *domain.User
	if chk.hasUser {
		actor = &chk.user
	}
	if chk.outage {
		_ = s.auditLogin(ctx, actor, nil, chk.backend, domain.ResultFailure, in.IP, chk.reason)
		return domain.User{}, chk.err
	}
	if chk.err != nil {
		if err := s.auditLogin(ctx, actor, nil, chk.backend, domain.ResultFailure, in.IP, chk.reason); err != nil {
			return domain.User{}, err
		}
		return domain.User{}, chk.err
	}
	if err := s.auditLogin(ctx, actor, nil, chk.backend, domain.ResultSuccess, in.IP, ""); err != nil {
		return domain.User{}, err
	}
	return chk.user, nil
}

// LoginLegacy checks the same credentials as Login but audits under the
// legacy protocol method and denies users who must use MFA (TECH_SPEC
// §6.4–6.5: direct bind is rejected when the user must use MFA, since a
// legacy bind cannot prompt for a second factor). Admins are always
// MFA-bound (TECH_SPEC §8, no exceptions); with an MFAPolicy wired,
// regular users are denied too when the target app requires MFA. The
// global LDAP tree carries no app identity, so its binds keep the
// admin-only gate.
func (s *Service) LoginLegacy(ctx context.Context, in LegacyLoginInput) (domain.User, error) {
	if in.Method != domain.MethodLDAP && in.Method != domain.MethodRADIUS {
		return domain.User{}, fmt.Errorf("%w: legacy login method must be ldap or radius", domain.ErrValidation)
	}
	chk := s.checkCredentials(ctx, in.Username, in.Password)
	if chk.infra {
		return domain.User{}, chk.err
	}
	var actor *domain.User
	if chk.hasUser {
		actor = &chk.user
	}
	if chk.outage {
		_ = s.auditLogin(ctx, actor, in.ApplicationID, in.Method, domain.ResultFailure, in.IP, chk.reason)
		return domain.User{}, chk.err
	}
	if chk.err != nil {
		if err := s.auditLogin(ctx, actor, in.ApplicationID, in.Method, domain.ResultFailure, in.IP, chk.reason); err != nil {
			return domain.User{}, err
		}
		return domain.User{}, chk.err
	}
	denied, err := s.legacyMFADenied(ctx, chk.user.ID, in.ApplicationID)
	if err != nil {
		return domain.User{}, err
	}
	if denied {
		if err := s.auditLogin(ctx, actor, in.ApplicationID, in.Method, domain.ResultFailure, in.IP, "mfa required"); err != nil {
			return domain.User{}, err
		}
		return domain.User{}, ErrMFARequired
	}
	if err := s.auditLogin(ctx, actor, in.ApplicationID, in.Method, domain.ResultSuccess, in.IP, ""); err != nil {
		return domain.User{}, err
	}
	return chk.user, nil
}

// ConfirmCachedBind records a legacy bind whose password already verified
// against a delivery-layer bind cache. It re-checks live account state —
// existence, active flag, MFA deny — and audits exactly like LoginLegacy;
// only the expensive credential check is skipped. Callers must only pass
// userIDs whose password verified within the cache TTL for a local user
// (directory users are never cached: no local write marks an upstream
// password change stale).
func (s *Service) ConfirmCachedBind(ctx context.Context, userID uuid.UUID, method, ip string) (domain.User, error) {
	if method != domain.MethodLDAP && method != domain.MethodRADIUS {
		return domain.User{}, fmt.Errorf("%w: legacy login method must be ldap or radius", domain.ErrValidation)
	}
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			if aerr := s.auditLogin(ctx, nil, nil, method, domain.ResultFailure, ip, "unknown user"); aerr != nil {
				return domain.User{}, aerr
			}
			return domain.User{}, domain.ErrUnauthorized
		}
		return domain.User{}, fmt.Errorf("auth: cached bind lookup: %w", err)
	}
	if !u.IsActive {
		if err := s.auditLogin(ctx, &u, nil, method, domain.ResultFailure, ip, "account disabled"); err != nil {
			return domain.User{}, err
		}
		return domain.User{}, domain.ErrForbidden
	}
	denied, err := s.legacyMFADenied(ctx, u.ID, nil)
	if err != nil {
		return domain.User{}, err
	}
	if denied {
		if err := s.auditLogin(ctx, &u, nil, method, domain.ResultFailure, ip, "mfa required"); err != nil {
			return domain.User{}, err
		}
		return domain.User{}, ErrMFARequired
	}
	if err := s.auditLogin(ctx, &u, nil, method, domain.ResultSuccess, ip, ""); err != nil {
		return domain.User{}, err
	}
	return u, nil
}

// legacyMFADenied reports whether the legacy bind must be rejected for
// MFA: admins always; when a policy and an app identity are both
// present, per-app requirements for regular users too.
func (s *Service) legacyMFADenied(ctx context.Context, userID uuid.UUID, appID *uuid.UUID) (bool, error) {
	if s.mfa != nil && appID != nil {
		required, err := s.mfa.RequiredForApp(ctx, userID, *appID)
		if err != nil {
			return false, fmt.Errorf("auth: mfa policy check: %w", err)
		}
		return required, nil
	}
	admin, err := s.groups.IsMember(ctx, userID, domain.AdminGroup)
	if err != nil {
		return false, fmt.Errorf("auth: mfa policy check: %w", err)
	}
	return admin, nil
}

// checkCredentials verifies username/password without auditing: local
// hash for local users, directory bind for LDAP users, with
// just-in-time provisioning when the account exists only upstream.
func (s *Service) checkCredentials(ctx context.Context, username, password string) credentialCheck {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return credentialCheck{backend: domain.MethodPassword, reason: "missing credentials", err: domain.ErrUnauthorized}
	}
	u, err := s.users.ByUsername(ctx, username)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return credentialCheck{infra: true, err: fmt.Errorf("auth: user lookup: %w", err)}
	}
	if errors.Is(err, domain.ErrNotFound) {
		return s.checkUnknownUser(ctx, username, password)
	}
	if u.Source == domain.SourceLDAP {
		return s.checkLDAPUser(ctx, u, password)
	}
	return s.checkLocalUser(u, password)
}

// checkUnknownUser tries the directory (JIT provisioning) when the local
// row is missing; without a directory it is a plain failure.
func (s *Service) checkUnknownUser(ctx context.Context, username, password string) credentialCheck {
	if s.dir == nil {
		return credentialCheck{backend: domain.MethodPassword, reason: "unknown user", err: domain.ErrUnauthorized}
	}
	lu, err := s.dir.Authenticate(ctx, username, password)
	switch {
	case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrUnauthorized):
		return credentialCheck{backend: domain.MethodLDAP, reason: "directory rejected", err: domain.ErrUnauthorized}
	case err != nil:
		return credentialCheck{
			backend: domain.MethodLDAP, reason: "directory unavailable",
			err: fmt.Errorf("auth: %w: %v", ErrDirectoryUnavailable, err), outage: true,
		}
	}
	// Directory accepted: provision the local cache row (PRD §5.1). A
	// concurrent worker sync may win the race; on conflict re-read.
	u, err := s.users.Create(ctx, domain.User{
		Username: lu.Username, Email: lu.Email, DisplayName: lu.DisplayName,
		Source: domain.SourceLDAP, ExternalDN: lu.DN, IsActive: true,
	})
	if errors.Is(err, domain.ErrConflict) {
		u, err = s.users.ByUsername(ctx, username)
	}
	if err != nil {
		return credentialCheck{infra: true, err: fmt.Errorf("auth: provision ldap user: %w", err)}
	}
	if !u.IsActive {
		return credentialCheck{user: u, hasUser: true, backend: domain.MethodLDAP,
			reason: "account disabled", err: fmt.Errorf("%w: account disabled", domain.ErrForbidden)}
	}
	// Mapped upstream attributes land on the provisioned row; a nil map
	// means no mapping is configured and skips the write.
	if lu.Attrs != nil && s.attrs != nil {
		defs, err := s.attrs.ListDefs(ctx)
		if err != nil {
			return credentialCheck{infra: true, err: fmt.Errorf("auth: provision list attr defs: %w", err)}
		}
		if err := s.attrs.ApplyUpstreamValues(ctx, u.ID, domain.UpstreamAttrValues(defs, lu.Attrs)); err != nil {
			return credentialCheck{infra: true, err: fmt.Errorf("auth: provision attrs: %w", err)}
		}
	}
	return credentialCheck{user: u, hasUser: true, backend: domain.MethodLDAP}
}

func (s *Service) checkLocalUser(u domain.User, password string) credentialCheck {
	if !s.hasher.Verify(password, u.PasswordHash) {
		return credentialCheck{user: u, hasUser: true, backend: domain.MethodPassword,
			reason: "bad password", err: domain.ErrUnauthorized}
	}
	if !u.IsActive {
		return credentialCheck{user: u, hasUser: true, backend: domain.MethodPassword,
			reason: "account disabled", err: fmt.Errorf("%w: account disabled", domain.ErrForbidden)}
	}
	return credentialCheck{user: u, hasUser: true, backend: domain.MethodPassword}
}

func (s *Service) checkLDAPUser(ctx context.Context, u domain.User, password string) credentialCheck {
	if s.dir == nil {
		return credentialCheck{user: u, hasUser: true, backend: domain.MethodLDAP,
			reason: "ldap disabled", err: domain.ErrUnauthorized}
	}
	_, err := s.dir.Authenticate(ctx, u.Username, password)
	switch {
	case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrUnauthorized):
		return credentialCheck{user: u, hasUser: true, backend: domain.MethodLDAP,
			reason: "directory rejected", err: domain.ErrUnauthorized}
	case err != nil:
		return credentialCheck{user: u, hasUser: true, backend: domain.MethodLDAP,
			reason: "directory unavailable",
			err:    fmt.Errorf("auth: %w: %v", ErrDirectoryUnavailable, err), outage: true}
	}
	if !u.IsActive {
		return credentialCheck{user: u, hasUser: true, backend: domain.MethodLDAP,
			reason: "account disabled", err: fmt.Errorf("%w: account disabled", domain.ErrForbidden)}
	}
	return credentialCheck{user: u, hasUser: true, backend: domain.MethodLDAP}
}

// auditLogin records one login attempt. A failed write fails the login
// (fail-closed) so the audit log stays complete.
func (s *Service) auditLogin(ctx context.Context, u *domain.User, appID *uuid.UUID, method, result, ip, reason string) error {
	e := domain.AuditEntry{Method: method, Result: result, IP: ip, Detail: map[string]any{}}
	if u != nil {
		id := u.ID
		e.ActorUserID = &id
	}
	if appID != nil {
		id := *appID
		e.ApplicationID = &id
	}
	if reason != "" {
		e.Detail["reason"] = reason
	}
	if err := s.audit.Record(ctx, e); err != nil {
		return fmt.Errorf("auth: audit login: %w", err)
	}
	return nil
}

// checkNewPassword enforces the v1 policy (PRD §6.10): minimum length and
// difference from the current plus the last HistoryDepth passwords.
func (s *Service) checkNewPassword(candidate string, currentHash []byte, history [][]byte) error {
	if len(candidate) < MinPasswordLength {
		return fmt.Errorf("%w: password must be at least %d characters", domain.ErrValidation, MinPasswordLength)
	}
	if len(currentHash) > 0 && s.hasher.Verify(candidate, currentHash) {
		return fmt.Errorf("%w: new password must differ from the current password", domain.ErrValidation)
	}
	for _, h := range history {
		if s.hasher.Verify(candidate, h) {
			return fmt.Errorf("%w: new password must differ from the last %d passwords", domain.ErrValidation, HistoryDepth)
		}
	}
	return nil
}

// requireLocal rejects LDAP users from password management with the
// explicit message PRD §6.10 requires.
func requireLocal(u domain.User) error {
	if u.Source != domain.SourceLocal {
		return fmt.Errorf("%w: password for LDAP users is managed in the directory; contact your directory admin", domain.ErrValidation)
	}
	return nil
}

// ChangePassword verifies the current password, applies the policy, and
// terminates every other session (PRD §6.10). keepToken is the current
// scs session token and is preserved. MFA re-auth gating happens in the
// HTTP layer (TOTP lands in M5); this method enforces the password rules.
// It returns the number of other sessions terminated.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current, new1, new2, keepToken string) (int64, error) {
	if new1 != new2 {
		return 0, fmt.Errorf("%w: new passwords do not match", domain.ErrValidation)
	}
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		return 0, err
	}
	if err := requireLocal(u); err != nil {
		return 0, err
	}
	if !s.hasher.Verify(current, u.PasswordHash) {
		return 0, domain.ErrUnauthorized
	}
	past, err := s.history.Recent(ctx, userID, HistoryDepth)
	if err != nil {
		return 0, fmt.Errorf("auth: read password history: %w", err)
	}
	if err := s.checkNewPassword(new1, u.PasswordHash, past); err != nil {
		return 0, err
	}
	hash, err := s.hasher.Hash(new1)
	if err != nil {
		return 0, fmt.Errorf("auth: hash password: %w", err)
	}
	if err := s.users.SetPasswordHash(ctx, userID, hash); err != nil {
		return 0, fmt.Errorf("auth: set password: %w", err)
	}
	if err := s.history.Add(ctx, userID, u.PasswordHash); err != nil {
		return 0, fmt.Errorf("auth: record password history: %w", err)
	}
	revoked, err := s.sessions.RevokeOthers(ctx, userID, keepToken)
	if err != nil {
		return 0, fmt.Errorf("auth: revoke other sessions: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &userID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionPasswordChange, "sessions_revoked": revoked},
	})
	return revoked, nil
}

// ForgotPassword issues a single-use reset token and emails the link.
// It returns nil for unknown addresses and LDAP users alike (generic
// responses, TECH_SPEC §8) and only fails on infrastructure errors —
// which the HTTP layer logs while still answering generically.
func (s *Service) ForgotPassword(ctx context.Context, loginOrEmail, ip string) error {
	key := strings.TrimSpace(loginOrEmail)
	if key == "" {
		return nil
	}
	u, err := s.users.ByUsername(ctx, key)
	if errors.Is(err, domain.ErrNotFound) {
		u, err = s.users.ByEmail(ctx, key)
	}
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("auth: forgot lookup: %w", err)
	}
	if u.Source != domain.SourceLocal || !u.IsActive || u.Email == "" {
		return nil
	}
	raw, err := s.tokenGen(ResetTokenBytes)
	if err != nil {
		return fmt.Errorf("auth: reset token entropy: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(encoded))
	now := s.clock.Now()
	if _, err := s.resets.Create(ctx, domain.PasswordResetToken{
		UserID: u.ID, TokenHash: sum[:], ExpiresAt: now.Add(ResetTokenTTL), CreatedIP: ip,
	}); err != nil {
		return fmt.Errorf("auth: store reset token: %w", err)
	}
	link := s.baseURL + "/reset-password?token=" + encoded
	subject := "Reset your IdentityHub password"
	text := "Someone requested a password reset for your IdentityHub account.\n\n" +
		"Open this link within 15 minutes to choose a new password:\n" + link + "\n\n" +
		"If this was not you, ignore this message — your password stays unchanged."
	if err := s.mailer.Send(u.Email, subject, text, ""); err != nil {
		return fmt.Errorf("auth: send reset mail: %w", err)
	}
	return nil
}

// ResetPassword redeems a forgot-password token. Unknown, expired and
// used tokens all fail with the same generic error.
func (s *Service) ResetPassword(ctx context.Context, rawToken, new1, new2 string) error {
	if new1 != new2 {
		return fmt.Errorf("%w: new passwords do not match", domain.ErrValidation)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(rawToken))
	if err != nil || len(raw) != ResetTokenBytes {
		return fmt.Errorf("%w: invalid or expired reset token", domain.ErrValidation)
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawToken)))
	tok, err := s.resets.ByHash(ctx, sum[:])
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("%w: invalid or expired reset token", domain.ErrValidation)
		}
		return fmt.Errorf("auth: reset lookup: %w", err)
	}
	now := s.clock.Now()
	if !tok.IsUsable(now) {
		return fmt.Errorf("%w: invalid or expired reset token", domain.ErrValidation)
	}
	u, err := s.users.ByID(ctx, tok.UserID)
	if err != nil {
		return err
	}
	if err := requireLocal(u); err != nil {
		return err
	}
	past, err := s.history.Recent(ctx, u.ID, HistoryDepth)
	if err != nil {
		return fmt.Errorf("auth: read password history: %w", err)
	}
	if err := s.checkNewPassword(new1, u.PasswordHash, past); err != nil {
		return err
	}
	// MarkUsed first: the atomic single-use gate. A concurrent redemption
	// loses here and fails closed below.
	if err := s.resets.MarkUsed(ctx, tok.ID, now); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("%w: invalid or expired reset token", domain.ErrValidation)
		}
		return fmt.Errorf("auth: consume reset token: %w", err)
	}
	hash, err := s.hasher.Hash(new1)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	if err := s.users.SetPasswordHash(ctx, u.ID, hash); err != nil {
		return fmt.Errorf("auth: set password: %w", err)
	}
	if err := s.history.Add(ctx, u.ID, u.PasswordHash); err != nil {
		return fmt.Errorf("auth: record password history: %w", err)
	}
	revoked, err := s.sessions.RevokeAll(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("auth: revoke sessions: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &u.ID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionPasswordReset, "sessions_revoked": revoked},
	})
	return nil
}

// AdminSetPassword lets an ih_admin member set a local user's password
// (PRD §6.10). LDAP targets are rejected explicitly; the action is
// audited with acting admin, target and time.
func (s *Service) AdminSetPassword(ctx context.Context, actorID, targetID uuid.UUID, newPassword string) error {
	admin, err := s.groups.IsMember(ctx, actorID, domain.AdminGroup)
	if err != nil {
		return fmt.Errorf("auth: admin check: %w", err)
	}
	if !admin {
		return fmt.Errorf("%w: administrator access required", domain.ErrForbidden)
	}
	u, err := s.users.ByID(ctx, targetID)
	if err != nil {
		return err
	}
	if err := requireLocal(u); err != nil {
		return err
	}
	past, err := s.history.Recent(ctx, u.ID, HistoryDepth)
	if err != nil {
		return fmt.Errorf("auth: read password history: %w", err)
	}
	if err := s.checkNewPassword(newPassword, u.PasswordHash, past); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	if err := s.users.SetPasswordHash(ctx, u.ID, hash); err != nil {
		return fmt.Errorf("auth: set password: %w", err)
	}
	if err := s.history.Add(ctx, u.ID, u.PasswordHash); err != nil {
		return fmt.Errorf("auth: record password history: %w", err)
	}
	revoked, err := s.sessions.RevokeAll(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("auth: revoke sessions: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{
			"action":         audit.ActionAdminPasswordReset,
			"target_user_id": u.ID.String(), "sessions_revoked": revoked,
		},
	})
	return nil
}
