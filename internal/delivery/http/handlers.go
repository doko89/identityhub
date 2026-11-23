package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/metrics"
	usecaseapikey "github.com/identityhub/identityhub/internal/usecase/apikey"
	usecaseapp "github.com/identityhub/identityhub/internal/usecase/app"
	usecaseasset "github.com/identityhub/identityhub/internal/usecase/asset"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
	usecasebranding "github.com/identityhub/identityhub/internal/usecase/branding"
	usecasemfa "github.com/identityhub/identityhub/internal/usecase/mfa"
	usecaseoidcflow "github.com/identityhub/identityhub/internal/usecase/oidcflow"
	usecasesamlflow "github.com/identityhub/identityhub/internal/usecase/samlflow"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
)

// Handlers serves the JSON API (TECH_SPEC §6.1). It translates HTTP into
// usecase calls; all policy lives in the usecases.
type Handlers struct {
	sessions Sessions
	registry domain.SessionRegistry
	auth     *usecaseauth.Service
	users    *usecaseuser.Service
	audits   *usecaseaudit.Service
	groups   domain.GroupStore
	dir      domain.Directory // nil when the LDAP upstream is disabled
	limiter  *Limiter
	log      *slog.Logger
	// OIDC provider wiring (TECH_SPEC §6.2). Nil in unit tests that
	// focus on the session API; mountOIDC skips registration then.
	oidc        domain.OIDCProvider
	oidcFlow    *usecaseoidcflow.Service
	challenges  domain.OIDCConsentChallengeStore
	oidcClients domain.OIDCClientStore
	// SAML IdP wiring (TECH_SPEC §6.3). Nil in unit tests that do not
	// cover the SAML endpoints; mountSAML skips registration then.
	saml         domain.SAMLProvider
	samlFlow     *usecasesamlflow.Service
	samlRequests domain.SAMLRequestStore
	samlSPs      domain.SAMLSPStore
	// MFA + app catalog + assets (TECH_SPEC §6.1, §6.7). Nil in unit
	// tests that predate M5/M6; the MFA login step, the admin MFA gate
	// and the new routes are skipped then.
	mfa     *usecasemfa.Service
	apps    *usecaseapp.Service
	assets  *usecaseasset.Service
	storage domain.FileStorage
	sealer  domain.SeedSealer
	// Branding serves GET /api/branding + the admin update (TECH_SPEC
	// §7). Nil in unit tests that predate M7; the routes are skipped
	// then.
	branding *usecasebranding.Service
	// Providers registers protocol credentials (OIDC/SAML/RADIUS) for
	// catalog applications. Nil in tests that predate M7 provider
	// registration; the routes are skipped then.
	providers *usecaseapp.ProviderService
	// APIKeys mints and verifies personal CLI keys. Nil in tests that
	// predate API keys; the routes and the Bearer fallback are skipped
	// then.
	apiKeys *usecaseapikey.Service
}

// HandlerDeps wires Handlers. Directory may be nil; everything else is
// required.
type HandlerDeps struct {
	Sessions Sessions
	Registry domain.SessionRegistry
	Auth     *usecaseauth.Service
	Users    *usecaseuser.Service
	Audits   *usecaseaudit.Service
	Groups   domain.GroupStore
	// Directory is nil when LDAP_URL is unset (LDAP test reports disabled).
	Directory domain.Directory
	Limiter   *Limiter
	Log       *slog.Logger
	// OIDC is nil in tests that do not cover the provider endpoints.
	OIDC        domain.OIDCProvider
	OIDCFlow    *usecaseoidcflow.Service
	Challenges  domain.OIDCConsentChallengeStore
	OIDCClients domain.OIDCClientStore
	// SAML is nil in tests that do not cover the SAML endpoints.
	SAML         domain.SAMLProvider
	SAMLFlow     *usecasesamlflow.Service
	SAMLRequests domain.SAMLRequestStore
	SAMLSPs      domain.SAMLSPStore
	// MFA/Apps/Assets/Storage are nil in tests that do not cover the
	// M5/M6 endpoints.
	MFA     *usecasemfa.Service
	Apps    *usecaseapp.Service
	Assets  *usecaseasset.Service
	Storage domain.FileStorage
	// Sealer guards pending enroll seeds in the session; required
	// whenever MFA is wired.
	Sealer domain.SeedSealer
	// Branding is nil in tests that do not cover the theme endpoints.
	Branding *usecasebranding.Service
	// Providers is nil in tests that do not cover provider registration.
	Providers *usecaseapp.ProviderService
	// APIKeys is nil in tests that do not cover personal API keys.
	APIKeys *usecaseapikey.Service
}

// NewHandlers builds the API handlers.
func NewHandlers(d HandlerDeps) *Handlers {
	if d.Limiter == nil {
		d.Limiter = NewLimiter()
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Handlers{
		sessions: d.Sessions, registry: d.Registry, auth: d.Auth, users: d.Users,
		audits: d.Audits, groups: d.Groups, dir: d.Directory,
		limiter: d.Limiter, log: d.Log,
		oidc: d.OIDC, oidcFlow: d.OIDCFlow, challenges: d.Challenges, oidcClients: d.OIDCClients,
		saml: d.SAML, samlFlow: d.SAMLFlow, samlRequests: d.SAMLRequests, samlSPs: d.SAMLSPs,
		mfa: d.MFA, apps: d.Apps, assets: d.Assets, storage: d.Storage,
		sealer: d.Sealer, branding: d.Branding, providers: d.Providers,
		apiKeys: d.APIKeys,
	}
}

// maxBodyBytes caps JSON request bodies (auth payloads are tiny).
const maxBodyBytes = 1 << 20

func decodeJSON(w http.ResponseWriter, req *http.Request, v any) bool {
	defer req.Body.Close()
	dec := json.NewDecoder(io.LimitReader(req.Body, maxBodyBytes))
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

// clientIP returns the caller IP without the port. The RealIP middleware
// resolves proxy headers before handlers run.
func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// userJSON is the safe public rendering of a user (never the hash).
func userJSON(u domain.User, groups []string, isAdmin bool) map[string]any {
	return map[string]any{
		"id": u.ID.String(), "username": u.Username, "email": u.Email,
		"display_name": u.DisplayName, "source": string(u.Source),
		"is_active": u.IsActive, "avatar_url": u.AvatarURL,
		"groups": groups, "is_admin": isAdmin,
	}
}

func groupNames(groups []domain.Group) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.Name)
	}
	return out
}

// ---------- session API ----------

type loginRequest struct {
	Username string `json:"username"` // username or email
	Password string `json:"password"`
}

// handleLogin verifies credentials, opens a session, and registers it.
// Rate limits (TECH_SPEC §8): 10/min/IP, 5/min/username, plus progressive
// lockout per username. Rejected attempts are audited like any login.
func (h *Handlers) handleLogin(w http.ResponseWriter, req *http.Request) {
	var in loginRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	ip := clientIP(req)
	username := strings.TrimSpace(in.Username)
	userKey := "login:user:" + strings.ToLower(username)

	if locked, wait := h.limiter.Locked("login:lock:" + strings.ToLower(username)); locked {
		if err := h.auditRateLimited(req.Context(), ip, username); err != nil {
			h.writeError(w, req, err)
			return
		}
		h.log.Warn("login locked out", "ip", ip, "retry_in", wait.String())
		metrics.ObserveAuthFailure(domain.MethodPassword, metrics.AppGlobal)
		writeRateLimited(w)
		return
	}
	if !h.limiter.Allow("login:ip:"+ip, LoginPerIPLimit, LoginPerIPWindow) ||
		!h.limiter.Allow(userKey, LoginPerUserLimit, LoginPerUserWindow) {
		if err := h.auditRateLimited(req.Context(), ip, username); err != nil {
			h.writeError(w, req, err)
			return
		}
		metrics.ObserveAuthFailure(domain.MethodPassword, metrics.AppGlobal)
		writeRateLimited(w)
		return
	}

	u, err := h.auth.Login(req.Context(), usecaseauth.LoginInput{Username: username, Password: in.Password, IP: ip})
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			h.limiter.NoteFailure("login:lock:" + strings.ToLower(username))
		}
		metrics.ObserveAuthFailure(domain.MethodPassword, metrics.AppGlobal)
		h.writeError(w, req, err)
		return
	}
	h.limiter.Reset("login:lock:" + strings.ToLower(username))

	// Second step: admins always, enrolled users by opt-in (PRD §6.6).
	// The password login already audited; the pending session carries
	// no identity until the factor verifies.
	if h.mfa != nil {
		required, enrolled, err := h.mfa.RequiredForLogin(req.Context(), u.ID)
		if err != nil {
			h.writeError(w, req, err)
			return
		}
		if required {
			if err := h.sessions.RenewToken(req.Context()); err != nil {
				h.writeError(w, req, err)
				return
			}
			h.sessions.Put(req.Context(), SessionPendingMFAUserID, u.ID.String())
			writeJSON(w, http.StatusOK, map[string]any{
				"mfa_required": true, "setup_required": !enrolled,
				"user": map[string]any{"id": u.ID.String(), "username": u.Username},
			})
			return
		}
	}

	// Renew the session id to prevent fixation, then bind the identity.
	if err := h.sessions.RenewToken(req.Context()); err != nil {
		h.writeError(w, req, err)
		return
	}
	h.sessions.Put(req.Context(), SessionUserID, u.ID.String())
	h.sessions.Put(req.Context(), SessionAuthTime, time.Now().UTC().Format(time.RFC3339Nano))
	if err := h.registry.Register(req.Context(), u.ID, h.sessions.Token(req.Context())); err != nil {
		h.writeError(w, req, err)
		return
	}
	groups, err := h.groups.GroupsOfUser(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	isAdmin, err := h.groups.IsMember(req.Context(), u.ID, domain.AdminGroup)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mfa_required": false, "user": userJSON(u, groupNames(groups), isAdmin),
	})
}

// auditRateLimited records a rate-limited login attempt so the audit log
// stays complete. The entry carries no actor id (the attempt never
// authenticated); the attempted username rides in detail. A failed write
// fails the request (fail-closed) like any other login audit.
func (h *Handlers) auditRateLimited(ctx context.Context, ip, username string) error {
	return h.audits.Record(ctx, domain.AuditEntry{
		Method: domain.MethodPassword, Result: domain.ResultFailure, IP: ip,
		Detail: map[string]any{"reason": "rate limited", "username": username},
	})
}

// handleLogout drops the session registration and destroys the session.
// It is idempotent: logging out twice still answers 204.
func (h *Handlers) handleLogout(w http.ResponseWriter, req *http.Request) {
	token := h.sessions.Token(req.Context())
	if token != "" {
		_ = h.registry.Unregister(req.Context(), token)
	}
	_ = h.sessions.Destroy(req.Context())
	w.WriteHeader(http.StatusNoContent)
}

// handleMe returns the session user with groups and the admin flag.
func (h *Handlers) handleMe(w http.ResponseWriter, req *http.Request) {
	u := mustUser(req.Context())
	groups, err := h.groups.GroupsOfUser(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	isAdmin, err := h.groups.IsMember(req.Context(), u.ID, domain.AdminGroup)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(u, groupNames(groups), isAdmin)})
}

// ---------- password management (PRD §6.10, local users only) ----------

type changePasswordRequest struct {
	CurrentPassword    string `json:"current_password"`
	NewPassword        string `json:"new_password"`
	NewPasswordConfirm string `json:"new_password_confirm"`
	// TOTPCurrent is the re-auth factor, required when the user has MFA
	// and the session's last verification is older than mfaReAuthWindow.
	TOTPCurrent string `json:"totp_code"`
}

// mfaReAuthWindow is how fresh the session's second-factor verification
// must be to change the password without presenting a new code
// (PRD §6.10: MFA re-auth required when MFA is active).
const mfaReAuthWindow = 10 * time.Minute

// handleChangePassword changes the session user's own password. Users
// with MFA must have verified a factor within mfaReAuthWindow or present
// a fresh code with the request.
func (h *Handlers) handleChangePassword(w http.ResponseWriter, req *http.Request) {
	var in changePasswordRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	u := mustUser(req.Context())
	if !h.limiter.Allow("change:user:"+u.ID.String(), ChangePerUserLimit, ChangePerUserWindow) {
		writeRateLimited(w)
		return
	}
	if h.mfa != nil && !h.checkPasswordChangeMFA(w, req, u, in.TOTPCurrent) {
		return
	}
	revoked, err := h.auth.ChangePassword(req.Context(), u.ID, in.CurrentPassword, in.NewPassword, in.NewPasswordConfirm, h.sessions.Token(req.Context()))
	if err != nil {
		// The generic unauthorized message names the wrong credential
		// here; the current password is what failed.
		if errors.Is(err, domain.ErrUnauthorized) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
			return
		}
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions_revoked": revoked})
}

type updateAccountAvatarRequest struct {
	AvatarURL string `json:"avatar_url"`
}

// handleUpdateAccountAvatar attaches an uploaded image as the session
// user's own avatar. Only server-issued /uploads/ URLs are accepted:
// arbitrary URLs would turn every avatar <img> into an SSRF/tracking
// vector; the admin console stays the only place that may set other
// values.
func (h *Handlers) handleUpdateAccountAvatar(w http.ResponseWriter, req *http.Request) {
	var in updateAccountAvatarRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	if !validSelfAvatarURL(in.AvatarURL) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "avatar_url must be an /uploads/ image URL"})
		return
	}
	u := mustUser(req.Context())
	updated, err := h.users.UpdateProfile(req.Context(), u.ID, u.DisplayName, u.Email, in.AvatarURL)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	groups, err := h.groups.GroupsOfUser(req.Context(), updated.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	isAdmin, err := h.groups.IsMember(req.Context(), updated.ID, domain.AdminGroup)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(updated, groupNames(groups), isAdmin)})
}

// validSelfAvatarURL accepts only relative /uploads/ paths produced by
// POST /api/uploads: no scheme, host, parent traversal or whitespace.
func validSelfAvatarURL(s string) bool {
	if s == "" || len(s) > 512 || !strings.HasPrefix(s, "/uploads/") || len(s) <= len("/uploads/") {
		return false
	}
	if strings.Contains(s, "..") || strings.Contains(s, "://") || strings.Contains(s, "\\") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

type forgotPasswordRequest struct {
	Login string `json:"login"` // username or email
}

// handleForgotPassword always answers the same generic message so
// account existence is never leaked (TECH_SPEC §8). Infrastructure
// failures are logged (without the identifier) and still answer
// generically.
func (h *Handlers) handleForgotPassword(w http.ResponseWriter, req *http.Request) {
	var in forgotPasswordRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	ip := clientIP(req)
	key := strings.ToLower(strings.TrimSpace(in.Login))
	if !h.limiter.Allow("forgot:login:"+key, ForgotPerLoginLimit, ForgotPerLoginWindow) ||
		!h.limiter.Allow("forgot:ip:"+ip, ForgotPerIPLimit, ForgotPerIPWindow) {
		writeRateLimited(w)
		return
	}
	if err := h.auth.ForgotPassword(req.Context(), in.Login, ip); err != nil {
		h.log.Error("forgot-password failed", "ip", ip, "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "If an account exists for that username or email, a reset link is on its way.",
	})
}

type resetPasswordRequest struct {
	Token              string `json:"token"`
	NewPassword        string `json:"new_password"`
	NewPasswordConfirm string `json:"new_password_confirm"`
}

// handleResetPassword redeems a forgot-password token.
func (h *Handlers) handleResetPassword(w http.ResponseWriter, req *http.Request) {
	var in resetPasswordRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	if !h.limiter.Allow("reset:ip:"+clientIP(req), ResetPerIPLimit, ResetPerIPWindow) {
		writeRateLimited(w)
		return
	}
	if err := h.auth.ResetPassword(req.Context(), in.Token, in.NewPassword, in.NewPasswordConfirm); err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Password has been reset. You can now sign in."})
}

type adminSetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// handleAdminSetPassword lets an admin set a local user's password.
// LDAP targets are rejected explicitly by the usecase.
func (h *Handlers) handleAdminSetPassword(w http.ResponseWriter, req *http.Request) {
	var in adminSetPasswordRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	actor := mustUser(req.Context())
	targetID, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	if err := h.auth.AdminSetPassword(req.Context(), actor.ID, targetID, in.NewPassword); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminInviteUser emails a password-setup link to a provisioned
// local user (HRIS invite flow). Unlike the public forgot-password
// endpoint it carries no rate limit: the admin gate plus the audit
// entry are the abuse control.
func (h *Handlers) handleAdminInviteUser(w http.ResponseWriter, req *http.Request) {
	actor := mustUser(req.Context())
	targetID, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	if err := h.auth.InviteUser(req.Context(), actor.ID, targetID, clientIP(req)); err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invitation sent."})
}
