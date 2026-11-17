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

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
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
	Username string `json:"username"`
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
		writeRateLimited(w)
		return
	}
	if !h.limiter.Allow("login:ip:"+ip, LoginPerIPLimit, LoginPerIPWindow) ||
		!h.limiter.Allow(userKey, LoginPerUserLimit, LoginPerUserWindow) {
		if err := h.auditRateLimited(req.Context(), ip, username); err != nil {
			h.writeError(w, req, err)
			return
		}
		writeRateLimited(w)
		return
	}

	u, err := h.auth.Login(req.Context(), usecaseauth.LoginInput{Username: username, Password: in.Password, IP: ip})
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			h.limiter.NoteFailure("login:lock:" + strings.ToLower(username))
		}
		h.writeError(w, req, err)
		return
	}
	h.limiter.Reset("login:lock:" + strings.ToLower(username))

	// Renew the session id to prevent fixation, then bind the identity.
	if err := h.sessions.RenewToken(req.Context()); err != nil {
		h.writeError(w, req, err)
		return
	}
	h.sessions.Put(req.Context(), SessionUserID, u.ID.String())
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
	writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(u, groupNames(groups), isAdmin)})
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
}

// handleChangePassword changes the session user's own password. MFA
// re-auth gating arrives with the TOTP milestone (M5); until then the
// active session alone authorizes the change.
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
