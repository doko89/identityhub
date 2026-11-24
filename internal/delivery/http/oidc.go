package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// consentChallengeTTL bounds the consent-page round trip.
const consentChallengeTTL = 10 * time.Minute

// mountOIDC registers the OIDC provider endpoints (TECH_SPEC §6.2) plus
// the consent API backing the SPA consent page. It is a no-op when the
// provider is not wired (unit tests that focus on the session API).
func (h *Handlers) mountOIDC(r *chi.Mux) {
	if h.oidc == nil {
		return
	}
	r.Get("/oauth2/auth", h.handleAuthorize)
	r.Post("/oauth2/token", h.handleToken)
	r.Get("/oauth2/userinfo", h.handleUserinfo)
	r.Get("/.well-known/openid-configuration", h.handleDiscovery)
	r.Get("/oauth2/jwks", h.handleJWKS)
	r.With(h.requireUser).Get("/api/oidc/consent", h.handleConsentGet)
	r.With(h.requireUser).Post("/api/oidc/consent", h.handleConsentPost)
}

// handleAuthorize runs the authorization endpoint: parse the request,
// require a login session (redirecting to /login with a return target),
// evaluate scopes and consent, then either issue the code or redirect to
// the consent page.
func (h *Handlers) handleAuthorize(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	authReq, err := h.oidc.ParseAuthorizeRequest(ctx, req)
	if err != nil {
		h.oidc.WriteAuthorizeError(ctx, w, req, err)
		return
	}
	user, ok := h.authorizeUser(w, req)
	if !ok {
		return
	}
	outcome, err := h.oidcFlow.Evaluate(ctx, user, authReq)
	if err != nil {
		h.auditOIDC(ctx, authReq.ClientID, &user.ID, clientIP(req),
			domain.ResultFailure, "authorize", err.Error())
		h.oidc.WriteAuthorizeError(ctx, w, req, err)
		return
	}
	if !outcome.NeedConsent {
		if err := h.oidc.FinishAuthorizeRequest(ctx, w, req, outcome.Decision); err != nil {
			h.auditOIDC(ctx, authReq.ClientID, &user.ID, clientIP(req),
				domain.ResultFailure, "authorize", "issuance failed")
			return
		}
		h.auditOIDC(ctx, authReq.ClientID, &user.ID, clientIP(req),
			domain.ResultSuccess, "authorize", "")
		return
	}
	challenge, err := newChallenge()
	if err != nil {
		h.log.Error("consent challenge randomness failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := h.challenges.Create(ctx, domain.OIDCConsentChallenge{
		Challenge: challenge, UserID: user.ID, ClientID: authReq.ClientID,
		Query: req.URL.RawQuery, ExpiresAt: time.Now().Add(consentChallengeTTL),
	}); err != nil {
		h.log.Error("consent challenge store failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	http.Redirect(w, req, "/consent?challenge="+challenge, http.StatusFound)
}

// authorizeUser resolves the login session for the authorize endpoint.
// Browsers without a session (or with a disabled account) are sent to
// the login page with a return target back to this exact request.
func (h *Handlers) authorizeUser(w http.ResponseWriter, req *http.Request) (domain.User, bool) {
	raw := h.sessions.GetString(req.Context(), SessionUserID)
	id, err := uuid.Parse(raw)
	if err != nil {
		h.redirectToLogin(w, req)
		return domain.User{}, false
	}
	u, err := h.users.GetUser(req.Context(), id)
	if err != nil || !u.IsActive {
		h.redirectToLogin(w, req)
		return domain.User{}, false
	}
	return u, true
}

// redirectToLogin sends the browser to the SPA login page, preserving
// this authorize request as a relative return target.
func (h *Handlers) redirectToLogin(w http.ResponseWriter, req *http.Request) {
	next := "/oauth2/auth?" + req.URL.RawQuery
	http.Redirect(w, req, "/login?next="+url.QueryEscape(next), http.StatusFound)
}

// handleToken serves POST /oauth2/token (code exchange + refresh).
func (h *Handlers) handleToken(w http.ResponseWriter, req *http.Request) {
	h.oidc.HandleToken(req.Context(), w, req)
}

// handleUserinfo serves GET /oauth2/userinfo.
func (h *Handlers) handleUserinfo(w http.ResponseWriter, req *http.Request) {
	h.oidc.HandleUserinfo(req.Context(), w, req)
}

// handleDiscovery serves GET /.well-known/openid-configuration.
func (h *Handlers) handleDiscovery(w http.ResponseWriter, req *http.Request) {
	h.oidc.HandleDiscovery(w, req)
}

// handleJWKS serves GET /oauth2/jwks.
func (h *Handlers) handleJWKS(w http.ResponseWriter, req *http.Request) {
	h.oidc.HandleJWKS(w, req)
}

// handleConsentGet renders the pending authorize request for the SPA
// consent page. The stored raw query is re-parsed, so a client deleted
// after the challenge surfaces here instead of issuing a code.
func (h *Handlers) handleConsentGet(w http.ResponseWriter, req *http.Request) {
	u := mustUser(req.Context())
	ch, ok := h.loadChallenge(w, req, u.ID, req.URL.Query().Get("challenge"))
	if !ok {
		return
	}
	authReq, err := h.oidc.ParseAuthorizeRequest(req.Context(), rebuildAuthorize(ch.Query))
	if err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "authorization request is no longer valid"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":    ch.Challenge,
		"client_id":    authReq.ClientID,
		"client_name":  authReq.ClientName,
		"redirect_uri": authReq.RedirectURI,
		"scopes":       authReq.RequestedScopes,
	})
}

type consentPostRequest struct {
	Challenge string `json:"challenge"`
	Grant     bool   `json:"grant"`
}

// handleConsentPost records the user's decision and completes the
// authorize flow. The challenge is consumed atomically, so double
// submits fail closed. The browser-facing redirect target is returned as
// JSON; the SPA navigates there (a fetch cannot follow a 302 to a
// different origin usefully).
func (h *Handlers) handleConsentPost(w http.ResponseWriter, req *http.Request) {
	u := mustUser(req.Context())
	var in consentPostRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	ch, err := h.challenges.Consume(req.Context(), in.Challenge)
	if err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "consent request expired, restart login from the app"})
		return
	}
	if ch.UserID != u.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "consent request belongs to another session"})
		return
	}
	r2 := rebuildAuthorize(ch.Query)
	if !in.Grant {
		h.auditOIDC(req.Context(), ch.ClientID, &u.ID, clientIP(req),
			domain.ResultFailure, "consent", "denied by user")
		h.captureRedirect(w, req, r2, nil)
		return
	}
	authReq, err := h.oidc.ParseAuthorizeRequest(req.Context(), r2)
	if err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "authorization request is no longer valid"})
		return
	}
	outcome, err := h.oidcFlow.Evaluate(req.Context(), u, authReq)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	if err := h.oidcFlow.GrantConsent(req.Context(), u.ID, ch.ClientID, outcome.Decision.GrantedScopes); err != nil {
		h.writeError(w, req, err)
		return
	}
	h.auditOIDC(req.Context(), ch.ClientID, &u.ID, clientIP(req),
		domain.ResultSuccess, "consent", "")
	h.captureRedirect(w, req, r2, &outcome.Decision)
}

// captureRedirect runs the authorize completion (grant or deny) against a
// recorder and returns the outcome as JSON for the SPA. Redirect modes
// answer the Location to navigate to; form_post renders an auto-submit
// HTML page instead (no Location), which the SPA swaps into the
// document so the browser posts it onward to the client.
func (h *Handlers) captureRedirect(w http.ResponseWriter, req *http.Request, r2 *http.Request, d *domain.OIDCDecision) {
	rec := httptest.NewRecorder()
	if d == nil {
		_ = h.oidc.DenyAuthorizeRequest(req.Context(), rec, r2)
	} else {
		_ = h.oidc.FinishAuthorizeRequest(req.Context(), rec, r2, *d)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		writeJSON(w, http.StatusOK, map[string]string{"redirect_to": loc})
		return
	}
	if rec.Code == http.StatusOK && rec.Body.Len() > 0 {
		writeJSON(w, http.StatusOK, map[string]string{"form_post": rec.Body.String()})
		return
	}
	h.log.Error("oidc completion produced no redirect",
		"client", r2.URL.Query().Get("client_id"), "status", rec.Code)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authorization failed, restart login from the app"})
}

// loadChallenge fetches a live challenge and checks session ownership.
func (h *Handlers) loadChallenge(w http.ResponseWriter, req *http.Request, userID uuid.UUID, challenge string) (domain.OIDCConsentChallenge, bool) {
	if challenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge is required"})
		return domain.OIDCConsentChallenge{}, false
	}
	ch, err := h.challenges.Get(req.Context(), challenge)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeJSON(w, http.StatusGone, map[string]string{"error": "consent request expired, restart login from the app"})
			return domain.OIDCConsentChallenge{}, false
		}
		h.writeError(w, req, err)
		return domain.OIDCConsentChallenge{}, false
	}
	if ch.UserID != userID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "consent request belongs to another session"})
		return domain.OIDCConsentChallenge{}, false
	}
	return ch, true
}

// auditOIDC records one authorize/consent outcome (PRD §6.9: every login
// is logged). Audit failures are logged loudly but do not revoke an
// already-issued code: fosite issues inside its own flow, so issuance and
// audit cannot share a transaction.
func (h *Handlers) auditOIDC(ctx context.Context, clientID string, userID *uuid.UUID, ip, result, action, reason string) {
	e := domain.AuditEntry{
		Method: domain.MethodOIDC, Result: result, IP: ip,
		Detail: map[string]any{"action": action, "client_id": clientID},
	}
	e.ActorUserID = userID
	if c, err := h.oidcClients.GetByClientID(ctx, clientID); err == nil {
		appID := c.ApplicationID
		e.ApplicationID = &appID
	}
	if reason != "" {
		e.Detail["reason"] = reason
	}
	if err := h.audits.Record(ctx, e); err != nil {
		h.log.Error("oidc audit record failed", "action", action, "result", result, "error", err)
	}
}

// rebuildAuthorize reconstructs the authorize GET from the stored raw
// query for re-parsing (never from browser input).
func rebuildAuthorize(rawQuery string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/oauth2/auth?"+rawQuery, nil)
	return r
}

// newChallenge mints a 256-bit opaque challenge.
func newChallenge() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
