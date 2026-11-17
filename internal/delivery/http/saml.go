package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// samlRequestTTL bounds the SSO login round trip (stash → login → issue).
const samlRequestTTL = 10 * time.Minute

// maxSAMLRequestBytes caps a stashed SSO request body. AuthnRequests are a
// few KB; 1 MB leaves headroom without letting a pasted body exhaust memory.
const maxSAMLRequestBytes = 1 << 20

// mountSAML registers the SAML IdP endpoints (TECH_SPEC §6.3). It is a
// no-op when the provider is not wired (unit tests that focus on the
// session API).
func (h *Handlers) mountSAML(r *chi.Mux) {
	if h.saml == nil {
		return
	}
	r.Get("/saml/metadata", h.handleSAMLMetadata)
	r.Get("/saml/sso", h.handleSAMLSSO)
	r.Post("/saml/sso", h.handleSAMLSSO)
	r.Get("/saml/slo", h.handleSAMLSLO)
	r.Post("/saml/slo", h.handleSAMLSLO)
}

// handleSAMLMetadata serves GET /saml/metadata.
func (h *Handlers) handleSAMLMetadata(w http.ResponseWriter, req *http.Request) {
	h.saml.HandleMetadata(w, req)
}

// handleSAMLSSO runs the SSO endpoint: SP-initiated AuthnRequests (Redirect
// or POST binding), IdP-initiated logins via ?sp=<entityID>, and challenge
// replays after the login redirect. Browsers without a session are sent to
// /login with a return target; the request bytes are stashed server-side so
// signature validation replays exactly what the SP sent.
func (h *Handlers) handleSAMLSSO(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	r, authReq, initiated, challenge, ok := h.resolveSSORequest(w, req)
	if !ok {
		return
	}
	user, loggedIn := h.ssoSessionUser(req)
	if !loggedIn {
		// IsPassive must never visibly interact (saml-profiles §4.1.3.4):
		// answer with an error Response instead of a login redirect.
		if authReq.IsPassive {
			h.auditSAML(ctx, authReq.EntityID, nil, clientIP(req),
				domain.ResultFailure, "sso", "passive login without a session")
			h.saml.WriteAuthnError(ctx, w, r,
				domain.SAMLStatusResponder, domain.SAMLStatusNoPassive, "")
			return
		}
		h.stashAndRedirectToLogin(w, req, r, initiated, authReq)
		return
	}
	if authReq.ForceAuthn {
		// ForceAuthn re-authenticates directly: drop the session and make
		// the browser log in again (saml-profiles §4.1.3.4).
		h.destroySession(req)
		h.stashAndRedirectToLogin(w, req, r, initiated, authReq)
		return
	}
	decision, err := h.samlFlow.Evaluate(ctx, user, authReq)
	if err != nil {
		h.auditSAML(ctx, authReq.EntityID, &user.ID, clientIP(req),
			domain.ResultFailure, "sso", trimPrefix(err.Error()))
		h.saml.WriteAuthnError(ctx, w, r,
			domain.SAMLStatusResponder, domain.SAMLStatusRequestDenied, "login denied")
		return
	}
	if err := h.finishSSO(ctx, w, r, initiated, authReq, decision); err != nil {
		h.auditSAML(ctx, authReq.EntityID, &user.ID, clientIP(req),
			domain.ResultFailure, "sso", "issuance failed")
		h.log.Error("saml issuance failed", "sp", authReq.EntityID, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sso failed, restart login from the app"})
		return
	}
	if challenge != "" {
		_ = h.samlRequests.Delete(ctx, challenge)
	}
	h.auditSAML(ctx, authReq.EntityID, &user.ID, clientIP(req),
		domain.ResultSuccess, "sso", "")
}

// resolveSSORequest normalizes the three SSO entry shapes into one
// validated request: a challenge replay, an IdP-initiated ?sp= target, or
// a plain AuthnRequest. It returns the replayable *http.Request for the
// adapter, the parsed request, whether it is IdP-initiated, and the
// consumed challenge ("" for direct requests).
func (h *Handlers) resolveSSORequest(w http.ResponseWriter, req *http.Request) (*http.Request, domain.SAMLAuthnRequest, bool, string, bool) {
	if challenge := req.URL.Query().Get("challenge"); challenge != "" {
		return h.replayStashed(w, req, challenge)
	}
	if req.Method == http.MethodGet {
		if sp := req.URL.Query().Get("sp"); sp != "" {
			authReq, err := h.saml.ParseIdPInitiated(req.Context(), req, sp, req.URL.Query().Get("RelayState"))
			if err != nil {
				h.log.Warn("saml idp-initiated rejected", "sp", sp, "error", err)
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown service provider"})
				return nil, domain.SAMLAuthnRequest{}, false, "", false
			}
			return req, authReq, true, "", true
		}
	}
	r, rawErr := withReplayableBody(req)
	if rawErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sso request too large"})
		return nil, domain.SAMLAuthnRequest{}, false, "", false
	}
	authReq, err := h.saml.ParseAuthnRequest(req.Context(), r)
	if err != nil {
		h.log.Warn("saml authn request rejected", "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid sso request"})
		return nil, domain.SAMLAuthnRequest{}, false, "", false
	}
	return r, authReq, false, "", true
}

// replayStashed rebuilds an SSO request stashed before the login redirect.
// The bytes replay byte-identically (raw query or raw body), so query
// string and SimpleSign signatures still verify.
func (h *Handlers) replayStashed(w http.ResponseWriter, req *http.Request, challenge string) (*http.Request, domain.SAMLAuthnRequest, bool, string, bool) {
	sr, err := h.samlRequests.Get(req.Context(), challenge)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeJSON(w, http.StatusGone, map[string]string{"error": "login request expired, restart login from the app"})
			return nil, domain.SAMLAuthnRequest{}, false, "", false
		}
		h.writeError(w, req, err)
		return nil, domain.SAMLAuthnRequest{}, false, "", false
	}
	var r *http.Request
	if sr.Method == http.MethodPost {
		var bodyErr error
		r, bodyErr = http.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(sr.Target))
		if bodyErr != nil {
			h.writeError(w, req, bodyErr)
			return nil, domain.SAMLAuthnRequest{}, false, "", false
		}
		if sr.ContentType != "" {
			r.Header.Set("Content-Type", sr.ContentType)
		}
	} else {
		var qErr error
		r, qErr = http.NewRequest(http.MethodGet, "/saml/sso?"+sr.Target, nil)
		if qErr != nil {
			h.writeError(w, req, qErr)
			return nil, domain.SAMLAuthnRequest{}, false, "", false
		}
	}
	r.RemoteAddr = req.RemoteAddr
	if sp := r.URL.Query().Get("sp"); sp != "" && !hasSAMLRequest(r) {
		authReq, err := h.saml.ParseIdPInitiated(req.Context(), r, sp, r.URL.Query().Get("RelayState"))
		if err != nil {
			writeJSON(w, http.StatusGone, map[string]string{"error": "login request is no longer valid, restart login from the app"})
			return nil, domain.SAMLAuthnRequest{}, false, "", false
		}
		return r, authReq, true, challenge, true
	}
	authReq, err := h.saml.ParseAuthnRequest(req.Context(), r)
	if err != nil {
		h.log.Warn("saml stashed request no longer valid", "error", err)
		writeJSON(w, http.StatusGone, map[string]string{"error": "login request is no longer valid, restart login from the app"})
		return nil, domain.SAMLAuthnRequest{}, false, "", false
	}
	return r, authReq, false, challenge, true
}

// stashAndRedirectToLogin stores the SSO request and sends the browser to
// the SPA login page with a return target. IdP-initiated logins stash
// only the sp target, never assertion content.
func (h *Handlers) stashAndRedirectToLogin(w http.ResponseWriter, req *http.Request, r *http.Request, initiated bool, authReq domain.SAMLAuthnRequest) {
	challenge, err := newChallenge()
	if err != nil {
		h.log.Error("saml challenge randomness failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	stashed := domain.SAMLRequest{Challenge: challenge, ExpiresAt: time.Now().Add(samlRequestTTL)}
	if initiated {
		v := url.Values{"sp": {authReq.EntityID}}
		if authReq.RelayState != "" {
			v.Set("RelayState", authReq.RelayState)
		}
		stashed.Method, stashed.Target = http.MethodGet, v.Encode()
	} else if r.Method == http.MethodPost {
		stashed.Method, stashed.Target = http.MethodPost, rawBodyOf(r)
		stashed.ContentType = r.Header.Get("Content-Type")
	} else {
		stashed.Method, stashed.Target = http.MethodGet, r.URL.RawQuery
	}
	if err := h.samlRequests.Create(req.Context(), stashed); err != nil {
		h.log.Error("saml request stash failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	http.Redirect(w, req, "/login?next="+url.QueryEscape("/saml/sso?challenge="+challenge), http.StatusFound)
}

// ssoSessionUser resolves the login session for the SSO endpoint: the
// user row (which must still be active) or not-logged-in.
func (h *Handlers) ssoSessionUser(req *http.Request) (domain.User, bool) {
	raw := h.sessions.GetString(req.Context(), SessionUserID)
	id, err := uuid.Parse(raw)
	if err != nil {
		return domain.User{}, false
	}
	u, err := h.users.GetUser(req.Context(), id)
	if err != nil || !u.IsActive {
		return domain.User{}, false
	}
	return u, true
}

// finishSSO issues the signed Response for either SSO shape.
func (h *Handlers) finishSSO(ctx context.Context, w http.ResponseWriter, r *http.Request, initiated bool, authReq domain.SAMLAuthnRequest, decision domain.SAMLDecision) error {
	if initiated {
		return h.saml.FinishIdPInitiated(ctx, w, r, authReq.EntityID, authReq.RelayState, decision)
	}
	return h.saml.FinishAuthnRequest(ctx, w, r, decision)
}

// handleSAMLSLO runs basic single logout (TECH_SPEC §6.3): a LogoutRequest
// destroys the local session and earns a signed LogoutResponse; a bare
// request (IdP-initiated local logout) destroys the session and returns
// home. LogoutResponses (we never send requests) land home too.
func (h *Handlers) handleSAMLSLO(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	r, rawErr := withReplayableBody(req)
	if rawErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "logout request too large"})
		return
	}
	if !hasSAMLRequest(r) {
		h.destroySession(req)
		h.auditSAML(ctx, "", h.sessionUserID(req), clientIP(req),
			domain.ResultSuccess, "slo-local", "")
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}
	logoutReq, err := h.saml.ParseLogoutRequest(ctx, r)
	if err != nil {
		h.log.Warn("saml logout request rejected", "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid logout request"})
		return
	}
	userID := h.sessionUserID(req)
	h.destroySession(req)
	if err := h.saml.FinishLogoutRequest(ctx, w, r); err != nil {
		h.auditSAML(ctx, logoutReq.EntityID, userID, clientIP(req),
			domain.ResultFailure, "slo", "response failed")
		h.log.Error("saml logout response failed", "sp", logoutReq.EntityID, "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "logout failed"})
		return
	}
	h.auditSAML(ctx, logoutReq.EntityID, userID, clientIP(req),
		domain.ResultSuccess, "slo", "")
}

// destroySession drops the session registration and the session itself.
// It is idempotent: logging out twice still proceeds.
func (h *Handlers) destroySession(req *http.Request) {
	if token := h.sessions.Token(req.Context()); token != "" {
		_ = h.registry.Unregister(req.Context(), token)
	}
	_ = h.sessions.Destroy(req.Context())
}

// sessionUserID returns the session user id for audit attribution. A
// missing or broken session yields nil — audit never fails the request.
func (h *Handlers) sessionUserID(req *http.Request) *uuid.UUID {
	id, err := uuid.Parse(h.sessions.GetString(req.Context(), SessionUserID))
	if err != nil {
		return nil
	}
	return &id
}

// withReplayableBody reads a POST body up to the cap and restores it so
// the adapter can parse the live request and the stash can replay the
// exact bytes later. GET requests pass through untouched.
func withReplayableBody(req *http.Request) (*http.Request, error) {
	if req.Method != http.MethodPost {
		return req, nil
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxSAMLRequestBytes+1))
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	if len(raw) > maxSAMLRequestBytes {
		return nil, errors.New("body too large")
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	return req, nil
}

// rawBodyOf returns the current POST body bytes (after withReplayableBody
// restored them) for stashing.
func rawBodyOf(r *http.Request) string {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSAMLRequestBytes+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return string(raw)
}

// hasSAMLRequest reports whether the request carries a SAML protocol
// message (Redirect query or POST form), without consuming the body twice.
func hasSAMLRequest(r *http.Request) bool {
	if r.URL.Query().Get("SAMLRequest") != "" || r.URL.Query().Get("SAMLResponse") != "" {
		return true
	}
	if r.Method != http.MethodPost {
		return false
	}
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/xml") || strings.HasPrefix(ct, "application/soap+xml") {
		return true // SOAP logout message; the adapter parses the body
	}
	_ = r.ParseForm()
	return r.PostForm.Get("SAMLRequest") != "" || r.PostForm.Get("SAMLResponse") != ""
}

// auditSAML records one SSO/SLO outcome (PRD §6.9: every login is logged).
// Like OIDC, audit runs after issuance and failures are logged loudly.
func (h *Handlers) auditSAML(ctx context.Context, entityID string, userID *uuid.UUID, ip, result, action, reason string) {
	detail := map[string]any{"action": action}
	if entityID != "" {
		detail["entity_id"] = entityID
	}
	if reason != "" {
		detail["reason"] = reason
	}
	e := domain.AuditEntry{
		ActorUserID: userID, Method: domain.MethodSAML, Result: result,
		IP: ip, Detail: detail,
	}
	if entityID != "" {
		if sp, err := h.samlSPs.GetByEntityID(ctx, entityID); err == nil {
			appID := sp.ApplicationID
			e.ApplicationID = &appID
		}
	}
	if err := h.audits.Record(ctx, e); err != nil {
		h.log.Error("saml audit record failed", "action", action, "result", result, "error", err)
	}
}
