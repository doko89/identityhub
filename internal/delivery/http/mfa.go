package http

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// ---------- second login step (TECH_SPEC §6.1) ----------

type verifyTOTPRequest struct {
	Code         string `json:"code"`
	RecoveryCode string `json:"recovery_code"`
}

// handleVerifyTOTP completes a pending password login or steps up a full
// session. Exactly one of code/recovery_code must be set. Attempts are
// rate limited (5/min/user) with progressive lockout (TECH_SPEC §8);
// failures are audited by the usecase, rate-limited attempts here so the
// log stays complete.
func (h *Handlers) handleVerifyTOTP(w http.ResponseWriter, req *http.Request) {
	var in verifyTOTPRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	code := strings.TrimSpace(in.Code)
	recovery := strings.TrimSpace(in.RecoveryCode)
	if (code == "") == (recovery == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "exactly one of code or recovery_code is required"})
		return
	}
	u, pending, ok := h.mfaSubject(req)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	lockKey := "totp:lock:" + u.ID.String()
	if locked, _ := h.limiter.Locked(lockKey); locked {
		h.auditMFARateLimited(req, u)
		h.log.Warn("mfa locked out", "ip", clientIP(req))
		writeRateLimited(w)
		return
	}
	if !h.limiter.Allow("totp:user:"+u.ID.String(), TOTPPerUserLimit, TOTPPerUserWindow) {
		h.auditMFARateLimited(req, u)
		writeRateLimited(w)
		return
	}
	var err error
	if code != "" {
		err = h.mfa.Verify(req.Context(), u.ID, code, clientIP(req))
	} else {
		err = h.mfa.VerifyRecovery(req.Context(), u.ID, recovery, clientIP(req))
	}
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			h.limiter.NoteFailure(lockKey)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
			return
		}
		h.writeError(w, req, err)
		return
	}
	h.limiter.Reset(lockKey)
	if !pending {
		// Step-up on a full session: stamp the verification time.
		h.sessions.Put(req.Context(), SessionMFAVerifiedAt, time.Now().UTC().Format(time.RFC3339Nano))
		writeJSON(w, http.StatusOK, map[string]any{"verified": true})
		return
	}
	h.completeMFALogin(w, req, u)
}

// mfaSubject resolves the verify/enroll caller: a full session user
// (step-up, opt-in enroll) or a pending-MFA user (login second step,
// setup). It reports which one via pending.
func (h *Handlers) mfaSubject(req *http.Request) (domain.User, bool, bool) {
	if raw := h.sessions.GetString(req.Context(), SessionUserID); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			if u, err := h.users.GetUser(req.Context(), id); err == nil && u.IsActive {
				return u, false, true
			}
		}
	}
	if u, ok := h.pendingUser(req); ok {
		return u, true, true
	}
	return domain.User{}, false, false
}

// completeMFALogin promotes a pending session to a full login: the id
// rotates against fixation, the pending marker dies, and the identity +
// factor time + auth time bind. Auth time stamps the completed login
// (after MFA), which is what SAML ForceAuthn freshness compares.
func (h *Handlers) completeMFALogin(w http.ResponseWriter, req *http.Request, u domain.User) {
	if err := h.sessions.RenewToken(req.Context()); err != nil {
		h.writeError(w, req, err)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	h.sessions.Remove(req.Context(), SessionPendingMFAUserID)
	h.sessions.Remove(req.Context(), SessionPendingMFASeed)
	h.sessions.Put(req.Context(), SessionUserID, u.ID.String())
	h.sessions.Put(req.Context(), SessionMFAVerifiedAt, now)
	h.sessions.Put(req.Context(), SessionAuthTime, now)
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

// auditMFARateLimited records a throttled second-step attempt. Failures
// fail the request (fail-closed) like any other login audit.
func (h *Handlers) auditMFARateLimited(req *http.Request, u domain.User) {
	_ = h.audits.Record(req.Context(), domain.AuditEntry{
		ActorUserID: &u.ID, Method: domain.MethodTOTP, Result: domain.ResultFailure,
		IP: clientIP(req), Detail: map[string]any{"reason": "rate limited"},
	})
}

// ---------- self-service factors (/api/account/mfa/*) ----------

// handleMFAStatus reports the session user's factor state.
func (h *Handlers) handleMFAStatus(w http.ResponseWriter, req *http.Request) {
	u := mustUser(req.Context())
	st, err := h.mfa.Status(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"has_totp": st.HasTOTP, "remaining_recovery_codes": st.RemainingRecoveryCodes,
	})
}

// handleMFAEnroll starts enrollment: the sealed seed waits in the
// server-side session until confirm, while the QR + URL + secret go to
// the client exactly once (TECH_SPEC §8). Pending-setup sessions (admin
// first login) may enroll as well as full sessions.
func (h *Handlers) handleMFAEnroll(w http.ResponseWriter, req *http.Request) {
	u, _, ok := h.mfaSubject(req)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if !h.limiter.Allow("totp:user:"+u.ID.String(), TOTPPerUserLimit, TOTPPerUserWindow) {
		writeRateLimited(w)
		return
	}
	ch, err := h.mfa.EnrollStart(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	sealed, err := h.sealer.Seal(ch.Seed)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	h.sessions.Put(req.Context(), SessionPendingMFASeed, sealed)
	writeJSON(w, http.StatusOK, map[string]any{
		"otpauth_url": ch.OTPAuthURL,
		"secret":      ch.Secret,
		"qr_png":      "data:image/png;base64," + base64.StdEncoding.EncodeToString(ch.QRCodePNG),
	})
}

type enrollConfirmRequest struct {
	Code string `json:"code"`
}

// handleMFAEnrollConfirm verifies the first code, stores the credential,
// and returns the recovery set (shown once, never logged). A pending
// session promotes to a full login; a full session stamps a fresh
// verification time.
func (h *Handlers) handleMFAEnrollConfirm(w http.ResponseWriter, req *http.Request) {
	var in enrollConfirmRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	u, pending, ok := h.mfaSubject(req)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	lockKey := "totp:lock:" + u.ID.String()
	if locked, _ := h.limiter.Locked(lockKey); locked {
		writeRateLimited(w)
		return
	}
	if !h.limiter.Allow("totp:user:"+u.ID.String(), TOTPPerUserLimit, TOTPPerUserWindow) {
		writeRateLimited(w)
		return
	}
	sealed := h.sessions.GetBytes(req.Context(), SessionPendingMFASeed)
	if len(sealed) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enrollment expired; start again"})
		return
	}
	seed, err := h.sealer.Open(sealed)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	codes, err := h.mfa.EnrollConfirm(req.Context(), u.ID, seed, strings.TrimSpace(in.Code))
	if err != nil {
		if errors.Is(err, domain.ErrValidation) {
			h.limiter.NoteFailure(lockKey)
		}
		h.writeError(w, req, err)
		return
	}
	h.limiter.Reset(lockKey)
	h.sessions.Remove(req.Context(), SessionPendingMFASeed)
	if !pending {
		h.sessions.Put(req.Context(), SessionMFAVerifiedAt, time.Now().UTC().Format(time.RFC3339Nano))
		writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
		return
	}
	// Pending setup (e.g. first admin login): enroll doubles as the
	// login's second step, so promote — but keep the recovery codes in
	// the response, they are shown exactly once.
	if err := h.sessions.RenewToken(req.Context()); err != nil {
		h.writeError(w, req, err)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	h.sessions.Remove(req.Context(), SessionPendingMFAUserID)
	h.sessions.Put(req.Context(), SessionUserID, u.ID.String())
	h.sessions.Put(req.Context(), SessionMFAVerifiedAt, now)
	h.sessions.Put(req.Context(), SessionAuthTime, now)
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
		"recovery_codes": codes,
	})
}

type factorRequest struct {
	Code string `json:"code"`
}

// handleMFADisable removes the session user's own factors after re-auth
// with the old factor.
func (h *Handlers) handleMFADisable(w http.ResponseWriter, req *http.Request) {
	var in factorRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	u := mustUser(req.Context())
	if !h.limiter.Allow("totp:user:"+u.ID.String(), TOTPPerUserLimit, TOTPPerUserWindow) {
		writeRateLimited(w)
		return
	}
	if err := h.mfa.DisableSelf(req.Context(), u.ID, strings.TrimSpace(in.Code)); err != nil {
		h.writeError(w, req, err)
		return
	}
	h.sessions.Remove(req.Context(), SessionMFAVerifiedAt)
	w.WriteHeader(http.StatusNoContent)
}

// handleMFARegenerateRecovery swaps the recovery set after re-auth and
// returns the fresh codes (shown once, never logged).
func (h *Handlers) handleMFARegenerateRecovery(w http.ResponseWriter, req *http.Request) {
	var in factorRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	u := mustUser(req.Context())
	if !h.limiter.Allow("totp:user:"+u.ID.String(), TOTPPerUserLimit, TOTPPerUserWindow) {
		writeRateLimited(w)
		return
	}
	codes, err := h.mfa.RegenerateRecovery(req.Context(), u.ID, strings.TrimSpace(in.Code))
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleAdminMFAReset clears a user's factors without the old factor
// (the MFA-loss flow, PRD §10). The acting admin is audited.
func (h *Handlers) handleAdminMFAReset(w http.ResponseWriter, req *http.Request) {
	actor := mustUser(req.Context())
	targetID, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	if err := h.mfa.AdminReset(req.Context(), actor.ID, targetID); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// checkPasswordChangeMFA enforces PRD §6.10 re-auth for password changes.
func (h *Handlers) checkPasswordChangeMFA(w http.ResponseWriter, req *http.Request, u domain.User, code string) bool {
	return h.checkReAuth(w, req, u, code, "to change the password")
}

// checkReAuth enforces step-up re-auth for sensitive self-service actions
// (password change, API key issuance): users with MFA need a verification
// within mfaReAuthWindow or a fresh code with the request. action names
// the guarded operation in the failure message. It answers the failure
// itself and reports whether to proceed.
func (h *Handlers) checkReAuth(w http.ResponseWriter, req *http.Request, u domain.User, code, action string) bool {
	has, err := h.mfa.HasTOTP(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return false
	}
	if !has {
		return true
	}
	if at, ok := h.mfaVerifiedAt(req); ok && time.Since(at) < mfaReAuthWindow {
		return true
	}
	if strings.TrimSpace(code) == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":        "recent second-factor verification is required " + action,
			"mfa_required": true,
		})
		return false
	}
	if !h.limiter.Allow("totp:user:"+u.ID.String(), TOTPPerUserLimit, TOTPPerUserWindow) {
		writeRateLimited(w)
		return false
	}
	if err := h.mfa.ReAuth(req.Context(), u.ID, strings.TrimSpace(code)); err != nil {
		h.writeError(w, req, err)
		return false
	}
	h.sessions.Put(req.Context(), SessionMFAVerifiedAt, time.Now().UTC().Format(time.RFC3339Nano))
	return true
}
