package http

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// ---------- account: API keys ----------

// apiKeyJSON renders a key for its owner. The hash never leaves the
// server; the plaintext secret is returned only once, by the create
// endpoint.
func apiKeyJSON(k domain.APIKey) map[string]any {
	out := map[string]any{
		"id": k.ID.String(), "name": k.Name, "prefix": k.Prefix,
		"created_with_mfa": k.CreatedWithMFA,
		"created_at":       k.CreatedAt.Format(time.RFC3339),
	}
	var expires, revoked, used any
	if k.ExpiresAt != nil {
		expires = k.ExpiresAt.Format(time.RFC3339)
	}
	if k.RevokedAt != nil {
		revoked = k.RevokedAt.Format(time.RFC3339)
	}
	if k.LastUsedAt != nil {
		used = k.LastUsedAt.Format(time.RFC3339)
	}
	out["expires_at"], out["revoked_at"], out["last_used_at"] = expires, revoked, used
	return out
}

type createAPIKeyRequest struct {
	Name string `json:"name"`
	// ExpiresInDays sets a TTL; omitted means the key never expires.
	ExpiresInDays *int `json:"expires_in_days"`
	// TOTPCode is the re-auth factor, required when the user has MFA and
	// the session's last verification is older than mfaReAuthWindow.
	TOTPCode string `json:"totp_code"`
}

// handleCreateAPIKey mints one personal API key for the session user.
// The secret is returned once and cannot be recovered later. Users with
// MFA step up first (like the password change); admins always have MFA,
// so admin keys are always issued from an MFA-verified session, which is
// what satisfies the admin gate for Bearer requests.
func (h *Handlers) handleCreateAPIKey(w http.ResponseWriter, req *http.Request) {
	var in createAPIKeyRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	u := mustUser(req.Context())
	if !h.limiter.Allow("apikey:user:"+u.ID.String(), APIKeyPerUserLimit, APIKeyPerUserWindow) {
		writeRateLimited(w)
		return
	}
	if h.mfa != nil && !h.checkReAuth(w, req, u, in.TOTPCode, "to create an API key") {
		return
	}
	var expiresAt *time.Time
	if in.ExpiresInDays != nil {
		if *in.ExpiresInDays <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_in_days must be positive"})
			return
		}
		t := time.Now().UTC().AddDate(0, 0, *in.ExpiresInDays)
		expiresAt = &t
	}
	_, withMFA := h.mfaVerifiedAt(req)
	k, secret, err := h.apiKeys.Create(req.Context(), u.ID, in.Name, expiresAt, withMFA)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"api_key": apiKeyJSON(k), "secret": secret})
}

// handleListAPIKeys returns the session user's keys, newest first.
func (h *Handlers) handleListAPIKeys(w http.ResponseWriter, req *http.Request) {
	keys, err := h.apiKeys.List(req.Context(), mustUser(req.Context()).ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, apiKeyJSON(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": out})
}

// handleRevokeAPIKey revokes one of the session user's keys. Unknown ids
// and other owners' ids both answer 404.
func (h *Handlers) handleRevokeAPIKey(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid API key id"})
		return
	}
	if err := h.apiKeys.Revoke(req.Context(), mustUser(req.Context()).ID, id); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
