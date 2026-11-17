package http

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

// Sessions is the session-manager surface handlers need. *scs.SessionManager
// satisfies it in production; tests use a real scs manager on the memory
// store or a stub.
type Sessions interface {
	LoadAndSave(next http.Handler) http.Handler
	Token(ctx context.Context) string
	RenewToken(ctx context.Context) error
	Put(ctx context.Context, key string, val any)
	GetString(ctx context.Context, key string) string
	GetBytes(ctx context.Context, key string) []byte
	Remove(ctx context.Context, key string)
	Destroy(ctx context.Context) error
}

type ctxKey int

const userCtxKey ctxKey = 1

// currentUser returns the authenticated user loaded by requireUser.
func currentUser(ctx context.Context) (domain.User, bool) {
	u, ok := ctx.Value(userCtxKey).(domain.User)
	return u, ok
}

// mustUser returns the authenticated user or panics: requireUser runs
// first on every route that calls it.
func mustUser(ctx context.Context) domain.User {
	u, ok := currentUser(ctx)
	if !ok {
		panic("http: mustUser without requireUser")
	}
	return u
}

// requireUser loads the session user or answers 401. Disabled users lose
// access on the next request (no caching).
func (h *Handlers) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw := h.sessions.GetString(req.Context(), SessionUserID)
		id, err := uuid.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		u, err := h.users.GetUser(req.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if !u.IsActive {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "account disabled"})
			return
		}
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), userCtxKey, u)))
	})
}

// requireAdmin answers 403 unless the session user is an ih_admin member.
// Membership is checked on every request so revocation takes effect
// immediately (TECH_SPEC §5). Admins must also have passed a second
// factor in this session (TECH_SPEC §8: no exceptions); the check is
// skipped only when MFA is unwired (unit tests that predate M5).
func (h *Handlers) requireAdmin(next http.Handler) http.Handler {
	return h.requireUser(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u := mustUser(req.Context())
		member, err := h.groups.IsMember(req.Context(), u.ID, domain.AdminGroup)
		if err != nil {
			h.log.Error("admin check failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if !member {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator access required"})
			return
		}
		if h.mfa != nil && h.sessions.GetString(req.Context(), SessionMFAVerifiedAt) == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":        "multi-factor authentication is required for administrators",
				"mfa_required": true,
			})
			return
		}
		next.ServeHTTP(w, req)
	}))
}

// pendingUser loads the user behind a pending-MFA session (between
// password login and the second step). It returns false when the session
// carries no pending identity.
func (h *Handlers) pendingUser(req *http.Request) (domain.User, bool) {
	raw := h.sessions.GetString(req.Context(), SessionPendingMFAUserID)
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

// mfaVerifiedAt returns when the session passed a second factor.
func (h *Handlers) mfaVerifiedAt(req *http.Request) (time.Time, bool) {
	raw := h.sessions.GetString(req.Context(), SessionMFAVerifiedAt)
	if raw == "" {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

// writeError maps domain/usecase errors to status codes. Messages are
// safe to show: validation and policy errors carry user-facing text,
// while unexpected errors collapse to "internal error" (logged with the
// detail, never with credentials or PII).
func (h *Handlers) writeError(w http.ResponseWriter, req *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, domain.ErrValidation):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": trimPrefix(err.Error())})
	case errors.Is(err, domain.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already exists"})
	case errors.Is(err, domain.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": trimPrefix(err.Error())})
	case errors.Is(err, domain.ErrUnauthorized):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
	case errors.Is(err, usecaseauth.ErrDirectoryUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "directory temporarily unavailable"})
	default:
		h.log.Error("request failed", "method", req.Method, "path", req.URL.Path, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

// writeRateLimited answers 429 with a Retry-After hint. Callers audit
// login-scoped rejections separately so the audit log stays complete.
func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
}

// trimPrefix strips the "validation failed: " / "forbidden: " sentinel
// prefixes so API clients see the human sentence.
func trimPrefix(msg string) string {
	for _, p := range []string{"validation failed: ", "forbidden: "} {
		if len(msg) > len(p) && msg[:len(p)] == p {
			return msg[len(p):]
		}
	}
	return msg
}
