// Package http is the HTTP delivery layer: chi router, JSON API handlers,
// middleware, and the embedded SPA build (TECH_SPEC §4, §6.1).
package http

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session keys stored in the scs session. Later milestones (M1/M5) read and
// write these; they are declared here so delivery and usecase share names.
const (
	// SessionUserID holds the authenticated user's UUID string.
	SessionUserID = "user_id"
	// SessionMFAVerifiedAt holds the RFC3339 time the second factor passed.
	SessionMFAVerifiedAt = "mfa_verified_at"
	// SessionPendingMFAUserID holds the user id between step-up steps.
	SessionPendingMFAUserID = "pending_mfa_user_id"
	// SessionPendingMFASeed holds the sealed TOTP seed between enroll
	// start and confirm. Sessions are server-side (Postgres), so the
	// seed never touches the client.
	SessionPendingMFASeed = "pending_mfa_seed"
	// SessionAuthTime holds the RFC3339Nano time the password login
	// completed. SAML ForceAuthn compares it against the stashed request's
	// creation time to prove the login is fresh (saml-profiles §4.1.3.4).
	SessionAuthTime = "auth_time"
)

// SessionConfig carries the cookie/timeout decisions from internal/config.
type SessionConfig struct {
	IdleTimeout time.Duration
	Lifetime    time.Duration
	Secure      bool
}

// NewSessionManager builds the scs manager on the pgx session store with
// TECH_SPEC §8 cookie rules: HttpOnly + Secure (production) + SameSite=Lax.
//
// The cookie persists (Expires/Max-Age set, refreshed on every request
// to min(deadline, now+idle)): a browser-close must not log the user
// out while the server-side session is still within idle/lifetime.
func NewSessionManager(pool *pgxpool.Pool, cfg SessionConfig) *scs.SessionManager {
	sm := scs.New()
	sm.Store = pgxstore.New(pool)
	sm.Lifetime = cfg.Lifetime
	sm.IdleTimeout = cfg.IdleTimeout
	sm.Cookie.Name = "identityhub_session"
	sm.Cookie.HttpOnly = true
	sm.Cookie.Secure = cfg.Secure
	sm.Cookie.SameSite = http.SameSiteLaxMode
	sm.Cookie.Persist = true
	sm.Cookie.Path = "/"
	return sm
}
