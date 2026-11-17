package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Pinger abstracts the readiness check so tests inject a stub.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps wires delivery handlers. main.go is the only construction site.
type Deps struct {
	Sessions Sessions
	DB       Pinger
	// Handlers serves the JSON API. Nil leaves only the probes mounted
	// (used by router tests that focus on health/SPA behavior).
	Handlers *Handlers
}

// NewRouter builds the chi mux: middleware, health probes, API routes, and
// the SPA fallback serving the embedded web/dist build.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(d.Sessions.LoadAndSave)

	r.Get("/healthz", handleHealthz)
	r.Get("/readyz", handleReadyz(d.DB))

	if d.Handlers != nil {
		d.Handlers.mount(r)
	}

	// API surface grows in later milestones; unknown /api/* paths fail as
	// JSON 404 instead of falling through to the SPA.
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if isAPIPath(req.URL.Path) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		serveSPA(w, req)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	})
	return r
}

// mount registers the JSON API (TECH_SPEC §6.1). Auth guards wrap each
// route group: session users for /account, ih_admin members for /admin.
func (h *Handlers) mount(r *chi.Mux) {
	r.Post("/api/auth/login", h.handleLogin)
	r.Post("/api/auth/logout", h.handleLogout)
	r.Post("/api/auth/password/forgot", h.handleForgotPassword)
	r.Post("/api/auth/password/reset", h.handleResetPassword)
	r.With(h.requireUser).Get("/api/auth/me", h.handleMe)
	r.With(h.requireUser).Post("/api/account/password/change", h.handleChangePassword)

	r.Route("/api/admin", func(r chi.Router) {
		r.Use(h.requireAdmin)
		r.Get("/users", h.handleAdminListUsers)
		r.Post("/users", h.handleAdminCreateUser)
		r.Get("/users/{id}", h.handleAdminGetUser)
		r.Patch("/users/{id}", h.handleAdminUpdateUser)
		r.Post("/users/{id}/password", h.handleAdminSetPassword)
		r.Get("/groups", h.handleAdminListGroups)
		r.Post("/groups", h.handleAdminCreateGroup)
		r.Get("/groups/{id}", h.handleAdminGetGroup)
		r.Delete("/groups/{id}", h.handleAdminDeleteGroup)
		r.Post("/groups/{id}/members", h.handleAdminAddMember)
		r.Delete("/groups/{id}/members/{userID}", h.handleAdminRemoveMember)
		r.Get("/audit", h.handleAdminListAudit)
		r.Post("/ldap/test", h.handleAdminLDAPTest)
	})
}

// handleHealthz is the liveness probe: it answers without touching the
// database so a sick DB does not get the process killed.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz is the readiness probe: it pings Postgres.
func handleReadyz(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if err := db.Ping(req.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
