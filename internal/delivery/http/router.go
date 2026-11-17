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
	h.mountOIDC(r)
	h.mountSAML(r)
	r.With(h.requireUser).Get("/api/auth/me", h.handleMe)
	r.With(h.requireUser).Post("/api/account/password/change", h.handleChangePassword)
	r.With(h.requireUser).Post("/api/account/avatar", h.handleUpdateAccountAvatar)
	h.mountMFA(r)
	h.mountApps(r)
	if h.branding != nil {
		r.Get("/api/branding", h.handleGetBranding)
	}

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
		r.Get("/audit/export", h.handleAdminExportAudit)
		r.Post("/ldap/test", h.handleAdminLDAPTest)
		if h.mfa != nil {
			r.Post("/users/{id}/mfa/reset", h.handleAdminMFAReset)
		}
		if h.branding != nil {
			r.Patch("/branding", h.handleAdminUpdateBranding)
		}
		if h.providers != nil {
			r.Get("/oidc/clients", h.handleAdminListOIDCClients)
			r.Post("/oidc/clients", h.handleAdminCreateOIDCClient)
			r.Delete("/oidc/clients/{clientID}", h.handleAdminDeleteOIDCClient)
			r.Get("/saml/sps", h.handleAdminListSAMLSPs)
			r.Post("/saml/sps", h.handleAdminImportSAMLSP)
			r.Delete("/saml/sps", h.handleAdminDeleteSAMLSP)
			r.Get("/radius/clients", h.handleAdminListRADIUSClients)
			r.Post("/radius/clients", h.handleAdminCreateRADIUSClient)
			r.Delete("/radius/clients/{nas}", h.handleAdminDeleteRADIUSClient)
		}
		if h.apps != nil {
			r.Get("/apps", h.handleAdminListApps)
			r.Post("/apps", h.handleAdminCreateApp)
			r.Get("/apps/{id}", h.handleAdminGetApp)
			r.Patch("/apps/{id}", h.handleAdminUpdateApp)
			r.Delete("/apps/{id}", h.handleAdminDeleteApp)
			r.Get("/apps/{id}/bindings", h.handleAdminListBindings)
			r.Post("/apps/{id}/bindings", h.handleAdminCreateBinding)
			r.Delete("/apps/{id}/bindings/{bindingID}", h.handleAdminDeleteBinding)
		}
	})
}

// mountMFA registers the second-step and self-service factor routes.
// Skipped when MFA is unwired (unit tests that predate M5).
func (h *Handlers) mountMFA(r *chi.Mux) {
	if h.mfa == nil {
		return
	}
	r.Post("/api/auth/mfa/totp", h.handleVerifyTOTP)
	r.With(h.requireUser).Get("/api/account/mfa/status", h.handleMFAStatus)
	// Enroll accepts pending-setup sessions (first admin login) as well
	// as full sessions, so it resolves its own subject.
	r.Post("/api/account/mfa/enroll", h.handleMFAEnroll)
	r.Post("/api/account/mfa/enroll/confirm", h.handleMFAEnrollConfirm)
	r.With(h.requireUser).Post("/api/account/mfa/disable", h.handleMFADisable)
	r.With(h.requireUser).Post("/api/account/mfa/recovery/regenerate", h.handleMFARegenerateRecovery)
}

// mountApps registers the dashboard, launch and upload routes. Skipped
// piece-wise when the catalog or assets are unwired.
func (h *Handlers) mountApps(r *chi.Mux) {
	if h.apps != nil {
		r.With(h.requireUser).Get("/api/my-apps", h.handleMyApps)
		r.With(h.requireUser).Get("/api/apps/{slug}/launch", h.handleLaunch)
	}
	if h.assets != nil && h.storage != nil {
		r.With(h.requireUser).Post("/api/uploads", h.handleUpload)
		r.Get("/uploads/*", h.handleUploadServe)
	}
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
