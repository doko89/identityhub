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
	Sessions interface {
		LoadAndSave(next http.Handler) http.Handler
	}
	DB Pinger
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
