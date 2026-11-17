package http

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	frontend "github.com/identityhub/identityhub/web"
)

// serveSPA serves the embedded production build (web/dist). Exact file hits
// (JS/CSS/assets) return the file; every other non-API path falls back to
// index.html so the React router owns client-side routes (/login, /mfa, ...).
func serveSPA(w http.ResponseWriter, req *http.Request) {
	dist, err := fs.Sub(frontend.Dist, "dist")
	if err != nil {
		http.Error(w, "frontend build missing", http.StatusServiceUnavailable)
		return
	}
	p := path.Clean("/" + strings.TrimPrefix(req.URL.Path, "/"))
	if p != "/" {
		if f, err := dist.Open(strings.TrimPrefix(p, "/")); err == nil {
			_ = f.Close()
			http.ServeFileFS(w, req, dist, strings.TrimPrefix(p, "/"))
			return
		}
	}
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		http.Error(w, "frontend build missing", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(index)
}

// isAPIPath reports whether p belongs to the JSON/protocol API surface
// (handled by routers, never by the SPA fallback).
func isAPIPath(p string) bool {
	for _, prefix := range []string{"/api/", "/oauth2/", "/saml/", "/.well-known/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return p == "/api"
}
