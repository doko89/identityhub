package http

import (
	"net/http"

	"github.com/identityhub/identityhub/internal/domain"
)

// ---------- branding ----------

// brandingJSON renders the singleton brand for the public theme endpoint
// and the admin console. It carries no secrets (TECH_SPEC §6.1).
func brandingJSON(b domain.Branding) map[string]any {
	return map[string]any{
		"org_name": b.OrgName, "tagline": b.Tagline, "logo_url": b.LogoURL,
		"favicon_url": b.FaviconURL, "primary_color": b.PrimaryColor, "theme": b.Theme,
		"login_background_url": b.LoginBackgroundURL, "custom_css": b.CustomCSS,
	}
}

// handleGetBranding answers the public theme endpoint (TECH_SPEC §7).
// The login page and the SPA theme provider fetch it on every load, so
// the response is never cached client-side: admin edits apply without a
// redeploy and without waiting out a max-age.
func (h *Handlers) handleGetBranding(w http.ResponseWriter, req *http.Request) {
	b, err := h.branding.Get(req.Context())
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"branding": brandingJSON(b)})
}

type adminBrandingRequest struct {
	OrgName            *string `json:"org_name"`
	Tagline            *string `json:"tagline"`
	LogoURL            *string `json:"logo_url"`
	FaviconURL         *string `json:"favicon_url"`
	PrimaryColor       *string `json:"primary_color"`
	Theme              *string `json:"theme"`
	LoginBackgroundURL *string `json:"login_background_url"`
	CustomCSS          *string `json:"custom_css"`
}

// handleAdminUpdateBranding rewrites the singleton row. Only keys present
// in the body change; the usecase re-validates the merged row (hex
// colors, known themes, custom_css safety) before storing it.
func (h *Handlers) handleAdminUpdateBranding(w http.ResponseWriter, req *http.Request) {
	var in adminBrandingRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	current, err := h.branding.Get(req.Context())
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	next := current
	if in.OrgName != nil {
		next.OrgName = *in.OrgName
	}
	if in.Tagline != nil {
		next.Tagline = *in.Tagline
	}
	if in.LogoURL != nil {
		next.LogoURL = *in.LogoURL
	}
	if in.FaviconURL != nil {
		next.FaviconURL = *in.FaviconURL
	}
	if in.PrimaryColor != nil {
		next.PrimaryColor = *in.PrimaryColor
	}
	if in.Theme != nil {
		next.Theme = *in.Theme
	}
	if in.LoginBackgroundURL != nil {
		next.LoginBackgroundURL = *in.LoginBackgroundURL
	}
	if in.CustomCSS != nil {
		next.CustomCSS = *in.CustomCSS
	}
	updated, err := h.branding.Update(req.Context(), mustUser(req.Context()).ID, next)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"branding": brandingJSON(updated)})
}
