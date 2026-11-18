package http

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/metrics"
)

// ---------- dashboard (PRD §6.7) ----------

func appJSON(a domain.Application) map[string]any {
	return map[string]any{
		"id": a.ID.String(), "slug": a.Slug, "name": a.Name,
		"description": a.Description, "icon_url": a.IconURL,
		"launch_url": a.LaunchURL, "group_label": a.GroupLabel,
		"provider_type": string(a.ProviderType), "is_visible": a.IsVisible,
		"sort_order": a.SortOrder, "mfa_required": a.MFARequired,
		"open_in_new_tab": a.OpenInNewTab,
	}
}

// handleMyApps returns the session user's dashboard: visible apps whose
// bindings admit them (PRD §6.7).
func (h *Handlers) handleMyApps(w http.ResponseWriter, req *http.Request) {
	u := mustUser(req.Context())
	apps, err := h.apps.MyApps(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(apps))
	for _, a := range apps {
		out = append(out, appJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

// handleLaunch resolves an app for SSO start. When the app's MFA policy
// covers the user, the session must have verified a factor (the client
// steps up through POST /api/auth/mfa/totp, then retries).
func (h *Handlers) handleLaunch(w http.ResponseWriter, req *http.Request) {
	u := mustUser(req.Context())
	slug := req.PathValue("slug")
	a, err := h.apps.Launch(req.Context(), u.ID, slug)
	if err != nil {
		metrics.ObserveAuthFailure("launch", slug)
		h.writeError(w, req, err)
		return
	}
	if h.mfa != nil {
		required, err := h.mfa.RequiredForApp(req.Context(), u.ID, a.ID)
		if err != nil {
			metrics.ObserveAuthFailure("launch", slug)
			h.writeError(w, req, err)
			return
		}
		if required {
			if _, ok := h.mfaVerifiedAt(req); !ok {
				metrics.ObserveAuthFailure("launch", slug)
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":        "multi-factor authentication is required to open this application",
					"mfa_required": true,
				})
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": appJSON(a), "launch_url": a.LaunchURL})
}

// ---------- admin: app catalog ----------

type adminAppRequest struct {
	Slug         *string `json:"slug"`
	Name         *string `json:"name"`
	Description  *string `json:"description"`
	IconURL      *string `json:"icon_url"`
	LaunchURL    *string `json:"launch_url"`
	GroupLabel   *string `json:"group_label"`
	ProviderType *string `json:"provider_type"`
	IsVisible    *bool   `json:"is_visible"`
	SortOrder    *int    `json:"sort_order"`
	MFARequired  *bool   `json:"mfa_required"`
	OpenInNewTab *bool   `json:"open_in_new_tab"`
}

// applyTo overlays the keys present in the body onto base. Create passes
// a zero app (visible by default); update passes the stored row so
// omitted keys keep their values.
func (r adminAppRequest) applyTo(base domain.Application) domain.Application {
	if r.Slug != nil {
		base.Slug = *r.Slug
	}
	if r.Name != nil {
		base.Name = *r.Name
	}
	if r.Description != nil {
		base.Description = *r.Description
	}
	if r.IconURL != nil {
		base.IconURL = *r.IconURL
	}
	if r.LaunchURL != nil {
		base.LaunchURL = *r.LaunchURL
	}
	if r.GroupLabel != nil {
		base.GroupLabel = *r.GroupLabel
	}
	if r.ProviderType != nil {
		base.ProviderType = domain.ProviderType(*r.ProviderType)
	}
	if r.IsVisible != nil {
		base.IsVisible = *r.IsVisible
	}
	if r.SortOrder != nil {
		base.SortOrder = *r.SortOrder
	}
	if r.MFARequired != nil {
		base.MFARequired = *r.MFARequired
	}
	if r.OpenInNewTab != nil {
		base.OpenInNewTab = *r.OpenInNewTab
	}
	return base
}

// handleAdminListApps pages the whole catalog including invisible apps,
// optionally filtered by dashboard group (?group=).
func (h *Handlers) handleAdminListApps(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	limit, offset := parsePage(q.Get)
	f := domain.AppFilter{Group: q.Get("group"), Limit: limit, Offset: offset}
	apps, total, err := h.apps.ListApps(req.Context(), f)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(apps))
	for _, a := range apps {
		out = append(out, appJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out, "total": total})
}

// handleAdminCreateApp registers an application.
func (h *Handlers) handleAdminCreateApp(w http.ResponseWriter, req *http.Request) {
	var in adminAppRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	a, err := h.apps.CreateApp(req.Context(), in.applyTo(domain.Application{IsVisible: true}))
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"app": appJSON(a)})
}

// handleAdminGetApp returns one application.
func (h *Handlers) handleAdminGetApp(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid app id"})
		return
	}
	a, err := h.apps.GetApp(req.Context(), id)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": appJSON(a)})
}

// handleAdminUpdateApp patches an application. Only keys present in the
// body change; omitted keys keep their stored values.
func (h *Handlers) handleAdminUpdateApp(w http.ResponseWriter, req *http.Request) {
	var in adminAppRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid app id"})
		return
	}
	current, err := h.apps.GetApp(req.Context(), id)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	next := in.applyTo(current)
	next.ID = id
	updated, err := h.apps.UpdateApp(req.Context(), next)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": appJSON(updated)})
}

// handleAdminDeleteApp removes an application (bindings cascade).
func (h *Handlers) handleAdminDeleteApp(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid app id"})
		return
	}
	if err := h.apps.DeleteApp(req.Context(), id); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- admin: bindings ----------

func bindingJSON(b domain.AppBinding) map[string]any {
	out := map[string]any{
		"id": b.ID.String(), "application_id": b.ApplicationID.String(),
		"binding_type": string(b.BindingType), "eval_mode": string(b.EvalMode),
	}
	if b.UserID != nil {
		out["user_id"] = b.UserID.String()
	}
	if b.GroupID != nil {
		out["group_id"] = b.GroupID.String()
	}
	if b.PolicyExpr != "" {
		out["policy_expr"] = b.PolicyExpr
	}
	return out
}

type adminBindingRequest struct {
	BindingType string `json:"binding_type"`
	UserID      string `json:"user_id"`
	GroupID     string `json:"group_id"`
	PolicyExpr  string `json:"policy_expr"`
	EvalMode    string `json:"eval_mode"`
}

// handleAdminListBindings returns every binding of one application.
func (h *Handlers) handleAdminListBindings(w http.ResponseWriter, req *http.Request) {
	appID, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid app id"})
		return
	}
	bindings, err := h.apps.ListBindings(req.Context(), appID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, bindingJSON(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": out})
}

// handleAdminCreateBinding stores one binding.
func (h *Handlers) handleAdminCreateBinding(w http.ResponseWriter, req *http.Request) {
	var in adminBindingRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	appID, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid app id"})
		return
	}
	b := domain.AppBinding{
		ApplicationID: appID, BindingType: domain.BindingType(in.BindingType),
		PolicyExpr: in.PolicyExpr, EvalMode: domain.EvalMode(in.EvalMode),
	}
	if in.UserID != "" {
		id, err := uuid.Parse(in.UserID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
			return
		}
		b.UserID = &id
	}
	if in.GroupID != "" {
		id, err := uuid.Parse(in.GroupID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid group id"})
			return
		}
		b.GroupID = &id
	}
	created, err := h.apps.CreateBinding(req.Context(), b)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"binding": bindingJSON(created)})
}

// handleAdminDeleteBinding removes one binding.
func (h *Handlers) handleAdminDeleteBinding(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("bindingID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid binding id"})
		return
	}
	if err := h.apps.DeleteBinding(req.Context(), id); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
