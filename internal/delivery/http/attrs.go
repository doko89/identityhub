package http

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// ---------- admin: custom attributes ----------

func attrDefJSON(d domain.UserAttrDef) map[string]any {
	return map[string]any{"key": d.Key, "type": string(d.Type), "multi": d.Multi}
}

// handleAdminListAttrDefs lists the attribute schema ordered by key.
func (h *Handlers) handleAdminListAttrDefs(w http.ResponseWriter, req *http.Request) {
	defs, err := h.users.ListAttrDefs(req.Context())
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(defs))
	for _, d := range defs {
		out = append(out, attrDefJSON(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"defs": out})
}

type adminCreateAttrDefRequest struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Multi bool   `json:"multi"`
}

// handleAdminCreateAttrDef registers a custom attribute. Keys double as
// the wire names on LDAP, OIDC and SAML; reserved names are rejected.
func (h *Handlers) handleAdminCreateAttrDef(w http.ResponseWriter, req *http.Request) {
	var in adminCreateAttrDefRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	d, err := h.users.CreateAttrDef(req.Context(), mustUser(req.Context()).ID,
		in.Key, domain.UserAttrType(in.Type), in.Multi)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"def": attrDefJSON(d)})
}

// handleAdminDeleteAttrDef drops a def; its values cascade across users.
func (h *Handlers) handleAdminDeleteAttrDef(w http.ResponseWriter, req *http.Request) {
	key := req.PathValue("key")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "attribute key is required"})
		return
	}
	if err := h.users.DeleteAttrDef(req.Context(), mustUser(req.Context()).ID, key); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminGetUserAttrs returns one user's custom attributes as typed
// values (scalars for single-valued defs, arrays for multi-valued).
func (h *Handlers) handleAdminGetUserAttrs(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	attrs, err := h.users.GetUserAttrs(req.Context(), id)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attrs": attrs})
}

// handleAdminSetUserAttrs replaces the given keys (scalar or array per
// key, null clears) and returns the user's full typed map. Unknown keys
// and type violations fail the whole write.
func (h *Handlers) handleAdminSetUserAttrs(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	var in map[string]any
	if !decodeJSON(w, req, &in) {
		return
	}
	if in == nil {
		in = map[string]any{}
	}
	attrs, err := h.users.SetUserAttrs(req.Context(), mustUser(req.Context()).ID, id, in)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attrs": attrs})
}
