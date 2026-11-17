package http

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
)

// ---------- admin: users ----------

func parsePage(get func(string) string) (limit, offset int) {
	limit, offset = 50, 0
	if v, err := strconv.Atoi(get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	if v, err := strconv.Atoi(get("offset")); err == nil && v >= 0 {
		offset = v
	}
	return limit, offset
}

// handleAdminListUsers searches and pages users (PRD §6.1).
func (h *Handlers) handleAdminListUsers(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	limit, offset := parsePage(q.Get)
	f := domain.UserFilter{Query: q.Get("q"), Source: domain.UserSource(q.Get("source")), Limit: limit, Offset: offset}
	if v := q.Get("active"); v != "" {
		active := v == "true" || v == "1"
		f.Active = &active
	}
	users, total, err := h.users.ListUsers(req.Context(), f)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(users))
	for _, u := range users {
		groups, err := h.groups.GroupsOfUser(req.Context(), u.ID)
		if err != nil {
			h.writeError(w, req, err)
			return
		}
		isAdmin, err := h.groups.IsMember(req.Context(), u.ID, domain.AdminGroup)
		if err != nil {
			h.writeError(w, req, err)
			return
		}
		out = append(out, userJSON(u, groupNames(groups), isAdmin))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "total": total})
}

type adminCreateUserRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Source      string `json:"source"`
	ExternalDN  string `json:"external_dn"`
}

// handleAdminCreateUser creates a local user or pre-provisions an LDAP one.
func (h *Handlers) handleAdminCreateUser(w http.ResponseWriter, req *http.Request) {
	var in adminCreateUserRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	u, err := h.users.CreateUser(req.Context(), mustUser(req.Context()).ID, usecaseuser.NewUser{
		Username: in.Username, Email: in.Email, DisplayName: in.DisplayName,
		Password: in.Password, Source: domain.UserSource(in.Source), ExternalDN: in.ExternalDN,
	})
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": userJSON(u, []string{}, false)})
}

// handleAdminGetUser returns one user with groups and the admin flag.
func (h *Handlers) handleAdminGetUser(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	u, err := h.users.GetUser(req.Context(), id)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	groups, err := h.groups.GroupsOfUser(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	isAdmin, err := h.groups.IsMember(req.Context(), u.ID, domain.AdminGroup)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(u, groupNames(groups), isAdmin)})
}

type adminUpdateUserRequest struct {
	DisplayName *string `json:"display_name"`
	Email       *string `json:"email"`
	AvatarURL   *string `json:"avatar_url"`
	IsActive    *bool   `json:"is_active"`
}

// handleAdminUpdateUser patches profile fields and/or the active flag.
// Deactivation revokes every session immediately (usecase).
func (h *Handlers) handleAdminUpdateUser(w http.ResponseWriter, req *http.Request) {
	var in adminUpdateUserRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	u, err := h.users.GetUser(req.Context(), id)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	if in.DisplayName != nil || in.Email != nil || in.AvatarURL != nil {
		display, email, avatar := u.DisplayName, u.Email, u.AvatarURL
		if in.DisplayName != nil {
			display = *in.DisplayName
		}
		if in.Email != nil {
			email = *in.Email
		}
		if in.AvatarURL != nil {
			avatar = *in.AvatarURL
		}
		if u, err = h.users.UpdateProfile(req.Context(), id, display, email, avatar); err != nil {
			h.writeError(w, req, err)
			return
		}
	}
	if in.IsActive != nil && *in.IsActive != u.IsActive {
		if err := h.users.SetActive(req.Context(), mustUser(req.Context()).ID, id, *in.IsActive); err != nil {
			h.writeError(w, req, err)
			return
		}
		u.IsActive = *in.IsActive
	}
	groups, err := h.groups.GroupsOfUser(req.Context(), u.ID)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	isAdmin, err := h.groups.IsMember(req.Context(), u.ID, domain.AdminGroup)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userJSON(u, groupNames(groups), isAdmin)})
}

// ---------- admin: groups ----------

func groupJSON(g domain.Group, members []string) map[string]any {
	return map[string]any{"id": g.ID.String(), "name": g.Name, "description": g.Description, "members": members}
}

// handleAdminListGroups pages groups with member counts.
func (h *Handlers) handleAdminListGroups(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePage(req.URL.Query().Get)
	groups, total, err := h.users.ListGroups(req.Context(), limit, offset)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(groups))
	for _, g := range groups {
		ids, err := h.groups.MemberIDs(req.Context(), g.ID)
		if err != nil {
			h.writeError(w, req, err)
			return
		}
		out = append(out, map[string]any{
			"id": g.ID.String(), "name": g.Name, "description": g.Description,
			"member_count": len(ids),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out, "total": total})
}

type adminCreateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// handleAdminCreateGroup creates a group (ih_admin is reserved).
func (h *Handlers) handleAdminCreateGroup(w http.ResponseWriter, req *http.Request) {
	var in adminCreateGroupRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	g, err := h.users.CreateGroup(req.Context(), in.Name, in.Description)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"group": groupJSON(g, []string{})})
}

// handleAdminGetGroup returns one group with member user ids.
func (h *Handlers) handleAdminGetGroup(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid group id"})
		return
	}
	g, err := h.groups.ByID(req.Context(), id)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	ids, err := h.groups.MemberIDs(req.Context(), id)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	members := make([]string, 0, len(ids))
	for _, mid := range ids {
		members = append(members, mid.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": groupJSON(g, members)})
}

// handleAdminDeleteGroup deletes a group; ih_admin is refused.
func (h *Handlers) handleAdminDeleteGroup(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid group id"})
		return
	}
	if err := h.users.DeleteGroup(req.Context(), id); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type adminAddMemberRequest struct {
	UserID string `json:"user_id"`
}

// handleAdminAddMember adds a user to a group (idempotent).
func (h *Handlers) handleAdminAddMember(w http.ResponseWriter, req *http.Request) {
	var in adminAddMemberRequest
	if !decodeJSON(w, req, &in) {
		return
	}
	groupID, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid group id"})
		return
	}
	userID, err := uuid.Parse(in.UserID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	if err := h.users.AddMember(req.Context(), mustUser(req.Context()).ID, userID, groupID); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminRemoveMember removes a user from a group. From ih_admin,
// self-removal and last-member removal are refused (usecase).
func (h *Handlers) handleAdminRemoveMember(w http.ResponseWriter, req *http.Request) {
	groupID, err := uuid.Parse(req.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid group id"})
		return
	}
	userID, err := uuid.Parse(req.PathValue("userID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}
	if err := h.users.RemoveMember(req.Context(), mustUser(req.Context()).ID, userID, groupID); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- admin: audit ----------

// auditFilterError maps a malformed filter parameter to its 400 message.
// The list and CSV export endpoints share the vocabulary.
func auditFilterError(param string) string {
	switch param {
	case "actor":
		return "invalid actor id"
	case "app":
		return "invalid app id"
	case "since":
		return "invalid since timestamp"
	case "until":
		return "invalid until timestamp"
	default:
		return "invalid filter"
	}
}

// parseAuditFilter reads the shared list/export filters (actor, app,
// method, result, since/until). It returns the offending parameter name
// when a value is malformed, or "" on success.
func parseAuditFilter(q map[string][]string, limit, offset int) (domain.AuditFilter, string) {
	get := func(k string) string {
		if len(q[k]) > 0 {
			return q[k][0]
		}
		return ""
	}
	f := domain.AuditFilter{Method: get("method"), Result: get("result"), Limit: limit, Offset: offset}
	if v := get("actor"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return domain.AuditFilter{}, "actor"
		}
		f.ActorUserID = &id
	}
	if v := get("app"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return domain.AuditFilter{}, "app"
		}
		f.ApplicationID = &id
	}
	// since/until accept RFC3339 timestamps; malformed values are 400.
	if v := get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return domain.AuditFilter{}, "since"
		}
		f.Since = &t
	}
	if v := get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return domain.AuditFilter{}, "until"
		}
		f.Until = &t
	}
	return f, ""
}

// handleAdminListAudit pages audit entries, newest first.
func (h *Handlers) handleAdminListAudit(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	limit, offset := parsePage(q.Get)
	f, bad := parseAuditFilter(q, limit, offset)
	if bad != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": auditFilterError(bad)})
		return
	}
	entries, total, err := h.audits.List(req.Context(), f)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		var actor, app any
		if e.ActorUserID != nil {
			actor = e.ActorUserID.String()
		}
		if e.ApplicationID != nil {
			app = e.ApplicationID.String()
		}
		out = append(out, map[string]any{
			"id": e.ID, "at": e.At.Format(time.RFC3339), "actor_user_id": actor,
			"application_id": app, "method": e.Method, "result": e.Result,
			"ip": e.IP, "detail": e.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out, "total": total})
}

// handleAdminExportAudit downloads the filtered audit log as CSV
// (PRD §6.9), newest first, capped at usecaseaudit.MaxExportRows rows.
// The output is buffered so a mid-stream store failure still answers a
// clean 500 instead of a truncated file.
func (h *Handlers) handleAdminExportAudit(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	f, bad := parseAuditFilter(q, 0, 0)
	if bad != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": auditFilterError(bad)})
		return
	}
	var buf bytes.Buffer
	if _, err := h.audits.ExportCSV(req.Context(), f, &buf); err != nil {
		h.writeError(w, req, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="audit-export-%s.csv"`,
		time.Now().UTC().Format("20060102-150405")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// ---------- admin: LDAP upstream ----------

// handleAdminLDAPTest checks the upstream directory connection from the
// admin UI (PRD §6.2). Without LDAP_URL configured it reports disabled.
func (h *Handlers) handleAdminLDAPTest(w http.ResponseWriter, req *http.Request) {
	if h.dir == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false, "ok": false, "error": "LDAP upstream is not configured"})
		return
	}
	if err := h.dir.Ping(req.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": true, "ok": false, "error": "directory unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "ok": true})
}
