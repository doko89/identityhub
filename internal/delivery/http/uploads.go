package http

import (
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/adapter/storage"
	"github.com/identityhub/identityhub/internal/domain"
)

// maxUploadFormBytes caps the multipart form: 10 MB of image plus header
// headroom (TECH_SPEC §8 enforces 10 MB on the image itself).
const maxUploadFormBytes = (10 << 20) + (64 << 10)

// handleUpload stores one image as webp (TECH_SPEC §6.7). Any signed-in
// user may upload an avatar; app/SaaS logos are admin-only.
func (h *Handlers) handleUpload(w http.ResponseWriter, req *http.Request) {
	u := mustUser(req.Context())
	if !h.limiter.Allow("upload:user:"+u.ID.String(), UploadPerUserLimit, UploadPerUserWindow) {
		writeRateLimited(w)
		return
	}
	if err := req.ParseMultipartForm(maxUploadFormBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid multipart upload"})
		return
	}
	assetType := strings.TrimSpace(req.FormValue("asset_type"))
	switch assetType {
	case domain.AssetAvatar:
	case domain.AssetAppLogo, domain.AssetSaaSLogo:
		member, err := h.groups.IsMember(req.Context(), u.ID, domain.AdminGroup)
		if err != nil {
			h.writeError(w, req, err)
			return
		}
		if !member {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator access required"})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "asset_type must be avatar, app_logo or saas_logo"})
		return
	}
	file, _, err := req.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "multipart field file is required"})
		return
	}
	defer file.Close()
	a, err := h.assets.Upload(req.Context(), &u.ID, assetType, file)
	if err != nil {
		h.writeError(w, req, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": a.ID.String(), "url": a.PublicPath(),
		"width": a.Width, "height": a.Height, "byte_size": a.ByteSize,
	})
}

// handleUploadServe reads back an object by its public path
// (/uploads/<type>/<uuid>.webp). The path carries no user input beyond
// the UUID, the content type is pinned to image/webp, and the immutable
// cache header matches the content-addressed key (a re-upload mints a
// new UUID, so stale caches cannot stick).
func (h *Handlers) handleUploadServe(w http.ResponseWriter, req *http.Request) {
	rest, ok := strings.CutPrefix(req.URL.Path, "/uploads/")
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	typ, file := parts[0], parts[1]
	switch typ {
	case domain.AssetAvatar, domain.AssetAppLogo, domain.AssetSaaSLogo:
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	name, ok := strings.CutSuffix(file, ".webp")
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if _, err := uuid.Parse(name); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	rc, err := h.storage.Get(req.Context(), typ+"/"+file)
	if err != nil {
		if storage.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		h.writeError(w, req, err)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "image/webp")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}
