package http

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var adminOpenAPI []byte

// adminDocsHTML renders the embedded spec with Scalar from CDN. The spec
// URL is same-origin so the browser reuses the admin session cookie;
// no secret ever appears in the page.
const adminDocsHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IdentityHub Admin API</title>
</head>
<body>
<script id="api-reference" data-url="/api/admin/docs/openapi.json"></script>
<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>
`

// handleAdminAPIDocs serves the API reference UI. Mounted inside the
// requireAdmin group: ih_admin session (MFA) or admin-owned Bearer key.
func (h *Handlers) handleAdminAPIDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(adminDocsHTML))
}

// handleAdminAPIDocsSpec serves the embedded OpenAPI document.
func (h *Handlers) handleAdminAPIDocsSpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(adminOpenAPI)
}
