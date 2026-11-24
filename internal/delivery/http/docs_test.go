package http

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAdminDocsGuards(t *testing.T) {
	root := localUser("root", "root-password-12")
	bob := localUser("bob", "bob-password-12")
	h := newAPI(t, root, bob)
	ctx := context.Background()
	_ = h.groups.AddMember(ctx, root.ID, h.admin.ID)

	for _, path := range []string{"/api/admin/docs", "/api/admin/docs/openapi.json"} {
		// Anonymous bounces before any docs leak. The spec endpoint
		// answers JSON; the UI path needs a raw read (non-JSON 401).
		req, _ := http.NewRequest(http.MethodGet, h.server.URL+path, nil)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s anonymous = %d, want 401", path, resp.StatusCode)
		}
		if strings.Contains(string(raw), "openapi") {
			t.Errorf("GET %s anonymous leaked spec content", path)
		}
	}

	// Non-admin is forbidden on both.
	h.login(t, "bob", "bob-password-12")
	code, _ := h.do(http.MethodGet, "/api/admin/docs/openapi.json", nil)
	if code != http.StatusForbidden {
		t.Errorf("non-admin spec = %d, want 403", code)
	}
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/admin/docs", nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin UI = %d, want 403", resp.StatusCode)
	}
}

func TestAdminDocsContent(t *testing.T) {
	root := localUser("root", "root-password-12")
	h := newAPI(t, root)
	ctx := context.Background()
	_ = h.groups.AddMember(ctx, root.ID, h.admin.ID)
	h.login(t, "root", "root-password-12")

	code, out := h.do(http.MethodGet, "/api/admin/docs/openapi.json", nil)
	if code != http.StatusOK {
		t.Fatalf("spec = %d", code)
	}
	if out["openapi"] != "3.0.3" {
		t.Fatalf("spec openapi = %v", out["openapi"])
	}
	paths, _ := out["paths"].(map[string]any)
	for _, p := range []string{"/api/admin/users", "/api/admin/apps/{id}/bindings", "/api/admin/oidc/clients", "/api/admin/docs/openapi.json", "/api/auth/password/forgot", "/api/auth/password/reset"} {
		if _, ok := paths[p]; !ok {
			t.Errorf("spec missing path %s", p)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/admin/docs", nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UI = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("UI content-type = %q", ct)
	}
	if !strings.Contains(string(raw), "/api/admin/docs/openapi.json") {
		t.Error("UI does not reference the embedded spec URL")
	}
}
