//go:build integration

// M7 hardening end-to-end tests against real Postgres (TECH_SPEC §9):
// public + admin branding (PRD §6.8), custom_css sanitization, and the
// audit CSV export (PRD §6.9). The fixture is shared with the MFA/apps
// suite (setupMFAFixture), which wires branding since M7.
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5434/identityhub \
//	  go test -tags=integration ./internal/delivery/http/ -run 'TestBranding|TestAuditExport'
package http

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// getBranding fetches the public theme endpoint without a session.
func getBranding(t *testing.T, fx *mfaFixture) (int, map[string]any, http.Header) {
	t.Helper()
	resp, err := http.Get(fx.srv.URL + "/api/branding")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("branding body is not JSON: %v", err)
		}
	}
	return resp.StatusCode, out, resp.Header
}

// verifiedAdmin returns a browser holding a full MFA admin session:
// password login parks at setup, enroll promotes it (M5 flow).
func verifiedAdmin(t *testing.T, fx *mfaFixture, prefix string) (*http.Client, domain.User) {
	t.Helper()
	root := fx.mkadmin(prefix)
	r := fx.browser()
	if code, body := fx.login(r, root.Username); code != 200 || body["setup_required"] != true {
		t.Fatalf("admin login = %d %v, want setup park", code, body)
	}
	fx.enroll(r)
	return r, root
}

func TestBrandingPublicGet(t *testing.T) {
	fx := setupMFAFixture(t)
	code, body, hdr := getBranding(t, fx)
	if code != 200 {
		t.Fatalf("GET /api/branding = %d (%v), want 200", code, body)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", hdr.Get("Cache-Control"))
	}
	brand, _ := body["branding"].(map[string]any)
	for _, k := range []string{"org_name", "logo_url", "favicon_url", "primary_color", "theme", "login_background_url", "custom_css"} {
		if _, ok := brand[k]; !ok {
			t.Fatalf("branding missing key %q: %v", k, body)
		}
	}
}

func TestBrandingAdminUpdateE2E(t *testing.T) {
	fx := setupMFAFixture(t)
	r, _ := verifiedAdmin(t, fx, "brand-root")

	// Snapshot the row so the suite leaves the singleton untouched.
	_, before, _ := getBranding(t, fx)
	t.Cleanup(func() {
		doJSON(t, r, http.MethodPatch, fx.srv.URL+"/api/admin/branding", before["branding"])
	})

	patchURL := fx.srv.URL + "/api/admin/branding"
	wantOrg := "E2E Org " + strings.Repeat("x", 4)
	code, body := doJSON(t, r, http.MethodPatch, patchURL, map[string]any{
		"org_name": wantOrg, "primary_color": "#123abc", "theme": "dark",
		"custom_css": ".login { color: #123abc; }",
	})
	if code != 200 {
		t.Fatalf("PATCH branding = %d (%v), want 200", code, body)
	}
	if got, _ := body["branding"].(map[string]any)["org_name"].(string); got != wantOrg {
		t.Fatalf("updated org_name = %q, want %q", got, wantOrg)
	}
	// The public endpoint reflects the change without a redeploy.
	_, after, _ := getBranding(t, fx)
	if got, _ := after["branding"].(map[string]any)["primary_color"].(string); got != "#123abc" {
		t.Fatalf("public primary_color = %q, want #123abc", got)
	}

	// Partial update: omitted keys keep their stored values.
	if code, body := doJSON(t, r, http.MethodPatch, patchURL, map[string]any{"theme": "light"}); code != 200 {
		t.Fatalf("partial PATCH = %d (%v)", code, body)
	} else if brand, _ := body["branding"].(map[string]any); brand["org_name"] != wantOrg || brand["theme"] != "light" {
		t.Fatalf("partial PATCH lost stored values: %v", brand)
	}

	// Sanitization rejects bypass attempts before anything is stored.
	for name, css := range map[string]string{
		"import":   `@import url("https://evil/x.css");`,
		"url":      `.a { background: url(https://evil/x.png); }`,
		"style":    `a{}</style><script>alert(1)</script>`,
		"oversize": strings.Repeat("a", 10*1024+1),
	} {
		if code, _ := doJSON(t, r, http.MethodPatch, patchURL, map[string]any{"custom_css": css}); code != 400 {
			t.Fatalf("PATCH css/%s = %d, want 400", name, code)
		}
	}
	if code, _ := doJSON(t, r, http.MethodPatch, patchURL, map[string]any{"primary_color": "red"}); code != 400 {
		t.Fatalf("PATCH bad color = %d, want 400", code)
	}
	if code, _ := doJSON(t, r, http.MethodPatch, patchURL, map[string]any{"theme": "neon"}); code != 400 {
		t.Fatalf("PATCH bad theme = %d, want 400", code)
	}

	// Guards: anonymous 401, plain user 403, admin without MFA 403.
	anon := fx.browser()
	if code, _ := doJSON(t, anon, http.MethodPatch, patchURL, map[string]any{"org_name": "x"}); code != 401 {
		t.Fatalf("anonymous PATCH = %d, want 401", code)
	}
	alice := fx.mkuser("brand-alice")
	a := fx.browser()
	if code, _ := fx.login(a, alice.Username); code != 200 {
		t.Fatalf("alice login = %d", code)
	}
	if code, _ := doJSON(t, a, http.MethodPatch, patchURL, map[string]any{"org_name": "x"}); code != 403 {
		t.Fatalf("non-admin PATCH = %d, want 403", code)
	}
}

func TestAuditExportCSV(t *testing.T) {
	fx := setupMFAFixture(t)
	r, _ := verifiedAdmin(t, fx, "csv-root")

	// Generate isolated rows: one success + one failure for a fresh user.
	bob := fx.mkuser("csv-bob")
	b := fx.browser()
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("bob login = %d", code)
	}
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/auth/login", map[string]any{
		"username": bob.Username, "password": "wrong-password-000",
	}); code != 401 {
		t.Fatalf("bob bad login = %d, want 401", code)
	}

	exportURL := fx.srv.URL + "/api/admin/audit/export?actor=" + bob.ID.String()
	req, err := http.NewRequest(http.MethodGet, exportURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("export = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "audit-export-") {
		t.Fatalf("Content-Disposition = %q, want attachment", cd)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v", err)
	}
	if len(recs) != 3 { // header + success + failure
		t.Fatalf("records = %d, want 3", len(recs))
	}
	seen := map[string]bool{}
	for _, rec := range recs[1:] {
		if rec[2] != bob.ID.String() || rec[4] != domain.MethodPassword {
			t.Fatalf("row leaks other actors: %v", rec)
		}
		seen[rec[5]] = true
	}
	if !seen[domain.ResultSuccess] || !seen[domain.ResultFailure] {
		t.Fatalf("export misses success/failure rows: %v", recs)
	}

	// Filters narrow the export like they narrow the list.
	filtered, err := http.NewRequest(http.MethodGet, exportURL+"&result=failure", nil)
	if err != nil {
		t.Fatal(err)
	}
	fresp, err := r.Do(filtered)
	if err != nil {
		t.Fatal(err)
	}
	defer fresp.Body.Close()
	fraw, _ := io.ReadAll(io.LimitReader(fresp.Body, 1<<20))
	frecs, err := csv.NewReader(strings.NewReader(string(fraw))).ReadAll()
	if err != nil || len(frecs) != 2 || frecs[1][5] != domain.ResultFailure {
		t.Fatalf("filtered export = %v (err %v), want header + 1 failure", frecs, err)
	}

	// Malformed filters are 400 with the shared vocabulary.
	badActor, err := http.NewRequest(http.MethodGet, fx.srv.URL+"/api/admin/audit/export?actor=nope", nil)
	if err != nil {
		t.Fatal(err)
	}
	bresp, err := r.Do(badActor)
	if err != nil {
		t.Fatal(err)
	}
	defer bresp.Body.Close()
	if bresp.StatusCode != 400 {
		t.Fatalf("bad actor export = %d, want 400", bresp.StatusCode)
	}

	// Guards: anonymous 401, plain user 403.
	anon := fx.browser()
	areq, _ := http.NewRequest(http.MethodGet, exportURL, nil)
	aresp, err := anon.Do(areq)
	if err != nil {
		t.Fatal(err)
	}
	_ = aresp.Body.Close()
	if aresp.StatusCode != 401 {
		t.Fatalf("anonymous export = %d, want 401", aresp.StatusCode)
	}
	ureq, _ := http.NewRequest(http.MethodGet, exportURL, nil)
	uresp, err := b.Do(ureq)
	if err != nil {
		t.Fatal(err)
	}
	_ = uresp.Body.Close()
	if uresp.StatusCode != 403 {
		t.Fatalf("non-admin export = %d, want 403", uresp.StatusCode)
	}
}

// spMetadata builds a minimal SP metadata document with a test-unique
// entityID (the registry enforces UNIQUE entity_id across runs).
func spMetadata(tag string) string {
	return `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp-` + tag + `.example.com/metadata">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp-` + tag + `.example.com/acs" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`
}

// TestProviderRegistrationE2E walks the admin registration APIs a
// non-developer follows in docs/INTEGRATION.md: catalog app first, then
// exactly one protocol credential per app (OIDC client secret, SAML
// metadata import, RADIUS NAS secret), each shown once.
func TestProviderRegistrationE2E(t *testing.T) {
	fx := setupMFAFixture(t)
	r, _ := verifiedAdmin(t, fx, "prov-root")
	tag := uuid.NewString()[:8]

	mkapp := func(slug, provider string) string {
		t.Helper()
		code, body := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/apps", map[string]any{
			"slug": slug + "-" + tag, "name": slug, "provider_type": provider,
		})
		if code != 201 {
			t.Fatalf("create app %s = %d (%v)", slug, code, body)
		}
		app, _ := body["app"].(map[string]any)
		id, _ := app["id"].(string)
		if id == "" {
			t.Fatalf("create app %s returned no id: %v", slug, body)
		}
		t.Cleanup(func() {
			_, _ = doJSON(t, r, http.MethodDelete, fx.srv.URL+"/api/admin/apps/"+id, nil)
		})
		return id
	}

	// OIDC: confidential client, secret shown once, one client per app.
	appOIDC := mkapp("prov-wiki", "oidc")
	code, body := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/oidc/clients", map[string]any{
		"application_id": appOIDC, "redirect_uris": []string{"https://wiki.example.com/callback"},
	})
	if code != 201 {
		t.Fatalf("register OIDC client = %d (%v)", code, body)
	}
	client, _ := body["client"].(map[string]any)
	clientID, _ := client["client_id"].(string)
	secret, _ := body["client_secret"].(string)
	if !strings.HasPrefix(clientID, "oidc-") || len(secret) != 43 {
		t.Fatalf("client id=%q secret len=%d", clientID, len(secret))
	}
	if _, hasHash := client["client_secret_hash"]; hasHash {
		t.Fatalf("create must never echo the hash: %v", client)
	}
	if code, body := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/oidc/clients", map[string]any{
		"application_id": appOIDC, "redirect_uris": []string{"http://evil.example.com/cb"},
	}); code != 400 {
		t.Fatalf("http redirect = %d (%v), want 400", code, body)
	}
	if code, body := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/oidc/clients", map[string]any{
		"application_id": appOIDC, "redirect_uris": []string{"https://wiki.example.com/other"},
	}); code != 409 {
		t.Fatalf("second client for one app = %d (%v), want 409", code, body)
	}
	if code, body := doJSON(t, r, http.MethodGet, fx.srv.URL+"/api/admin/oidc/clients", nil); code != 200 {
		t.Fatalf("list OIDC clients = %d", code)
	} else if raw, _ := body["clients"].([]any); len(raw) == 0 {
		t.Fatalf("list misses the registered client: %v", body)
	} else if _, hasSecret := raw[0].(map[string]any)["client_secret"]; hasSecret {
		t.Fatalf("list must not re-show secrets: %v", raw[0])
	}
	if code, _ := doJSON(t, r, http.MethodDelete, fx.srv.URL+"/api/admin/oidc/clients/"+clientID, nil); code != 204 {
		t.Fatalf("delete OIDC client = %d, want 204", code)
	}
	if code, _ := doJSON(t, r, http.MethodDelete, fx.srv.URL+"/api/admin/oidc/clients/"+clientID, nil); code != 404 {
		t.Fatalf("re-delete OIDC client = %d, want 404", code)
	}
	if client["public"] != false {
		t.Fatalf("confidential create must report public=false: %v", client)
	}
	// Public client: no secret issued, flagged PKCE-only.
	if code, body := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/oidc/clients", map[string]any{
		"application_id": appOIDC, "redirect_uris": []string{"https://spa.example.com/cb"}, "public": true,
	}); code != 201 {
		t.Fatalf("register public client = %d (%v)", code, body)
	} else if pub, _ := body["client"].(map[string]any); pub["public"] != true {
		t.Fatalf("public create must report public=true: %v", pub)
	} else if _, hasSecret := body["client_secret"]; hasSecret {
		t.Fatalf("public create must not issue a secret: %v", body)
	}

	// SAML: metadata import, duplicate + garbage rejected.
	appSAML := mkapp("prov-crm", "saml")
	entity := "https://sp-" + tag + ".example.com/metadata"
	code, body = doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/saml/sps", map[string]any{
		"application_id": appSAML, "metadata_xml": spMetadata(tag),
	})
	if code != 201 {
		t.Fatalf("import SP = %d (%v)", code, body)
	}
	if sp, _ := body["sp"].(map[string]any); sp["entity_id"] != entity {
		t.Fatalf("imported entity = %v, want %s", sp, entity)
	}
	if code, _ := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/saml/sps", map[string]any{
		"application_id": appSAML, "metadata_xml": "not xml",
	}); code != 400 {
		t.Fatalf("garbage metadata = %d, want 400", code)
	}
	appSAML2 := mkapp("prov-crm2", "saml")
	if code, _ := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/saml/sps", map[string]any{
		"application_id": appSAML2, "metadata_xml": spMetadata(tag),
	}); code != 409 {
		t.Fatalf("duplicate entity = %d, want 409", code)
	}
	delSP := fx.srv.URL + "/api/admin/saml/sps?entity_id=" + url.QueryEscape(entity)
	if code, _ := doJSON(t, r, http.MethodDelete, delSP, nil); code != 204 {
		t.Fatalf("delete SP = %d, want 204", code)
	}
	if code, _ := doJSON(t, r, http.MethodDelete, delSP, nil); code != 404 {
		t.Fatalf("re-delete SP = %d, want 404", code)
	}

	// RADIUS: NAS secret shown once, sealed at rest.
	appRADIUS := mkapp("prov-vpn", "radius")
	code, body = doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/radius/clients", map[string]any{
		"application_id": appRADIUS, "nas_identifier": "10.99.99.1",
	})
	if code != 201 {
		t.Fatalf("register NAS = %d (%v)", code, body)
	}
	nasSecret, _ := body["shared_secret"].(string)
	if len(nasSecret) != 32 {
		t.Fatalf("NAS secret len = %d, want 32", len(nasSecret))
	}
	if code, _ := doJSON(t, r, http.MethodPost, fx.srv.URL+"/api/admin/radius/clients", map[string]any{
		"application_id": appRADIUS, "nas_identifier": "not-an-ip",
	}); code != 400 {
		t.Fatalf("hostname NAS = %d, want 400", code)
	}
	if code, _ := doJSON(t, r, http.MethodDelete, fx.srv.URL+"/api/admin/radius/clients/10.99.99.1", nil); code != 204 {
		t.Fatalf("delete NAS = %d, want 204", code)
	}

	// Partial app PATCH (docs/INTEGRATION.md §6): omitted keys keep
	// their values, so flipping per-app MFA needs one key only.
	if code, body := doJSON(t, r, http.MethodPatch, fx.srv.URL+"/api/admin/apps/"+appOIDC, map[string]any{
		"mfa_required": true,
	}); code != 200 {
		t.Fatalf("partial PATCH app = %d (%v), want 200", code, body)
	} else {
		app, _ := body["app"].(map[string]any)
		slug, _ := app["slug"].(string)
		if app["mfa_required"] != true || !strings.HasPrefix(slug, "prov-wiki-") {
			t.Fatalf("partial PATCH lost stored values: %v", app)
		}
	}

	// Guards: a plain user registers nothing.
	bob := fx.mkuser("prov-bob")
	b := fx.browser()
	if code, _ := fx.login(b, bob.Username); code != 200 {
		t.Fatalf("bob login = %d", code)
	}
	if code, _ := doJSON(t, b, http.MethodPost, fx.srv.URL+"/api/admin/oidc/clients", map[string]any{
		"application_id": appOIDC, "redirect_uris": []string{"https://x.example.com/cb"},
	}); code != 403 {
		t.Fatalf("non-admin OIDC register = %d, want 403", code)
	}
}
