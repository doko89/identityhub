//go:build integration

// SAML IdP end-to-end tests against real Postgres (TECH_SPEC §9): IdP
// metadata, SP-initiated SSO (Redirect + signed POST bindings) against a
// real crewjam/saml service provider, IdP-initiated SSO, single logout,
// and rejection paths. Assertions are parsed and signature-verified by
// the SP, exactly like a production peer.
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5434/identityhub \
//	  go test -tags=integration ./internal/delivery/http/ -run TestSAML
package http

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	csaml "github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	adaptercrypto "github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/adapter/postgres"
	adaptersaml "github.com/identityhub/identityhub/internal/adapter/saml"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
	usecasesamlflow "github.com/identityhub/identityhub/internal/usecase/samlflow"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
)

type samlFixture struct {
	t        *testing.T
	srv      *httptest.Server
	pool     *pgxpool.Pool
	anon     *http.Client
	browser  *http.Client
	alice    domain.User
	password string
	sp       *csaml.ServiceProvider
	entityID string
	issuer   string
}

func setupSAMLFixture(t *testing.T) *samlFixture {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}
	if err := postgres.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)

	users := postgres.NewUserRepository(db)
	groups := postgres.NewGroupRepository(db)
	auditRepo := postgres.NewAuditRepository(db)
	passwords := postgres.NewPasswordRepository(db)
	registry := postgres.NewSessionRegistryRepository(db)
	samlSPs := postgres.NewSAMLSPRepository(db)
	samlRequests := postgres.NewSAMLRequestRepository(db)
	audits := usecaseaudit.New(auditRepo, nil)

	authSvc, err := usecaseauth.New(usecaseauth.Deps{
		Users: users, Groups: groups, Resets: passwords, History: passwords,
		Sessions: registry, Audit: audits, Hasher: adaptercrypto.Hasher{},
		Mailer: nullMailer{}, BaseURL: testIssuer(),
	})
	if err != nil {
		t.Fatalf("wire auth: %v", err)
	}
	userSvc, err := usecaseuser.New(usecaseuser.Deps{
		Users: users, Groups: groups, Sessions: registry, Audit: audits, Hasher: adaptercrypto.Hasher{},
	})
	if err != nil {
		t.Fatalf("wire user: %v", err)
	}
	flowSvc, err := usecasesamlflow.New(usecasesamlflow.Deps{
		SPs: samlSPs, Groups: groups,
	})
	if err != nil {
		t.Fatalf("wire samlflow: %v", err)
	}
	provider, err := adaptersaml.New(ctx, db.Pool, samlSPs, adaptersaml.Config{
		Issuer: testIssuer(),
	})
	if err != nil {
		t.Fatalf("wire saml: %v", err)
	}

	sessions := NewSessionManager(db.Pool, SessionConfig{
		IdleTimeout: 30 * time.Minute, Lifetime: 12 * time.Hour,
	})
	handlers := NewHandlers(HandlerDeps{
		Sessions: sessions, Registry: registry, Auth: authSvc, Users: userSvc,
		Audits: audits, Groups: groups,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		SAML:         provider,
		SAMLFlow:     flowSvc,
		SAMLRequests: samlRequests,
		SAMLSPs:      samlSPs,
	})
	srv := httptest.NewServer(NewRouter(Deps{Sessions: sessions, DB: db, Handlers: handlers}))
	t.Cleanup(srv.Close)

	tag := uuid.NewString()[:8]
	password := "integration-test-password-1"
	hash, err := adaptercrypto.Hasher{}.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	alice, err := users.Create(ctx, domain.User{
		Username: "saml-alice-" + tag, Email: "saml-alice-" + tag + "@example.com",
		DisplayName: "SAML Alice", PasswordHash: hash,
		Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	eng, err := groups.Create(ctx, domain.Group{Name: "saml-eng-" + tag})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := groups.AddMember(ctx, alice.ID, eng.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	fx := &samlFixture{
		t: t, srv: srv, pool: db.Pool, alice: alice, password: password,
		issuer:  testIssuer(),
		anon:    noRedirectClient(nil),
		browser: noRedirectClient(jar),
	}
	fx.sp, fx.entityID = fx.seedSP(ctx, samlSPs, tag)
	fx.login()
	return fx
}

// seedSP builds a real crewjam service provider (fresh RSA key), imports
// its metadata through the production ParseSPMetadata path, and points it
// at the IdP metadata served by the test server.
func (fx *samlFixture) seedSP(ctx context.Context, repo *postgres.SAMLSPRepository, tag string) (*csaml.ServiceProvider, string) {
	fx.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fx.t.Fatalf("generate SP key: %v", err)
	}
	cert := selfSignedTestCert(fx.t, key, "IT SP "+tag)
	entityID := "https://sp.it.example.com/" + tag + "/metadata"
	acsURL, _ := url.Parse("https://sp.it.example.com/" + tag + "/acs")
	sloURL, _ := url.Parse("https://sp.it.example.com/" + tag + "/slo")
	metaURL, _ := url.Parse(entityID)
	sp := &csaml.ServiceProvider{
		EntityID:        entityID,
		Key:             key,
		Certificate:     cert,
		MetadataURL:     *metaURL,
		AcsURL:          *acsURL,
		SloURL:          *sloURL,
		SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		LogoutBindings:  []string{csaml.HTTPRedirectBinding, csaml.HTTPPostBinding},
	}
	// The signing KeyDescriptor is emitted only when the SP signs; the
	// registered cert then verifies both Redirect and enveloped
	// signatures. Cleared afterwards so unsigned tests stay unsigned.
	md := sp.Metadata()
	sp.SignatureMethod = ""
	raw, err := xml.Marshal(md)
	if err != nil {
		fx.t.Fatalf("marshal SP metadata: %v", err)
	}
	parsed, err := adaptersaml.ParseSPMetadata(string(raw))
	if err != nil {
		fx.t.Fatalf("ParseSPMetadata: %v", err)
	}
	appID := uuid.New()
	if _, err := fx.pool.Exec(ctx, `INSERT INTO applications (id, slug, name, provider_type)
		VALUES ($1,$2,$3,'saml')`, appID, "it-saml-"+tag, "IT SAML "+tag); err != nil {
		fx.t.Fatalf("seed application: %v", err)
	}
	if parsed.CertPEM == "" {
		fx.t.Fatal("seeded SP metadata has no signing certificate")
	}
	if parsed.SLOURL == "" {
		fx.t.Fatal("seeded SP metadata has no SLO endpoint")
	}
	parsed.ApplicationID = appID
	if _, err := repo.Create(ctx, parsed); err != nil {
		fx.t.Fatalf("seed SP: %v", err)
	}
	// The SP pins the IdP exactly like a production peer: metadata fetch.
	resp, err := fx.anon.Get(fx.srv.URL + "/saml/metadata")
	if err != nil {
		fx.t.Fatalf("fetch IdP metadata: %v", err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fx.t.Fatalf("metadata status = %d", resp.StatusCode)
	}
	var idpMD csaml.EntityDescriptor
	if err := xml.Unmarshal(raw, &idpMD); err != nil {
		fx.t.Fatalf("parse IdP metadata: %v", err)
	}
	sp.IDPMetadata = &idpMD
	return sp, entityID
}

func selfSignedTestCert(t *testing.T, key *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func (fx *samlFixture) login() {
	fx.t.Helper()
	body, _ := json.Marshal(map[string]string{"username": fx.alice.Username, "password": fx.password})
	resp, err := fx.browser.Post(fx.srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fx.t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		fx.t.Fatalf("login status = %d, want 200 (%s)", resp.StatusCode, raw)
	}
}

// redirectAuthn builds an SP-initiated AuthnRequest for the Redirect
// binding. The request addresses the configured IdP SSO URL (Destination
// check), but the returned query is delivered to the httptest server.
func (fx *samlFixture) redirectAuthn(relayState string) (*csaml.AuthnRequest, string) {
	fx.t.Helper()
	req, err := fx.sp.MakeAuthenticationRequest(fx.issuer+"/saml/sso", csaml.HTTPRedirectBinding, csaml.HTTPPostBinding)
	if err != nil {
		fx.t.Fatalf("MakeAuthenticationRequest: %v", err)
	}
	u, err := req.Redirect(relayState, fx.sp)
	if err != nil {
		fx.t.Fatalf("Redirect: %v", err)
	}
	return req, u.RawQuery
}

// postAuthn builds an SP-initiated AuthnRequest for the POST binding and
// returns its form fields.
func (fx *samlFixture) postAuthn(signed bool, relayState string) (*csaml.AuthnRequest, url.Values) {
	fx.t.Helper()
	req, err := fx.sp.MakeAuthenticationRequest(fx.issuer+"/saml/sso", csaml.HTTPPostBinding, csaml.HTTPPostBinding)
	if err != nil {
		fx.t.Fatalf("MakeAuthenticationRequest: %v", err)
	}
	if signed {
		fx.sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		if err := fx.sp.SignAuthnRequest(req); err != nil {
			fx.t.Fatalf("SignAuthnRequest: %v", err)
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		fx.t.Fatalf("serialize AuthnRequest: %v", err)
	}
	return req, url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(raw)},
		"RelayState":  {relayState},
	}
}

var samlFormField = regexp.MustCompile(`<input type="hidden" name="(SAMLResponse|RelayState)" value="([^"]*)"`)

// responseFromForm extracts and decodes the SAMLResponse (+RelayState echo)
// from the IdP's auto-submit form.
func responseFromForm(t *testing.T, formHTML string) (responseXML []byte, relayState string) {
	t.Helper()
	fields := map[string]string{}
	for _, m := range samlFormField.FindAllStringSubmatch(formHTML, -1) {
		fields[m[1]] = m[2]
	}
	enc, ok := fields["SAMLResponse"]
	if !ok {
		t.Fatalf("SSO form has no SAMLResponse:\n%s", formHTML)
	}
	// The form is rendered with html/template: attribute values are
	// HTML-escaped (a browser unescapes before submit; we do it by hand).
	raw, err := base64.StdEncoding.DecodeString(html.UnescapeString(enc))
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	return raw, html.UnescapeString(fields["RelayState"])
}

// challengeFromLogin parses the stashed-request challenge out of a
// /login?next=/saml/sso?challenge=... redirect.
func challengeFromLogin(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse login redirect: %v", err)
	}
	next, err := url.Parse(u.Query().Get("next"))
	if err != nil {
		t.Fatalf("parse next target: %v", err)
	}
	ch := next.Query().Get("challenge")
	if ch == "" {
		t.Fatalf("login redirect has no challenge: %q", loc)
	}
	return ch
}

func getBody(t *testing.T, c *http.Client, target string) (int, http.Header, string) {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header, string(raw)
}

func TestSAMLMetadata(t *testing.T) {
	fx := setupSAMLFixture(t)
	status, header, body := getBody(t, fx.anon, fx.srv.URL+"/saml/metadata")
	if status != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200", status)
	}
	if ct := header.Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Fatalf("Content-Type = %q", ct)
	}
	var md csaml.EntityDescriptor
	if err := xml.Unmarshal([]byte(body), &md); err != nil {
		t.Fatalf("parse metadata: %v", err)
	}
	if md.EntityID != fx.issuer+"/saml/metadata" {
		t.Fatalf("entityID = %q", md.EntityID)
	}
	if len(md.IDPSSODescriptors) != 1 {
		t.Fatalf("IDPSSODescriptors = %d, want 1", len(md.IDPSSODescriptors))
	}
	desc := md.IDPSSODescriptors[0]
	var sso, slo bool
	for _, ep := range desc.SingleSignOnServices {
		if ep.Location == fx.issuer+"/saml/sso" {
			sso = true
		}
	}
	for _, ep := range desc.SingleLogoutServices {
		if ep.Location == fx.issuer+"/saml/slo" {
			slo = true
		}
	}
	if !sso || !slo {
		t.Fatalf("metadata SSO/SLO endpoints missing:\n%s", body)
	}
	if len(desc.KeyDescriptors) == 0 {
		t.Fatal("metadata has no signing KeyDescriptor")
	}
}

// TestSAMLSSORedirectFlow is the M3 proof: one real SP (crewjam/saml)
// passes SP-initiated SSO end to end — AuthnRequest, login redirect,
// signed Response, SP-side signature verification, NameID and attributes.
func TestSAMLSSORedirectFlow(t *testing.T) {
	fx := setupSAMLFixture(t)
	req, query := fx.redirectAuthn("relay-redirect-1")

	// 1. Anonymous browser hits SSO → bounced to login with a challenge.
	status, header, _ := getBody(t, fx.anon, fx.srv.URL+"/saml/sso?"+query)
	if status != http.StatusFound {
		t.Fatalf("anon SSO status = %d, want 302", status)
	}
	challenge := challengeFromLogin(t, header.Get("Location"))

	// 2. Logged-in browser replays the challenge → signed Response form.
	status, _, html := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?challenge="+challenge)
	if status != http.StatusOK {
		t.Fatalf("challenge SSO status = %d, want 200:\n%s", status, html)
	}
	raw, relay := responseFromForm(t, html)
	if relay != "relay-redirect-1" {
		t.Fatalf("RelayState = %q, want echo of relay-redirect-1", relay)
	}

	// 3. The SP verifies signature, audience, destination and InResponseTo.
	assertion, err := fx.sp.ParseXMLResponse(raw, []string{req.ID}, fx.sp.AcsURL)
	if err != nil {
		t.Fatalf("SP rejected the Response: %v", err)
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		t.Fatal("assertion has no Subject/NameID")
	}
	if got := assertion.Subject.NameID.Value; got != fx.alice.Username {
		t.Fatalf("NameID = %q, want username %q", got, fx.alice.Username)
	}
	attrs := map[string][]string{}
	for _, stmt := range assertion.AttributeStatements {
		for _, a := range stmt.Attributes {
			for _, v := range a.Values {
				attrs[a.Name] = append(attrs[a.Name], v.Value)
			}
		}
	}
	if len(attrs["email"]) != 1 || attrs["email"][0] != fx.alice.Email {
		t.Fatalf("email attr = %v, want [%s]", attrs["email"], fx.alice.Email)
	}
	if len(attrs["displayName"]) != 1 || attrs["displayName"][0] != fx.alice.DisplayName {
		t.Fatalf("displayName attr = %v", attrs["displayName"])
	}
	groupSet := map[string]bool{}
	for _, g := range attrs["groups"] {
		groupSet[g] = true
	}
	if !strings.Contains(fx.alice.Username, "saml-alice-") || !groupSet["saml-eng-"+fx.alice.Username[len("saml-alice-"):]] {
		t.Fatalf("groups attr = %v, want the eng group", attrs["groups"])
	}

	// 4. Wrong request ID fails closed (InResponseTo is enforced).
	if _, err := fx.sp.ParseXMLResponse(raw, []string{"id-bogus"}, fx.sp.AcsURL); err == nil {
		t.Fatal("SP accepted a Response for an unknown request ID")
	}

	// 5. A tampered assertion fails signature verification.
	tampered := bytes.Replace(raw, []byte(fx.alice.Username), []byte("mallory-x"), 1)
	if _, err := fx.sp.ParseXMLResponse(tampered, []string{req.ID}, fx.sp.AcsURL); err == nil {
		t.Fatal("SP accepted a tampered Response")
	}

	// 6. The challenge is single-use: replaying it is gone.
	status, _, _ = getBody(t, fx.browser, fx.srv.URL+"/saml/sso?challenge="+challenge)
	if status != http.StatusGone {
		t.Fatalf("replayed challenge status = %d, want 410", status)
	}

	// 7. The login is audited with method=saml.
	var n int
	if err := fx.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE method='saml' AND result='success' AND detail->>'action'='sso'`).Scan(&n); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if n < 1 {
		t.Fatal("no successful saml/sso audit row found")
	}
}

func TestSAMLSSOPostFlow(t *testing.T) {
	fx := setupSAMLFixture(t)
	for _, signed := range []bool{false, true} {
		name := "unsigned"
		if signed {
			name = "signed"
		}
		t.Run(name, func(t *testing.T) {
			req, form := fx.postAuthn(signed, "relay-post-"+name)
			resp, err := fx.browser.PostForm(fx.srv.URL+"/saml/sso", form)
			if err != nil {
				t.Fatalf("POST SSO: %v", err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// Already logged in: the Response form comes back directly.
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("POST SSO status = %d, want 200:\n%s", resp.StatusCode, raw)
			}
			responseXML, relay := responseFromForm(t, string(raw))
			if relay != "relay-post-"+name {
				t.Fatalf("RelayState = %q", relay)
			}
			assertion, err := fx.sp.ParseXMLResponse(responseXML, []string{req.ID}, fx.sp.AcsURL)
			if err != nil {
				t.Fatalf("SP rejected the Response: %v", err)
			}
			if assertion.Subject.NameID.Value != fx.alice.Username {
				t.Fatalf("NameID = %q", assertion.Subject.NameID.Value)
			}
		})
	}
}

func TestSAMLSSOAnonymousPOSTStash(t *testing.T) {
	fx := setupSAMLFixture(t)
	// Anonymous POST: the body is stashed, the browser logs in, the
	// challenge replays the exact bytes.
	_, form := fx.postAuthn(false, "relay-stash-1")
	anonJar, _ := cookiejar.New(nil)
	anonBrowser := noRedirectClient(anonJar)
	resp, err := anonBrowser.PostForm(fx.srv.URL+"/saml/sso", form)
	if err != nil {
		t.Fatalf("POST SSO: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anon POST status = %d, want 302", resp.StatusCode)
	}
	challenge := challengeFromLogin(t, resp.Header.Get("Location"))
	// Log the anonymous browser in, then replay.
	body, _ := json.Marshal(map[string]string{"username": fx.alice.Username, "password": fx.password})
	resp, err = anonBrowser.Post(fx.srv.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	status, _, html := getBody(t, anonBrowser, fx.srv.URL+"/saml/sso?challenge="+challenge)
	if status != http.StatusOK {
		t.Fatalf("stashed POST replay status = %d:\n%s", status, html)
	}
	if _, relay := responseFromForm(t, html); relay != "relay-stash-1" {
		t.Fatalf("RelayState = %q", relay)
	}
}

func TestSAMLSSOSignedRedirectAndTamper(t *testing.T) {
	fx := setupSAMLFixture(t)
	fx.sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	req, query := fx.redirectAuthn("relay-signed-1")
	if !strings.Contains(query, "Signature=") {
		t.Fatalf("signed request has no Signature param: %q", query)
	}
	// Valid signed request passes.
	status, _, html := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?"+query)
	if status != http.StatusOK {
		t.Fatalf("signed SSO status = %d:\n%s", status, html)
	}
	if _, err := fx.sp.ParseXMLResponse(mustResponse(t, html), []string{req.ID}, fx.sp.AcsURL); err != nil {
		t.Fatalf("SP rejected signed-flow Response: %v", err)
	}
	// Tampered signature fails closed.
	v, _ := url.ParseQuery(query)
	v.Set("Signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	status, _, _ = getBody(t, fx.browser, fx.srv.URL+"/saml/sso?"+v.Encode())
	if status != http.StatusBadRequest {
		t.Fatalf("tampered signature status = %d, want 400", status)
	}
}

func mustResponse(t *testing.T, html string) []byte {
	t.Helper()
	raw, _ := responseFromForm(t, html)
	return raw
}

// inflateLogoutResponse decodes a Redirect-binding LogoutResponse payload
// (base64 of DEFLATE-compressed XML, saml-bindings §3.4.4.1).
func inflateLogoutResponse(t *testing.T, raw []byte) []byte {
	t.Helper()
	r := flate.NewReader(bytes.NewReader(raw))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxSAMLRequestBytes))
	if err != nil {
		t.Fatalf("inflate LogoutResponse: %v", err)
	}
	return out
}

func TestSAMLIdPInitiated(t *testing.T) {
	fx := setupSAMLFixture(t)
	fx.sp.AllowIDPInitiated = true
	target := fx.srv.URL + "/saml/sso?sp=" + url.QueryEscape(fx.entityID) + "&RelayState=relay-idp-1"
	status, _, html := getBody(t, fx.browser, target)
	if status != http.StatusOK {
		t.Fatalf("idp-initiated status = %d:\n%s", status, html)
	}
	raw, relay := responseFromForm(t, html)
	if relay != "relay-idp-1" {
		t.Fatalf("RelayState = %q", relay)
	}
	// Unolicited: no request ID to match.
	assertion, err := fx.sp.ParseXMLResponse(raw, []string{}, fx.sp.AcsURL)
	if err != nil {
		t.Fatalf("SP rejected unsolicited Response: %v", err)
	}
	if assertion.Subject.NameID.Value != fx.alice.Username {
		t.Fatalf("NameID = %q", assertion.Subject.NameID.Value)
	}
	// Unknown SP fails closed.
	status, _, _ = getBody(t, fx.browser, fx.srv.URL+"/saml/sso?sp="+url.QueryEscape("https://evil.example.com/x"))
	if status != http.StatusBadRequest {
		t.Fatalf("unknown sp status = %d, want 400", status)
	}
}

func TestSAMLSLO(t *testing.T) {
	fx := setupSAMLFixture(t)
	fx.sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	// Sanity: the session is live before logout.
	status, _, _ := getBody(t, fx.browser, fx.srv.URL+"/api/auth/me")
	if status != http.StatusOK {
		t.Fatalf("pre-logout /me status = %d", status)
	}
	lr, err := fx.sp.MakeLogoutRequest(fx.issuer+"/saml/slo", fx.alice.Username)
	if err != nil {
		t.Fatalf("MakeLogoutRequest: %v", err)
	}
	u, err := fx.sp.RedirectLogoutRequestURL(lr, "relay-slo-1")
	if err != nil {
		t.Fatalf("RedirectLogoutRequestURL: %v", err)
	}
	status, header, _ := getBody(t, fx.browser, fx.srv.URL+"/saml/slo?"+u.RawQuery)
	if status != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302 to the SP SLO endpoint", status)
	}
	loc, err := url.Parse(header.Get("Location"))
	if err != nil {
		t.Fatalf("parse SLO redirect: %v", err)
	}
	enc := loc.Query().Get("SAMLResponse")
	if enc == "" || !strings.HasPrefix(loc.String(), fx.sp.SloURL.String()) {
		t.Fatalf("SLO redirect = %q, want SAMLResponse to the SP SLO endpoint", loc.String())
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("decode LogoutResponse: %v", err)
	}
	var lr2 csaml.LogoutResponse
	if err := xml.Unmarshal(inflateLogoutResponse(t, raw), &lr2); err != nil {
		t.Fatalf("parse LogoutResponse: %v", err)
	}
	if lr2.Status.StatusCode.Value != csaml.StatusSuccess {
		t.Fatalf("logout status = %q, want success", lr2.Status.StatusCode.Value)
	}
	if lr2.InResponseTo != lr.ID {
		t.Fatalf("InResponseTo = %q, want %q", lr2.InResponseTo, lr.ID)
	}
	// The local session is gone.
	status, _, _ = getBody(t, fx.browser, fx.srv.URL+"/api/auth/me")
	if status != http.StatusUnauthorized {
		t.Fatalf("post-logout /me status = %d, want 401", status)
	}
	// Bare SLO (IdP-initiated local logout) lands home.
	fx.login()
	status, header, _ = getBody(t, fx.browser, fx.srv.URL+"/saml/slo")
	if status != http.StatusFound || header.Get("Location") != "/" {
		t.Fatalf("bare SLO = %d %q, want 302 /", status, header.Get("Location"))
	}
	status, _, _ = getBody(t, fx.browser, fx.srv.URL+"/api/auth/me")
	if status != http.StatusUnauthorized {
		t.Fatalf("post-logout /me status = %d, want 401", status)
	}
}

func TestSAMLRejects(t *testing.T) {
	fx := setupSAMLFixture(t)
	t.Run("unknown issuer", func(t *testing.T) {
		other := *fx.sp
		other.EntityID = "https://unknown.example.com/metadata"
		req, err := other.MakeAuthenticationRequest(fx.issuer+"/saml/sso", csaml.HTTPRedirectBinding, csaml.HTTPPostBinding)
		if err != nil {
			t.Fatalf("MakeAuthenticationRequest: %v", err)
		}
		u, err := req.Redirect("r", &other)
		if err != nil {
			t.Fatalf("Redirect: %v", err)
		}
		status, _, _ := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?"+u.RawQuery)
		if status != http.StatusBadRequest {
			t.Fatalf("unknown issuer status = %d, want 400", status)
		}
	})
	t.Run("acs mismatch", func(t *testing.T) {
		other := *fx.sp
		evil, _ := url.Parse("https://evil.example.com/acs")
		other.AcsURL = *evil
		req, err := other.MakeAuthenticationRequest(fx.issuer+"/saml/sso", csaml.HTTPRedirectBinding, csaml.HTTPPostBinding)
		if err != nil {
			t.Fatalf("MakeAuthenticationRequest: %v", err)
		}
		u, err := req.Redirect("r", &other)
		if err != nil {
			t.Fatalf("Redirect: %v", err)
		}
		status, _, _ := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?"+u.RawQuery)
		if status != http.StatusBadRequest {
			t.Fatalf("acs mismatch status = %d, want 400", status)
		}
	})
	t.Run("expired challenge", func(t *testing.T) {
		status, _, _ := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?challenge="+strings.Repeat("a", 64))
		if status != http.StatusGone {
			t.Fatalf("expired challenge status = %d, want 410", status)
		}
	})
	t.Run("passive without session", func(t *testing.T) {
		req, err := fx.sp.MakeAuthenticationRequest(fx.issuer+"/saml/sso", csaml.HTTPRedirectBinding, csaml.HTTPPostBinding)
		if err != nil {
			t.Fatalf("MakeAuthenticationRequest: %v", err)
		}
		passive := true
		req.IsPassive = &passive
		u, err := req.Redirect("r-passive", fx.sp)
		if err != nil {
			t.Fatalf("Redirect: %v", err)
		}
		status, _, html := getBody(t, fx.anon, fx.srv.URL+"/saml/sso?"+u.RawQuery)
		// No login redirect: an error Response form instead.
		if status != http.StatusOK {
			t.Fatalf("passive status = %d, want 200 with error Response", status)
		}
		raw, _ := responseFromForm(t, html)
		var resp csaml.Response
		if err := xml.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("parse error Response: %v", err)
		}
		if resp.Status.StatusCode.Value != csaml.StatusResponder ||
			resp.Status.StatusCode.StatusCode == nil ||
			resp.Status.StatusCode.StatusCode.Value != csaml.StatusNoPassive {
			t.Fatalf("passive status = %+v, want Responder/NoPassive", resp.Status)
		}
	})
	t.Run("garbage request", func(t *testing.T) {
		status, _, _ := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?SAMLRequest=!!!not-base64!!!")
		if status != http.StatusBadRequest {
			t.Fatalf("garbage status = %d, want 400", status)
		}
	})
}

func TestSAMLForceAuthn(t *testing.T) {
	fx := setupSAMLFixture(t)
	req, err := fx.sp.MakeAuthenticationRequest(fx.issuer+"/saml/sso", csaml.HTTPRedirectBinding, csaml.HTTPPostBinding)
	if err != nil {
		t.Fatalf("MakeAuthenticationRequest: %v", err)
	}
	force := true
	req.ForceAuthn = &force
	u, err := req.Redirect("r-force", fx.sp)
	if err != nil {
		t.Fatalf("Redirect: %v", err)
	}
	// Logged in, but ForceAuthn drops the session and re-prompts login.
	status, header, _ := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?"+u.RawQuery)
	if status != http.StatusFound {
		t.Fatalf("forceauthn status = %d, want 302", status)
	}
	challenge := challengeFromLogin(t, header.Get("Location"))
	status, _, _ = getBody(t, fx.browser, fx.srv.URL+"/api/auth/me")
	if status != http.StatusUnauthorized {
		t.Fatalf("session should be destroyed, /me = %d", status)
	}
	// Fresh login completes the stashed request.
	fx.login()
	status, _, html := getBody(t, fx.browser, fx.srv.URL+"/saml/sso?challenge="+challenge)
	if status != http.StatusOK {
		t.Fatalf("post-login SSO status = %d:\n%s", status, html)
	}
	if _, err := fx.sp.ParseXMLResponse(mustResponse(t, html), []string{req.ID}, fx.sp.AcsURL); err != nil {
		t.Fatalf("SP rejected post-ForceAuthn Response: %v", err)
	}
}
