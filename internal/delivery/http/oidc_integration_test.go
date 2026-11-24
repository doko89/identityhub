//go:build integration

// OIDC provider end-to-end tests against real Postgres (TECH_SPEC §9):
// discovery/JWKS, authorization-code + PKCE for a public client,
// code flow for a confidential client, refresh rotation, consent
// remember/deny, and claim verification against the JWKS.
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5434/identityhub \
//	  go test -tags=integration ./internal/delivery/http/ -run TestOIDC
package http

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	adaptercrypto "github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/adapter/oidc"
	"github.com/identityhub/identityhub/internal/adapter/postgres"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
	usecaseoidcflow "github.com/identityhub/identityhub/internal/usecase/oidcflow"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
)

// RFC 7636 Appendix B test vector.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

type oidcFixture struct {
	t        *testing.T
	srv      *httptest.Server
	pool     *pgxpool.Pool
	anon     *http.Client // no redirects, no session
	browser  *http.Client // no redirects, session jar (logged in as alice)
	alice    domain.User
	password string
	pub      clientSeed
	conf     clientSeed
	issuer   string
}

type clientSeed struct {
	clientID    string
	redirectURI string
	secret      string // "" for public clients
}

type nullMailer struct{}

func (nullMailer) Send(_, _, _, _ string) error { return nil }

func testIssuer() string { return "http://127.0.0.1:18199" }

func setupOIDCFixture(t *testing.T) *oidcFixture {
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
	oidcClients := postgres.NewOIDCClientRepository(db)
	consents := postgres.NewOIDCConsentRepository(db)
	challenges := postgres.NewOIDCChallengeRepository(db)
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
	flowSvc, err := usecaseoidcflow.New(usecaseoidcflow.Deps{
		Clients: oidcClients, Groups: groups, Consents: consents,
	})
	if err != nil {
		t.Fatalf("wire oidcflow: %v", err)
	}
	provider, err := oidc.New(ctx, db.Pool, oidcClients, oidc.Config{
		Issuer: testIssuer(),
		// Fixed 32-byte HMAC secret for deterministic test runs.
		GlobalSecret: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("wire oidc: %v", err)
	}

	sessions := NewSessionManager(db.Pool, SessionConfig{
		IdleTimeout: 30 * time.Minute, Lifetime: 12 * time.Hour,
	})
	handlers := NewHandlers(HandlerDeps{
		Sessions: sessions, Registry: registry, Auth: authSvc, Users: userSvc,
		Audits: audits, Groups: groups,
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		OIDC: provider, OIDCFlow: flowSvc, Challenges: challenges, OIDCClients: oidcClients,
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
		Username: "oidc-alice-" + tag, Email: "oidc-alice-" + tag + "@example.com",
		DisplayName: "OIDC Alice", PasswordHash: hash,
		Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	eng, err := groups.Create(ctx, domain.Group{Name: "oidc-eng-" + tag})
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
	fx := &oidcFixture{
		t: t, srv: srv, pool: db.Pool, alice: alice, password: password, issuer: testIssuer(),
		anon:    noRedirectClient(nil),
		browser: noRedirectClient(jar),
	}
	fx.pub = fx.seedClient(ctx, oidcClients, tag, "pub", true)
	fx.conf = fx.seedClient(ctx, oidcClients, tag, "conf", false)
	fx.login()
	return fx
}

func noRedirectClient(jar http.CookieJar) *http.Client {
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if jar != nil {
		c.Jar = jar
	}
	return c
}

// seedClient inserts an application row plus its oidc_client. Public
// clients carry no secret hash (PKCE-only); confidential ones get a
// bcrypt hash of "test-secret-<tag>".
func (fx *oidcFixture) seedClient(ctx context.Context, repo *postgres.OIDCClientRepository, tag, kind string, public bool) clientSeed {
	fx.t.Helper()
	seed := clientSeed{
		clientID:    "it-" + kind + "-" + tag,
		redirectURI: "http://127.0.0.1:18099/callback-" + kind + "-" + tag,
	}
	appID := uuid.New()
	if _, err := fx.pool.Exec(ctx, `INSERT INTO applications (id, slug, name, provider_type)
		VALUES ($1,$2,$3,'oidc')`, appID, "it-"+kind+"-"+tag, "IT "+kind+" "+tag); err != nil {
		fx.t.Fatalf("seed application: %v", err)
	}
	c := domain.OIDCClient{
		ApplicationID: appID, ClientID: seed.clientID,
		RedirectURIs: []string{seed.redirectURI},
		Scopes:       []string{"openid", "profile", "email", "groups", "offline_access"},
	}
	if !public {
		seed.secret = "test-secret-" + tag
		hash, err := oidc.HashClientSecret(seed.secret)
		if err != nil {
			fx.t.Fatalf("hash client secret: %v", err)
		}
		c.ClientSecretHash = hash
	}
	if _, err := repo.Create(ctx, c); err != nil {
		fx.t.Fatalf("seed client: %v", err)
	}
	return seed
}

func (fx *oidcFixture) login() {
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

// authorizeURL builds an authorize request for seed with PKCE.
func (fx *oidcFixture) authorizeURL(seed clientSeed, state string, pkce bool) string {
	q := url.Values{
		"client_id":     {seed.clientID},
		"redirect_uri":  {seed.redirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile email groups offline_access"},
		"state":         {state},
	}
	if pkce {
		q.Set("code_challenge", pkceChallenge)
		q.Set("code_challenge_method", "S256")
	}
	return fx.srv.URL + "/oauth2/auth?" + q.Encode()
}

// authorizeConsent runs authorize → consent grant and returns the code.
func (fx *oidcFixture) authorizeConsent(state string, seed clientSeed, pkce bool) string {
	fx.t.Helper()
	resp, err := fx.browser.Get(fx.authorizeURL(seed, state, pkce))
	if err != nil {
		fx.t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	// Consent redirect is our 302; fosite answers successful issuance
	// with 303 See Other.
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		raw, _ := io.ReadAll(resp.Body)
		fx.t.Fatalf("authorize status = %d, want 302/303 (%s)", resp.StatusCode, raw)
	}
	loc := resp.Header.Get("Location")
	if strings.HasPrefix(loc, "/consent?challenge=") {
		redirectTo := fx.grant(loc, seed, true)
		return fx.codeFromRedirect(redirectTo, state)
	}
	// Remembered consent: straight to the client.
	return fx.codeFromRedirect(loc, state)
}

// grant completes the consent API round trip and returns redirect_to.
func (fx *oidcFixture) grant(consentLoc string, seed clientSeed, grant bool) string {
	fx.t.Helper()
	done := fx.grantJSON(consentLoc, seed, grant)
	if done["redirect_to"] == "" {
		fx.t.Fatalf("consent post has no redirect_to: %v", done)
	}
	return done["redirect_to"]
}

// grantJSON completes the consent API round trip and returns the decoded
// POST body (redirect_to for redirect modes, form_post HTML for
// response_mode=form_post).
func (fx *oidcFixture) grantJSON(consentLoc string, seed clientSeed, grant bool) map[string]string {
	fx.t.Helper()
	u, err := url.Parse(consentLoc)
	if err != nil {
		fx.t.Fatalf("parse consent location: %v", err)
	}
	challenge := u.Query().Get("challenge")
	if challenge == "" {
		fx.t.Fatalf("consent location has no challenge: %q", consentLoc)
	}
	resp, err := fx.browser.Get(fx.srv.URL + "/api/oidc/consent?challenge=" + challenge)
	if err != nil {
		fx.t.Fatalf("consent get: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fx.t.Fatalf("consent get status = %d (%s)", resp.StatusCode, raw)
	}
	var info struct {
		ClientID   string   `json:"client_id"`
		ClientName string   `json:"client_name"`
		Scopes     []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		fx.t.Fatalf("consent get decode: %v", err)
	}
	if info.ClientID != seed.clientID || len(info.Scopes) == 0 {
		fx.t.Fatalf("consent info = %+v, want client %q with scopes", info, seed.clientID)
	}
	post, _ := json.Marshal(map[string]any{"challenge": challenge, "grant": grant})
	resp, err = fx.browser.Post(fx.srv.URL+"/api/oidc/consent", "application/json", bytes.NewReader(post))
	if err != nil {
		fx.t.Fatalf("consent post: %v", err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fx.t.Fatalf("consent post status = %d (%s)", resp.StatusCode, raw)
	}
	var done map[string]string
	if err := json.Unmarshal(raw, &done); err != nil {
		fx.t.Fatalf("consent post decode: %v", err)
	}
	return done
}

func (fx *oidcFixture) codeFromRedirect(loc, state string) string {
	fx.t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		fx.t.Fatalf("parse redirect: %v", err)
	}
	if u.Query().Get("state") != state {
		fx.t.Fatalf("state = %q, want %q (redirect %q)", u.Query().Get("state"), state, loc)
	}
	code := u.Query().Get("code")
	if code == "" {
		fx.t.Fatalf("no code in redirect %q", loc)
	}
	return code
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
}

// token posts to /oauth2/token; secret=="" sends no client auth.
func (fx *oidcFixture) token(seed clientSeed, form url.Values, secret string) (int, tokenResponse, []byte) {
	fx.t.Helper()
	form.Set("client_id", seed.clientID)
	req, _ := http.NewRequest(http.MethodPost, fx.srv.URL+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(seed.clientID), url.QueryEscape(secret))
	}
	resp, err := fx.anon.Do(req)
	if err != nil {
		fx.t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var tok tokenResponse
	_ = json.Unmarshal(raw, &tok)
	return resp.StatusCode, tok, raw
}

func (fx *oidcFixture) userinfo(accessToken string) (int, map[string]any) {
	fx.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fx.srv.URL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := fx.anon.Do(req)
	if err != nil {
		fx.t.Fatalf("userinfo request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// verifyIDToken checks the RS256 signature against the JWKS and returns
// the payload claims.
func (fx *oidcFixture) verifyIDToken(rawToken string) map[string]any {
	fx.t.Helper()
	resp, err := fx.anon.Get(fx.srv.URL + "/oauth2/jwks")
	if err != nil {
		fx.t.Fatalf("jwks: %v", err)
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		fx.t.Fatalf("jwks decode: %v", err)
	}
	if len(jwks.Keys) != 1 {
		fx.t.Fatalf("jwks keys = %d, want 1", len(jwks.Keys))
	}
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		fx.t.Fatalf("id_token has %d parts, want 3", len(parts))
	}
	var hdr struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	hdrRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		fx.t.Fatalf("token header decode: %v", err)
	}
	if hdr.Alg != "RS256" || hdr.KID != jwks.Keys[0].KID {
		fx.t.Fatalf("token header = %+v, want RS256 with jwks kid", hdr)
	}
	nRaw, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	eRaw, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	n := new(big.Int).SetBytes(nRaw)
	e := int(new(big.Int).SetBytes(eRaw).Int64())
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&rsa.PublicKey{N: n, E: e}, crypto.SHA256, digest[:], sig); err != nil {
		fx.t.Fatalf("id_token signature invalid: %v", err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		fx.t.Fatalf("claims decode: %v", err)
	}
	return claims
}

func TestOIDCDiscoveryAndJWKS(t *testing.T) {
	fx := setupOIDCFixture(t)
	resp, err := fx.anon.Get(fx.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("discovery decode: %v", err)
	}
	for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		v, _ := doc[k].(string)
		if v == "" {
			t.Fatalf("discovery[%s] empty: %v", k, doc)
		}
		if k != "issuer" && !strings.HasPrefix(v, fx.issuer) {
			t.Fatalf("discovery[%s] = %q, want issuer prefix %q", k, v, fx.issuer)
		}
	}
	if doc["issuer"] != fx.issuer {
		t.Fatalf("issuer = %v, want %q", doc["issuer"], fx.issuer)
	}
	resp, err = fx.anon.Get(fx.srv.URL + "/oauth2/jwks")
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	defer resp.Body.Close()
	var jwks map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("jwks decode: %v", err)
	}
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("jwks keys = %v, want exactly 1", jwks)
	}
	k, _ := keys[0].(map[string]any)
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["kid"] == "" || k["n"] == "" || k["e"] == "" {
		t.Fatalf("jwks key = %v, want RSA/RS256 with kid/n/e", k)
	}
}

func TestOIDCPublicClientPKCEFlow(t *testing.T) {
	fx := setupOIDCFixture(t)

	// Anonymous authorize must bounce to the login page with a return target.
	resp, err := fx.anon.Get(fx.authorizeURL(fx.pub, "state-anon-0001", true))
	if err != nil {
		t.Fatalf("anon authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("anon authorize status = %d, want 302 login", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("anon authorize Location = %q, want /login?next=...", loc)
	}

	// Wrong verifier must fail the exchange (codes are single-use, so this
	// consumes a dedicated code).
	badCode := fx.authorizeConsent("state-pub-bad-01", fx.pub, true)
	status, _, raw := fx.token(fx.pub, url.Values{
		"grant_type": {"authorization_code"}, "code": {badCode},
		"redirect_uri": {fx.pub.redirectURI}, "code_verifier": {"wrong-verifier"},
	}, "")
	if status == http.StatusOK {
		t.Fatal("code exchange with wrong verifier succeeded, want failure")
	}
	t.Logf("wrong verifier correctly rejected: %d %s", status, raw)

	// Correct verifier mints access + refresh + ID tokens.
	code := fx.authorizeConsent("state-pub-0001", fx.pub, true)
	status, tok, raw := fx.token(fx.pub, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {fx.pub.redirectURI}, "code_verifier": {pkceVerifier},
	}, "")
	if status != http.StatusOK {
		t.Fatalf("code exchange status = %d (%s)", status, raw)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.IDToken == "" {
		t.Fatalf("token response missing fields: %+v", tok)
	}
	if tok.TokenType != "bearer" {
		t.Fatalf("token_type = %q, want bearer", tok.TokenType)
	}

	claims := fx.verifyIDToken(tok.IDToken)
	if claims["sub"] != fx.alice.ID.String() {
		t.Fatalf("sub = %v, want %q", claims["sub"], fx.alice.ID)
	}
	if claims["iss"] != fx.issuer {
		t.Fatalf("iss = %v, want %q", claims["iss"], fx.issuer)
	}
	if claims["preferred_username"] != fx.alice.Username || claims["email"] != fx.alice.Email {
		t.Fatalf("id claims = %v, want alice identity", claims)
	}
	groupList, _ := claims["groups"].([]any)
	if len(groupList) != 1 || !strings.HasPrefix(groupList[0].(string), "oidc-eng-") {
		t.Fatalf("groups = %v, want [oidc-eng-*]", claims["groups"])
	}

	status, info := fx.userinfo(tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("userinfo status = %d (%v)", status, info)
	}
	if info["sub"] != fx.alice.ID.String() || info["preferred_username"] != fx.alice.Username {
		t.Fatalf("userinfo = %v, want alice claims", info)
	}
	if status, _ := fx.userinfo("bogus-token"); status != http.StatusUnauthorized {
		t.Fatalf("userinfo(bogus) status = %d, want 401", status)
	}

	// Refresh rotation: the old refresh token dies on use.
	status, tok2, raw := fx.token(fx.pub, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken},
	}, "")
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d (%s)", status, raw)
	}
	if tok2.RefreshToken == "" || tok2.AccessToken == "" {
		t.Fatalf("refresh response missing tokens: %+v", tok2)
	}
	if status, info := fx.userinfo(tok2.AccessToken); status != http.StatusOK || info["sub"] != fx.alice.ID.String() {
		t.Fatalf("userinfo(refreshed) = %d %v, want alice", status, info)
	}
	status, _, raw = fx.token(fx.pub, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken},
	}, "")
	if status == http.StatusOK {
		t.Fatal("old refresh token still works after rotation, want failure")
	}
	t.Logf("rotated refresh correctly rejected: %d %s", status, raw)

	// Code replay must fail (single-use) and revoke the grant (RFC 6819
	// reuse detection). This runs last among token checks because the
	// replay revokes tok's siblings.
	status, _, _ = fx.token(fx.pub, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {fx.pub.redirectURI}, "code_verifier": {pkceVerifier},
	}, "")
	if status == http.StatusOK {
		t.Fatal("code replay succeeded, want failure")
	}
	// The replay revokes the whole grant, including the rotated tokens.
	if status, _ := fx.userinfo(tok2.AccessToken); status != http.StatusUnauthorized {
		t.Fatalf("userinfo after code replay = %d, want 401 (grant revoked)", status)
	}

	// Remembered consent: repeat authorize skips the consent page.
	code2 := fx.authorizeConsent("state-pub-0002", fx.pub, true)
	if code2 == "" || code2 == code {
		t.Fatalf("second authorize produced no fresh code")
	}

	// Public clients must use PKCE: no challenge → authorize error redirect.
	resp, err = fx.browser.Get(fx.authorizeURL(fx.pub, "state-no-pkce-01", false))
	if err != nil {
		t.Fatalf("no-pkce authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("no-pkce authorize status = %d, want 302/303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, fx.pub.redirectURI) ||
		!strings.Contains(loc, "error=") {
		t.Fatalf("no-pkce Location = %q, want client redirect with error", loc)
	}
}

func TestOIDCConfidentialClientFlow(t *testing.T) {
	fx := setupOIDCFixture(t)

	// No secret → invalid_client (dedicated code: exchanges are single-use).
	badCode := fx.authorizeConsent("state-conf-bad-01", fx.conf, true)
	status, _, raw := fx.token(fx.conf, url.Values{
		"grant_type": {"authorization_code"}, "code": {badCode},
		"redirect_uri": {fx.conf.redirectURI}, "code_verifier": {pkceVerifier},
	}, "")
	if status == http.StatusOK {
		t.Fatal("confidential exchange without secret succeeded, want failure")
	}
	t.Logf("missing secret correctly rejected: %d %s", status, raw)

	// Wrong secret → invalid_client.
	badCode2 := fx.authorizeConsent("state-conf-bad-02", fx.conf, true)
	status, _, _ = fx.token(fx.conf, url.Values{
		"grant_type": {"authorization_code"}, "code": {badCode2},
		"redirect_uri": {fx.conf.redirectURI}, "code_verifier": {pkceVerifier},
	}, "wrong-secret")
	if status == http.StatusOK {
		t.Fatal("confidential exchange with wrong secret succeeded, want failure")
	}

	// Correct secret → tokens.
	code := fx.authorizeConsent("state-conf-0001", fx.conf, true)
	status, tok, raw := fx.token(fx.conf, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {fx.conf.redirectURI}, "code_verifier": {pkceVerifier},
	}, fx.conf.secret)
	if status != http.StatusOK {
		t.Fatalf("confidential exchange status = %d (%s)", status, raw)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.IDToken == "" {
		t.Fatalf("token response missing fields: %+v", tok)
	}
	claims := fx.verifyIDToken(tok.IDToken)
	if claims["sub"] != fx.alice.ID.String() {
		t.Fatalf("sub = %v, want %q", claims["sub"], fx.alice.ID)
	}
	if status, info := fx.userinfo(tok.AccessToken); status != http.StatusOK || info["sub"] != fx.alice.ID.String() {
		t.Fatalf("userinfo = %d %v, want alice", status, info)
	}

	// Confidential clients may skip PKCE (only public clients must use it).
	code2 := fx.authorizeConsent("state-conf-0002", fx.conf, false)
	status, tok2, raw := fx.token(fx.conf, url.Values{
		"grant_type": {"authorization_code"}, "code": {code2},
		"redirect_uri": {fx.conf.redirectURI},
	}, fx.conf.secret)
	if status != http.StatusOK {
		t.Fatalf("no-PKCE confidential exchange status = %d (%s)", status, raw)
	}
	if tok2.AccessToken == "" {
		t.Fatalf("no-PKCE token response missing access token: %+v", tok2)
	}
}

func TestOIDCConsentDeny(t *testing.T) {
	fx := setupOIDCFixture(t)
	resp, err := fx.browser.Get(fx.authorizeURL(fx.pub, "state-deny-0001", true))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/consent?challenge=") {
		t.Fatalf("Location = %q, want consent page", loc)
	}
	redirectTo := fx.grant(loc, fx.pub, false)
	u, err := url.Parse(redirectTo)
	if err != nil {
		t.Fatalf("parse deny redirect: %v", err)
	}
	if u.Query().Get("error") != "access_denied" {
		t.Fatalf("deny redirect = %q, want error=access_denied", redirectTo)
	}
	if u.Query().Get("state") != "state-deny-0001" {
		t.Fatalf("deny redirect state = %q, want round-tripped state", redirectTo)
	}
}

func TestOIDCAuthorizeFormPost(t *testing.T) {
	fx := setupOIDCFixture(t)
	// .NET-based clients (Technitium) send response_mode=form_post with
	// PKCE: parse must accept it, and the consent completion must answer
	// the auto-submit form (fosite renders 200 HTML, no Location).
	authURL := fx.authorizeURL(fx.conf, "state-formpost-01", true) +
		"&response_mode=form_post&nonce=formpost-nonce-01"
	resp, err := fx.browser.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302 consent", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/consent?challenge=") {
		t.Fatalf("Location = %q, want consent page", loc)
	}
	done := fx.grantJSON(loc, fx.conf, true)
	form, ok := done["form_post"]
	if !ok || form == "" {
		t.Fatalf("consent post = %v, want form_post HTML", done)
	}
	if !strings.Contains(form, `action="`+fx.conf.redirectURI+`"`) ||
		!strings.Contains(form, `name="code"`) ||
		!strings.Contains(form, `name="state"`) {
		t.Fatalf("form_post HTML missing action/code/state: %.300s", form)
	}
	code := formPostParam(t, form, "code")
	if formPostParam(t, form, "state") != "state-formpost-01" {
		t.Fatalf("form state mismatch: %.200s", form)
	}
	status, tok, raw := fx.token(fx.conf, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {fx.conf.redirectURI}, "code_verifier": {pkceVerifier},
	}, fx.conf.secret)
	if status != http.StatusOK {
		t.Fatalf("form_post code exchange status = %d (%s)", status, raw)
	}
	if tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatalf("token response missing fields: %+v", tok)
	}

	// Remembered consent: authorize answers the form directly (200 HTML).
	resp, err = fx.browser.Get(fx.authorizeURL(fx.conf, "state-formpost-02", true) +
		"&response_mode=form_post&nonce=formpost-nonce-02")
	if err != nil {
		t.Fatalf("second authorize: %v", err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second authorize status = %d, want 200 form (%s)", resp.StatusCode, rawBody)
	}
	if !strings.Contains(string(rawBody), `name="code"`) {
		t.Fatalf("second authorize body has no form: %.300s", rawBody)
	}
}

// formPostParam extracts one hidden input value from a form_post page.
func formPostParam(t *testing.T, form, name string) string {
	t.Helper()
	for _, mm := range formPostInput.FindAllStringSubmatch(form, -1) {
		if mm[1] == name {
			return mm[2]
		}
	}
	t.Fatalf("form_post has no input %q: %.300s", name, form)
	return ""
}

var formPostInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
