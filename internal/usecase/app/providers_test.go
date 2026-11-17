package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

type fakeOIDCClients struct {
	byID    map[string]domain.OIDCClient
	created []domain.OIDCClient
	err     error
}

func (f *fakeOIDCClients) GetByClientID(_ context.Context, id string) (domain.OIDCClient, error) {
	if c, ok := f.byID[id]; ok {
		return c, nil
	}
	return domain.OIDCClient{}, domain.ErrNotFound
}

func (f *fakeOIDCClients) Create(_ context.Context, c domain.OIDCClient) (domain.OIDCClient, error) {
	if f.err != nil {
		return domain.OIDCClient{}, f.err
	}
	if _, dup := f.byID[c.ClientID]; dup {
		return domain.OIDCClient{}, domain.ErrConflict
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if f.byID == nil {
		f.byID = map[string]domain.OIDCClient{}
	}
	f.byID[c.ClientID] = c
	f.created = append(f.created, c)
	return c, nil
}

func (f *fakeOIDCClients) Delete(_ context.Context, id string) error {
	if _, ok := f.byID[id]; !ok {
		return domain.ErrNotFound
	}
	delete(f.byID, id)
	return nil
}

func (f *fakeOIDCClients) List(_ context.Context, _, _ int) ([]domain.OIDCClient, int, error) {
	out := make([]domain.OIDCClient, 0, len(f.byID))
	for _, c := range f.byID {
		out = append(out, c)
	}
	return out, len(out), nil
}

type fakeSAMLSPs struct {
	byEntity map[string]domain.SAMLServiceProvider
}

func (f *fakeSAMLSPs) GetByEntityID(_ context.Context, id string) (domain.SAMLServiceProvider, error) {
	if sp, ok := f.byEntity[id]; ok {
		return sp, nil
	}
	return domain.SAMLServiceProvider{}, domain.ErrNotFound
}

func (f *fakeSAMLSPs) Create(_ context.Context, sp domain.SAMLServiceProvider) (domain.SAMLServiceProvider, error) {
	if _, dup := f.byEntity[sp.EntityID]; dup {
		return domain.SAMLServiceProvider{}, domain.ErrConflict
	}
	if sp.ID == uuid.Nil {
		sp.ID = uuid.New()
	}
	if f.byEntity == nil {
		f.byEntity = map[string]domain.SAMLServiceProvider{}
	}
	f.byEntity[sp.EntityID] = sp
	return sp, nil
}

func (f *fakeSAMLSPs) Delete(_ context.Context, id string) error {
	if _, ok := f.byEntity[id]; !ok {
		return domain.ErrNotFound
	}
	delete(f.byEntity, id)
	return nil
}

func (f *fakeSAMLSPs) List(_ context.Context, _, _ int) ([]domain.SAMLServiceProvider, int, error) {
	out := make([]domain.SAMLServiceProvider, 0, len(f.byEntity))
	for _, sp := range f.byEntity {
		out = append(out, sp)
	}
	return out, len(out), nil
}

type fakeRADIUS struct {
	byNAS map[string]domain.RADIUSClient
}

func (f *fakeRADIUS) Create(_ context.Context, c domain.RADIUSClient) (domain.RADIUSClient, error) {
	if _, dup := f.byNAS[c.NASIdentifier]; dup {
		return domain.RADIUSClient{}, domain.ErrConflict
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if f.byNAS == nil {
		f.byNAS = map[string]domain.RADIUSClient{}
	}
	f.byNAS[c.NASIdentifier] = c
	return c, nil
}

func (f *fakeRADIUS) ByNASIdentifier(_ context.Context, nas string) (domain.RADIUSClient, error) {
	if c, ok := f.byNAS[nas]; ok {
		return c, nil
	}
	return domain.RADIUSClient{}, domain.ErrNotFound
}

func (f *fakeRADIUS) Delete(_ context.Context, nas string) error {
	if _, ok := f.byNAS[nas]; !ok {
		return domain.ErrNotFound
	}
	delete(f.byNAS, nas)
	return nil
}

func (f *fakeRADIUS) List(_ context.Context, _, _ int) ([]domain.RADIUSClient, int, error) {
	out := make([]domain.RADIUSClient, 0, len(f.byNAS))
	for _, c := range f.byNAS {
		out = append(out, c)
	}
	return out, len(out), nil
}

type fakeHasher struct{ err error }

func (f fakeHasher) HashSecret(plain string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []byte("hash:" + plain), nil
}

type fakeSealer struct{ err error }

func (f fakeSealer) Seal(plain []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte("sealed:"), plain...), nil
}

func (f fakeSealer) Open(sealed []byte) ([]byte, error) { return sealed, nil }

type fakeParser struct {
	sp  domain.SAMLServiceProvider
	err error
}

func (f fakeParser) ParseSPMetadata(_ string) (domain.SAMLServiceProvider, error) {
	if f.err != nil {
		return domain.SAMLServiceProvider{}, f.err
	}
	return f.sp, nil
}

func providerFixture() (*ProviderService, *fakeApps, *fakeOIDCClients, *fakeSAMLSPs, *fakeRADIUS, uuid.UUID) {
	apps := &fakeApps{byID: map[uuid.UUID]domain.Application{}}
	appID := uuid.New()
	apps.byID[appID] = domain.Application{ID: appID, Slug: "wiki", Name: "Wiki", ProviderType: domain.ProviderOIDC}
	oidc := &fakeOIDCClients{}
	sps := &fakeSAMLSPs{}
	radius := &fakeRADIUS{}
	svc, err := NewProviders(ProviderDeps{
		Apps: apps, OIDCClients: oidc, SAMLSPs: sps, RADIUS: radius,
		Hasher: fakeHasher{}, Sealer: fakeSealer{},
		Parser: fakeParser{sp: domain.SAMLServiceProvider{EntityID: "https://sp.example.com", ACSURL: "https://sp.example.com/acs"}},
	})
	if err != nil {
		panic(err)
	}
	return svc, apps, oidc, sps, radius, appID
}

func TestNewProvidersRequiresDeps(t *testing.T) {
	if _, err := NewProviders(ProviderDeps{}); err == nil {
		t.Fatal("NewProviders with nil deps must fail")
	}
	svc, _, _, _, _, _ := providerFixture()
	if svc == nil {
		t.Fatal("NewProviders with full deps must succeed")
	}
}

func TestRegisterOIDCClientConfidential(t *testing.T) {
	svc, _, oidc, _, _, appID := providerFixture()
	ctx := context.Background()
	created, secret, err := svc.RegisterOIDCClient(ctx, RegisterOIDCClientInput{
		ApplicationID: appID, RedirectURIs: []string{"https://wiki.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if !strings.HasPrefix(created.ClientID, "oidc-") || len(secret) != 43 {
		t.Fatalf("generated id=%q secret len=%d", created.ClientID, len(secret))
	}
	if created.ClientSecretHash != nil {
		t.Fatal("Register must strip the hash from the response")
	}
	stored := oidc.byID[created.ClientID]
	if string(stored.ClientSecretHash) != "hash:"+secret {
		t.Fatalf("stored hash = %q", stored.ClientSecretHash)
	}
	if len(stored.Scopes) != 3 || stored.Scopes[0] != domain.ScopeOpenID {
		t.Fatalf("default scopes = %v", stored.Scopes)
	}
}

func TestRegisterOIDCClientPublic(t *testing.T) {
	svc, _, oidc, _, _, appID := providerFixture()
	created, secret, err := svc.RegisterOIDCClient(context.Background(), RegisterOIDCClientInput{
		ApplicationID: appID, ClientID: "spa.wiki-1",
		RedirectURIs: []string{"https://wiki.example.com/cb"},
		Scopes:       []string{"openid", "groups", "offline_access"}, Public: true,
	})
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if secret != "" {
		t.Fatalf("public client secret = %q, want empty", secret)
	}
	if oidc.byID["spa.wiki-1"].ClientSecretHash != nil {
		t.Fatal("public client must carry a nil hash")
	}
	if created.ClientID != "spa.wiki-1" {
		t.Fatalf("client id = %q", created.ClientID)
	}
}

func TestRegisterOIDCClientValidation(t *testing.T) {
	svc, _, _, _, _, appID := providerFixture()
	ctx := context.Background()
	good := RegisterOIDCClientInput{ApplicationID: appID, RedirectURIs: []string{"https://a.example.com/cb"}}
	cases := []struct {
		name  string
		alter func(*RegisterOIDCClientInput)
	}{
		{"unknown app", func(in *RegisterOIDCClientInput) { in.ApplicationID = uuid.New() }},
		{"bad client id", func(in *RegisterOIDCClientInput) { in.ClientID = "a/b" }},
		{"short client id", func(in *RegisterOIDCClientInput) { in.ClientID = "ab" }},
		{"no redirect", func(in *RegisterOIDCClientInput) { in.RedirectURIs = nil }},
		{"blank redirect", func(in *RegisterOIDCClientInput) { in.RedirectURIs = []string{"  "} }},
		{"relative redirect", func(in *RegisterOIDCClientInput) { in.RedirectURIs = []string{"/cb"} }},
		{"http public", func(in *RegisterOIDCClientInput) { in.RedirectURIs = []string{"http://evil.example.com/cb"} }},
		{"fragment", func(in *RegisterOIDCClientInput) { in.RedirectURIs = []string{"https://a.example.com/cb#x"} }},
		{"custom scheme", func(in *RegisterOIDCClientInput) { in.RedirectURIs = []string{"myapp://cb"} }},
		{"bad scope", func(in *RegisterOIDCClientInput) { in.Scopes = []string{"openid", "admin"} }},
		{"missing openid", func(in *RegisterOIDCClientInput) { in.Scopes = []string{"profile"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := good
			tc.alter(&in)
			if _, _, err := svc.RegisterOIDCClient(ctx, in); err == nil {
				t.Fatalf("Register(%s) must fail", tc.name)
			}
		})
	}
	// Loopback http is the documented dev exception.
	for _, uri := range []string{"http://localhost:8080/cb", "http://127.0.0.1:8080/cb", "http://[::1]:8080/cb"} {
		in := good
		in.RedirectURIs = []string{uri}
		if _, _, err := svc.RegisterOIDCClient(ctx, in); err != nil {
			t.Fatalf("Register(%s) = %v, want success", uri, err)
		}
	}
}

func TestRegisterOIDCClientDuplicate(t *testing.T) {
	svc, _, _, _, _, appID := providerFixture()
	ctx := context.Background()
	in := RegisterOIDCClientInput{ApplicationID: appID, ClientID: "dup.client", RedirectURIs: []string{"https://a.example.com/cb"}}
	if _, _, err := svc.RegisterOIDCClient(ctx, in); err != nil {
		t.Fatalf("first Register = %v", err)
	}
	if _, _, err := svc.RegisterOIDCClient(ctx, in); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second Register = %v, want conflict", err)
	}
}

func TestOIDCDeleteValidation(t *testing.T) {
	svc, _, _, _, _, _ := providerFixture()
	if err := svc.DeleteOIDCClient(context.Background(), "  "); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("blank delete = %v, want validation", err)
	}
	if err := svc.DeleteOIDCClient(context.Background(), "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing delete = %v, want not found", err)
	}
}

func TestListOIDCClientsStripsHashes(t *testing.T) {
	svc, _, oidc, _, _, appID := providerFixture()
	ctx := context.Background()
	if _, _, err := svc.RegisterOIDCClient(ctx, RegisterOIDCClientInput{
		ApplicationID: appID, ClientID: "listed", RedirectURIs: []string{"https://a.example.com/cb"},
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate a stored hash (the fake Create keeps what Register passed
	// before stripping — re-add to prove the list strips).
	stored := oidc.byID["listed"]
	stored.ClientSecretHash = []byte("hash:x")
	oidc.byID["listed"] = stored
	out, total, err := svc.ListOIDCClients(ctx, 50, 0)
	if err != nil || total != 1 || len(out) != 1 {
		t.Fatalf("List = %v %d %v", out, total, err)
	}
	if out[0].ClientSecretHash != nil {
		t.Fatal("List must strip hashes")
	}
}

func TestImportSAMLSP(t *testing.T) {
	svc, _, _, sps, _, appID := providerFixture()
	sp, err := svc.ImportSAMLSP(context.Background(), appID, "<xml/>")
	if err != nil {
		t.Fatalf("Import = %v", err)
	}
	if sp.EntityID != "https://sp.example.com" || sp.ApplicationID != appID {
		t.Fatalf("imported = %+v", sp)
	}
	if _, err := svc.ImportSAMLSP(context.Background(), appID, "<xml/>"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate import = %v, want conflict", err)
	}
	if _, ok := sps.byEntity["https://sp.example.com"]; !ok {
		t.Fatal("SP not stored")
	}
	if err := svc.DeleteSAMLSP(context.Background(), "  "); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("blank delete = %v, want validation", err)
	}
}

func TestImportSAMLSPUnknownAppAndParseError(t *testing.T) {
	svc, _, _, _, _, _ := providerFixture()
	if _, err := svc.ImportSAMLSP(context.Background(), uuid.New(), "<xml/>"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown app import = %v, want not found", err)
	}
	bad, _, _, _, _, appID := providerFixture()
	bad.parser = fakeParser{err: errors.New("bad xml")}
	if _, err := bad.ImportSAMLSP(context.Background(), appID, "nope"); err == nil {
		t.Fatal("parse error must propagate")
	}
}

func TestRegisterRADIUSClient(t *testing.T) {
	svc, _, _, _, radius, appID := providerFixture()
	ctx := context.Background()
	created, secret, err := svc.RegisterRADIUSClient(ctx, RegisterRADIUSClientInput{
		ApplicationID: appID, NASIdentifier: "10.0.0.5",
	})
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("generated secret len = %d, want 32 hex", len(secret))
	}
	if created.SharedSecretEnc != nil {
		t.Fatal("Register must strip sealed bytes from the response")
	}
	if got := string(radius.byNAS["10.0.0.5"].SharedSecretEnc); got != "sealed:"+secret {
		t.Fatalf("stored = %q", got)
	}
	if _, _, err := svc.RegisterRADIUSClient(ctx, RegisterRADIUSClientInput{
		ApplicationID: appID, NASIdentifier: "10.0.0.5",
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate NAS = %v, want conflict", err)
	}
}

func TestRegisterRADIUSClientValidation(t *testing.T) {
	svc, _, _, _, _, appID := providerFixture()
	ctx := context.Background()
	for name, in := range map[string]RegisterRADIUSClientInput{
		"unknown app": {ApplicationID: uuid.New(), NASIdentifier: "10.0.0.1"},
		"hostname":    {ApplicationID: appID, NASIdentifier: "nas.example.com"},
		"blank":       {ApplicationID: appID, NASIdentifier: " "},
		"short":       {ApplicationID: appID, NASIdentifier: "10.0.0.2", SharedSecret: "short"},
	} {
		if _, _, err := svc.RegisterRADIUSClient(ctx, in); err == nil {
			t.Fatalf("Register(%s) must fail", name)
		}
	}
	created, secret, err := svc.RegisterRADIUSClient(ctx, RegisterRADIUSClientInput{
		ApplicationID: appID, NASIdentifier: "2001:db8::1", SharedSecret: "operator-chosen-secret",
	})
	if err != nil {
		t.Fatalf("IPv6 + chosen secret = %v", err)
	}
	if secret != "operator-chosen-secret" || created.NASIdentifier != "2001:db8::1" {
		t.Fatalf("chosen secret not honored: %+v %q", created, secret)
	}
	if err := svc.DeleteRADIUSClient(ctx, " "); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("blank delete = %v, want validation", err)
	}
}

func TestListRADIUSClientsStripsSecrets(t *testing.T) {
	svc, _, _, _, radius, appID := providerFixture()
	ctx := context.Background()
	if _, _, err := svc.RegisterRADIUSClient(ctx, RegisterRADIUSClientInput{
		ApplicationID: appID, NASIdentifier: "10.0.0.9",
	}); err != nil {
		t.Fatal(err)
	}
	stored := radius.byNAS["10.0.0.9"]
	stored.SharedSecretEnc = []byte("sealed:x")
	radius.byNAS["10.0.0.9"] = stored
	out, total, err := svc.ListRADIUSClients(ctx, 50, 0)
	if err != nil || total != 1 || len(out) != 1 {
		t.Fatalf("List = %v %d %v", out, total, err)
	}
	if out[0].SharedSecretEnc != nil {
		t.Fatal("List must strip sealed secrets")
	}
}
