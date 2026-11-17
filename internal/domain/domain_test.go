package domain

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUserValidate(t *testing.T) {
	if err := (User{Username: "ara", Source: SourceLocal, PasswordHash: []byte("h")}).Validate(); err != nil {
		t.Fatalf("valid local user: %v", err)
	}
	if err := (User{Username: "ara", Source: SourceLDAP}).Validate(); err != nil {
		t.Fatalf("ldap user without hash must be valid: %v", err)
	}
	for _, u := range []User{
		{Source: SourceLocal, PasswordHash: []byte("h")},
		{Username: "ara", Source: "oidc"},
		{Username: "ara", Source: SourceLocal},
	} {
		if err := u.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("user %+v: err = %v, want ErrValidation", u, err)
		}
	}
}

func TestApplicationValidate(t *testing.T) {
	if err := (Application{Slug: "wiki", Name: "Wiki", ProviderType: ProviderOIDC}).Validate(); err != nil {
		t.Fatalf("valid app: %v", err)
	}
	if err := (Application{Slug: "wiki", Name: "Wiki", ProviderType: "oauth1"}).Validate(); !errors.Is(err, ErrValidation) {
		t.Errorf("bad provider: err = %v, want ErrValidation", err)
	}
}

func TestBrandingValidate(t *testing.T) {
	good := Branding{ID: 1, OrgName: "Acme", PrimaryColor: "#4f46e5", Theme: ThemeSystem}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid branding: %v", err)
	}
	bad := good
	bad.PrimaryColor = "indigo"
	if err := bad.Validate(); !errors.Is(err, ErrValidation) {
		t.Errorf("named color: err = %v, want ErrValidation", err)
	}
	bad = good
	bad.Tagline = strings.Repeat("a", 201)
	if err := bad.Validate(); !errors.Is(err, ErrValidation) {
		t.Errorf("long tagline: err = %v, want ErrValidation", err)
	}
	bad = good
	bad.Theme = "sepia"
	if err := bad.Validate(); !errors.Is(err, ErrValidation) {
		t.Errorf("bad theme: err = %v, want ErrValidation", err)
	}
	for _, css := range []string{"a{background:url(http://x/y)}}", "@import 'evil';", "a{}</style><script>"} {
		bad = good
		bad.CustomCSS = css
		if err := bad.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("css %q: err = %v, want ErrValidation", css, err)
		}
	}
	bad = good
	bad.CustomCSS = strings.Repeat("a", 10*1024+1)
	if err := bad.Validate(); !errors.Is(err, ErrValidation) {
		t.Errorf("oversize css: err = %v, want ErrValidation", err)
	}
}

func TestMFAPolicy(t *testing.T) {
	app := uuid.New()
	other := uuid.New()
	p := MFAPolicy{AppRequired: map[uuid.UUID]bool{app: true}}
	if !p.RequiredFor(true, other) {
		t.Error("admins must always require MFA")
	}
	if !p.RequiredFor(false, app) {
		t.Error("flagged app must require MFA")
	}
	if p.RequiredFor(false, other) {
		t.Error("unflagged app must not require MFA")
	}
}

func TestPasswordResetTokenUsable(t *testing.T) {
	now := SystemClock{}.Now()
	fresh := PasswordResetToken{ExpiresAt: now.Add(15 * time.Minute)}
	if !fresh.IsUsable(now) {
		t.Error("fresh token must be usable")
	}
	expired := PasswordResetToken{ExpiresAt: now.Add(-time.Second)}
	if expired.IsUsable(now) {
		t.Error("expired token must not be usable")
	}
	used := PasswordResetToken{ExpiresAt: now.Add(15 * time.Minute), UsedAt: &now}
	if used.IsUsable(now) {
		t.Error("used token must not be usable")
	}
}
