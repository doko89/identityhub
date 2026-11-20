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
	if err := (User{Username: "ara", Source: SourceLocal}).Validate(); err != nil {
		t.Fatalf("invite-pending local user without hash must be valid: %v", err)
	}
	for _, u := range []User{
		{Source: SourceLocal, PasswordHash: []byte("h")},
		{Username: "ara", Source: "oidc"},
	} {
		if err := u.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("user %+v: err = %v, want ErrValidation", u, err)
		}
	}
}

func TestCheckPasswordComplexity(t *testing.T) {
	for _, pw := range []string{"Abcdef1!", "P@ssw0rd", "Orang-tua-1!"} {
		if err := CheckPasswordComplexity(pw); err != nil {
			t.Errorf("CheckPasswordComplexity(%q) = %v, want nil", pw, err)
		}
	}
	for pw, want := range map[string]string{
		"short1!":        "at least 8",
		"alllowercase1!": "uppercase",
		"ALLUPPERCASE1!": "",
		"NoDigitsHere!":  "",
		"NoSymbol123":    "symbol",
		"12345678":       "uppercase",
	} {
		err := CheckPasswordComplexity(pw)
		if want == "" {
			if err != nil {
				t.Errorf("CheckPasswordComplexity(%q) = %v, want nil", pw, err)
			}
			continue
		}
		if err == nil || !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckPasswordComplexity(%q) = %v, want validation mentioning %q", pw, err, want)
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
	good.DashboardColumns = 3
	good.DashboardIconShape = IconShapeCircle
	good.DashboardDensity = DensityCompact
	good.DashboardBackground = DashboardBGPhoto
	good.DashboardBackgroundURL = "/uploads/login_background/x.webp"
	if err := good.Validate(); err != nil {
		t.Fatalf("dashboard theme: %v", err)
	}
	for name, mutate := range map[string]func(*Branding){
		"columns": func(b *Branding) { b.DashboardColumns = 7 },
		"shape":   func(b *Branding) { b.DashboardIconShape = "oval" },
		"density": func(b *Branding) { b.DashboardDensity = "airy" },
		"bg":      func(b *Branding) { b.DashboardBackground = "video" },
	} {
		bad = good
		mutate(&bad)
		if err := bad.Validate(); !errors.Is(err, ErrValidation) {
			t.Errorf("bad dashboard %s: err = %v, want ErrValidation", name, err)
		}
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
