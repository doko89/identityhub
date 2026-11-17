package domain

import (
	"context"
	"regexp"
	"strings"
)

// Branding themes (PRD §6.8, DESIGN §3).
const (
	ThemeLight  = "light"
	ThemeDark   = "dark"
	ThemeSystem = "system"
)

// BrandingID is the only valid branding row id (CHECK id = 1).
const BrandingID = 1

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Branding is the single branding(id=1) row (TECH_SPEC §5).
type Branding struct {
	ID                 int
	OrgName            string
	Tagline            string
	LogoURL            string
	FaviconURL         string
	PrimaryColor       string
	Theme              string
	LoginBackgroundURL string
	CustomCSS          string
}

// Validate enforces hex colors, known themes, the tagline length cap,
// and the custom_css safety rules from TECH_SPEC §7 (max 10 KB;
// no @import, url(, </style>).
func (b Branding) Validate() error {
	if b.PrimaryColor != "" && !hexColor.MatchString(b.PrimaryColor) {
		return wrapValidation("primary_color must be #rrggbb")
	}
	if len(b.Tagline) > 200 {
		return wrapValidation("tagline too long (max 200 characters)")
	}
	switch b.Theme {
	case "", ThemeLight, ThemeDark, ThemeSystem:
	default:
		return wrapValidation("unknown theme")
	}
	if len(b.CustomCSS) > 10*1024 {
		return wrapValidation("custom_css exceeds 10 KB")
	}
	lowered := strings.ToLower(b.CustomCSS)
	for _, banned := range []string{"@import", "url(", "</style>"} {
		if strings.Contains(lowered, banned) {
			return wrapValidation("custom_css contains forbidden construct: " + banned)
		}
	}
	return nil
}

// BrandingStore reads/writes the singleton row.
type BrandingStore interface {
	Get(ctx context.Context) (Branding, error)
	Update(ctx context.Context, b Branding) (Branding, error)
}
