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

// Dashboard theme values (admin defaults; density/columns may be
// overridden per-device by the user).
const (
	// DashboardColumnsDefault is the desktop grid width; 0 in an update
	// payload means "keep the default".
	DashboardColumnsDefault = 3
	DashboardColumnsMin     = 2
	DashboardColumnsMax     = 4
	// Icon shapes for the dashboard app tiles.
	IconShapeRounded = "rounded"
	IconShapeCircle  = "circle"
	IconShapeSquare  = "square"
	// Card densities.
	DensityComfortable = "comfortable"
	DensityCompact     = "compact"
	// Dashboard backgrounds: the generative pattern, a plain page, or
	// the uploaded photo at DashboardBackgroundURL.
	DashboardBGPattern = "pattern"
	DashboardBGPlain   = "plain"
	DashboardBGPhoto   = "photo"
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Branding is the single branding(id=1) row (TECH_SPEC §5).
type Branding struct {
	ID                     int
	OrgName                string
	Tagline                string
	LogoURL                string
	FaviconURL             string
	PrimaryColor           string
	Theme                  string
	LoginBackgroundURL     string
	CustomCSS              string
	DashboardColumns       int
	DashboardIconShape     string
	DashboardDensity       string
	DashboardBackground    string
	DashboardBackgroundURL string
}

// Validate enforces hex colors, known themes, the tagline length cap,
// the dashboard theme enums, and the custom_css safety rules from
// TECH_SPEC §7 (max 10 KB; no @import, url(, </style>).
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
	if b.DashboardColumns != 0 &&
		(b.DashboardColumns < DashboardColumnsMin || b.DashboardColumns > DashboardColumnsMax) {
		return wrapValidation("dashboard_columns must be 2-4")
	}
	switch b.DashboardIconShape {
	case "", IconShapeRounded, IconShapeCircle, IconShapeSquare:
	default:
		return wrapValidation("unknown dashboard_icon_shape")
	}
	switch b.DashboardDensity {
	case "", DensityComfortable, DensityCompact:
	default:
		return wrapValidation("unknown dashboard_density")
	}
	switch b.DashboardBackground {
	case "", DashboardBGPattern, DashboardBGPlain, DashboardBGPhoto:
	default:
		return wrapValidation("unknown dashboard_background")
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
