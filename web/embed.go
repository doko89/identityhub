// Package web embeds the production SPA build (web/dist) into the Go
// binary so the release artifact is a single binary (TECH_SPEC §3).
//
// Build order: `npm run build` in this directory first, then `go build`.
// The committed dist/index.html fallback keeps `go build` working on
// machines without node; CI always rebuilds it from source.
package web

import "embed"

// Dist is the embedded SPA build rooted at dist/ (contains index.html).
//
//go:embed dist
var Dist embed.FS
