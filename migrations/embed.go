// Package migrations embeds the goose SQL migrations so the single binary
// can run `migrate up` with no external files.
package migrations

import "embed"

// FS holds the *.sql migration files at its root.
//
//go:embed *.sql
var FS embed.FS
