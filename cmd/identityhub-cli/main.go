// Command identityhub-cli manages an IdentityHub SaaS tenant from the
// terminal. It speaks the same JSON API as the web console and
// authenticates with a personal API key (created under /account/api-keys)
// presented as a Bearer token:
//
//	IDENTITYHUB_API_KEY=ih_... identityhub-cli users list
//	identityhub-cli --server https://idp.example.com --json apps list
//
// A key inherits its owner's permissions; admin keys must be created in
// the browser from an MFA-verified session (keys minted through the CLI
// itself never satisfy the admin gate).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "identityhub-cli: %v\n", err)
		os.Exit(1)
	}
}

// command is one CLI resource (users, groups, ...). Actions dispatch
// inside run so `groups members add` style nesting stays trivial.
type command struct {
	short string
	run   func(ctx context.Context, c *Client, out *output, args []string) error
}

var commands = map[string]command{
	"whoami":   {"show the API key owner", whoamiCmd},
	"users":    {"list, inspect and manage users", usersCmd},
	"groups":   {"list, inspect and manage groups", groupsCmd},
	"attrs":    {"manage custom user attributes", attrsCmd},
	"apps":     {"manage the application catalog", appsCmd},
	"bindings": {"manage app access bindings", bindingsCmd},
	"oidc":     {"manage OIDC clients", oidcCmd},
	"saml":     {"manage SAML service providers", samlCmd},
	"radius":   {"manage RADIUS NAS clients", radiusCmd},
	"audit":    {"query the audit log", auditCmd},
	"ldap":     {"test the upstream directory connection", ldapCmd},
	"branding": {"view and update branding", brandingCmd},
	"apikeys":  {"manage your own API keys", apiKeysCmd},
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("identityhub-cli", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", envOr("IDENTITYHUB_SERVER", "http://localhost:8080"), "IdentityHub origin")
	apiKey := fs.String("api-key", os.Getenv("IDENTITYHUB_API_KEY"), "personal API key ($IDENTITYHUB_API_KEY)")
	jsonOut := fs.Bool("json", false, "print raw JSON responses")
	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return fmt.Errorf("a command is required")
	}
	if rest[0] == "help" {
		if len(rest) == 2 {
			if c, ok := commands[rest[1]]; ok {
				fmt.Fprintf(stdout, "%s: %s\n", rest[1], c.short)
				return nil
			}
			return fmt.Errorf("unknown command %q", rest[1])
		}
		usage(stdout)
		return nil
	}
	cmd, ok := commands[rest[0]]
	if !ok {
		usage(stderr)
		return fmt.Errorf("unknown command %q", rest[0])
	}
	if strings.TrimSpace(*apiKey) == "" {
		return fmt.Errorf("an API key is required (--api-key or $IDENTITYHUB_API_KEY); create one under /account/api-keys")
	}
	c := newClient(*server, strings.TrimSpace(*apiKey))
	out := &output{w: stdout, json: *jsonOut}
	if err := cmd.run(context.Background(), c, out, rest[1:]); err != nil {
		if apiErr, ok := err.(*APIError); ok {
			return apiErr
		}
		return err
	}
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: identityhub-cli [--server URL] [--api-key KEY] [--json] <command> [args]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	names := []string{"whoami", "users", "groups", "attrs", "apps", "bindings", "oidc", "saml", "radius", "audit", "ldap", "branding", "apikeys"}
	for _, n := range names {
		fmt.Fprintf(w, "  %-10s %s\n", n, commands[n].short)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "examples:")
	fmt.Fprintln(w, "  identityhub-cli whoami")
	fmt.Fprintln(w, "  identityhub-cli users list --q ara")
	fmt.Fprintln(w, "  identityhub-cli groups members add <group-id> --user <user-id>")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
