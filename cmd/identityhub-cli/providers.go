package main

import (
	"context"
	"flag"
	"net/url"
	"os"
	"strings"
)

const oidcUsage = `usage:
  oidc list [--limit N] [--offset N]
  oidc create --app <app-id> --client-id ID --redirect-uris U1,U2 [--scopes S1,S2] [--public]
  oidc delete <client-id>`

func oidcCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", oidcUsage)
	}
	switch args[0] {
	case "list":
		return oidcList(ctx, c, out, args[1:])
	case "create":
		return oidcCreate(ctx, c, out, args[1:])
	case "delete":
		if len(args) != 2 {
			return usagef("oidc delete <client-id>")
		}
		if _, err := c.do(ctx, "DELETE", "/api/admin/oidc/clients/"+args[1], nil, nil); err != nil {
			return err
		}
		out.line("deleted OIDC client %s", args[1])
		return nil
	default:
		return usagef("unknown oidc action %q\n%s", args[0], oidcUsage)
	}
}

func oidcList(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("oidc list", flag.ContinueOnError)
	page := pageFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := c.do(ctx, "GET", "/api/admin/oidc/clients", page(), nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "clients") {
		cl := asObj(e)
		rows = append(rows, []string{cell(cl["client_id"]), cell(cl["application_id"]),
			cell(cl["redirect_uris"]), cell(cl["scopes"]), cell(cl["public"])})
	}
	out.table([]string{"CLIENT_ID", "APP_ID", "REDIRECT_URIS", "SCOPES", "PUBLIC"}, rows)
	out.line("total: %s", cell(asObj(resp)["total"]))
	return nil
}

func oidcCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("oidc create", flag.ContinueOnError)
	appID := fs.String("app", "", "application id (required)")
	clientID := fs.String("client-id", "", "public client id (required)")
	redirects := fs.String("redirect-uris", "", "comma-separated redirect URIs (required)")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	public := fs.Bool("public", false, "public PKCE-only client (no secret)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *appID == "" || *clientID == "" || *redirects == "" {
		return usagef("oidc create requires --app, --client-id and --redirect-uris")
	}
	resp, err := c.do(ctx, "POST", "/api/admin/oidc/clients", nil, map[string]any{
		"application_id": *appID, "client_id": *clientID,
		"redirect_uris": splitList(*redirects), "scopes": splitList(*scopes), "public": *public,
	})
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	cl := obj(resp, "client")
	out.table([]string{"CLIENT_ID", "APP_ID", "REDIRECT_URIS", "SCOPES", "PUBLIC"},
		[][]string{{cell(cl["client_id"]), cell(cl["application_id"]),
			cell(cl["redirect_uris"]), cell(cl["scopes"]), cell(cl["public"])}})
	if secret := cell(asObj(resp)["client_secret"]); secret != "" {
		out.line("client_secret (shown once): %s", secret)
	}
	return nil
}

const samlUsage = `usage:
  saml list [--limit N] [--offset N]
  saml import --app <app-id> (--metadata-file PATH | --metadata-xml XML)
  saml delete --entity-id ID`

func samlCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", samlUsage)
	}
	switch args[0] {
	case "list":
		return samlList(ctx, c, out, args[1:])
	case "import":
		return samlImport(ctx, c, out, args[1:])
	case "delete":
		return samlDelete(ctx, c, out, args[1:])
	default:
		return usagef("unknown saml action %q\n%s", args[0], samlUsage)
	}
}

func samlList(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("saml list", flag.ContinueOnError)
	page := pageFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := c.do(ctx, "GET", "/api/admin/saml/sps", page(), nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "sps") {
		sp := asObj(e)
		rows = append(rows, []string{cell(sp["entity_id"]), cell(sp["application_id"]), cell(sp["acs_url"]), cell(sp["slo_url"])})
	}
	out.table([]string{"ENTITY_ID", "APP_ID", "ACS_URL", "SLO_URL"}, rows)
	out.line("total: %s", cell(asObj(resp)["total"]))
	return nil
}

func samlImport(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("saml import", flag.ContinueOnError)
	appID := fs.String("app", "", "application id (required)")
	file := fs.String("metadata-file", "", "path to SP metadata XML")
	inline := fs.String("metadata-xml", "", "SP metadata XML")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *appID == "" || (*file == "" && *inline == "") {
		return usagef("saml import requires --app and --metadata-file or --metadata-xml")
	}
	xml := *inline
	if *file != "" {
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		xml = string(raw)
	}
	resp, err := c.do(ctx, "POST", "/api/admin/saml/sps", nil,
		map[string]any{"application_id": *appID, "metadata_xml": xml})
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	sp := obj(resp, "sp")
	out.table([]string{"ENTITY_ID", "APP_ID", "ACS_URL", "SLO_URL"},
		[][]string{{cell(sp["entity_id"]), cell(sp["application_id"]), cell(sp["acs_url"]), cell(sp["slo_url"])}})
	return nil
}

func samlDelete(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("saml delete", flag.ContinueOnError)
	entityID := fs.String("entity-id", "", "SP entity id (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *entityID == "" {
		return usagef("saml delete requires --entity-id")
	}
	q := url.Values{}
	q.Set("entity_id", *entityID)
	if _, err := c.do(ctx, "DELETE", "/api/admin/saml/sps", q, nil); err != nil {
		return err
	}
	out.line("deleted SAML SP %s", *entityID)
	return nil
}

const radiusUsage = `usage:
  radius list [--limit N] [--offset N]
  radius create --app <app-id> --nas IP [--secret SECRET]
  radius delete <nas-identifier>`

func radiusCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", radiusUsage)
	}
	switch args[0] {
	case "list":
		return radiusList(ctx, c, out, args[1:])
	case "create":
		return radiusCreate(ctx, c, out, args[1:])
	case "delete":
		if len(args) != 2 {
			return usagef("radius delete <nas-identifier>")
		}
		if _, err := c.do(ctx, "DELETE", "/api/admin/radius/clients/"+url.PathEscape(args[1]), nil, nil); err != nil {
			return err
		}
		out.line("deleted RADIUS client %s", args[1])
		return nil
	default:
		return usagef("unknown radius action %q\n%s", args[0], radiusUsage)
	}
}

func radiusList(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("radius list", flag.ContinueOnError)
	page := pageFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := c.do(ctx, "GET", "/api/admin/radius/clients", page(), nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "clients") {
		cl := asObj(e)
		rows = append(rows, []string{cell(cl["nas_identifier"]), cell(cl["application_id"])})
	}
	out.table([]string{"NAS_IDENTIFIER", "APP_ID"}, rows)
	out.line("total: %s", cell(asObj(resp)["total"]))
	return nil
}

func radiusCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("radius create", flag.ContinueOnError)
	appID := fs.String("app", "", "application id (required)")
	nas := fs.String("nas", "", "NAS identifier, the source IP (required)")
	secret := fs.String("secret", "", "shared secret (prompted when omitted)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *appID == "" || *nas == "" {
		return usagef("radius create requires --app and --nas")
	}
	shared := *secret
	if shared == "" {
		var err error
		if shared, err = promptSecret("Shared secret"); err != nil {
			return err
		}
	}
	resp, err := c.do(ctx, "POST", "/api/admin/radius/clients", nil, map[string]any{
		"application_id": *appID, "nas_identifier": *nas, "shared_secret": shared,
	})
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	cl := obj(resp, "client")
	out.table([]string{"NAS_IDENTIFIER", "APP_ID"},
		[][]string{{cell(cl["nas_identifier"]), cell(cl["application_id"])}})
	if s := cell(asObj(resp)["shared_secret"]); s != "" {
		out.line("shared_secret (shown once): %s", s)
	}
	return nil
}

// splitList splits a comma-separated flag into a JSON array.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
