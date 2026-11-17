package main

import (
	"context"
	"flag"
	"fmt"
)

func whoamiCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 0 {
		return usagef("whoami takes no arguments")
	}
	resp, err := c.do(ctx, "GET", "/api/auth/me", nil, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	out.table(userHeader, [][]string{userRow(obj(resp, "user"))})
	return nil
}

const auditUsage = `usage:
  audit list [--method METHOD] [--result success|failure] [--actor ID] [--app ID]
      [--since RFC3339] [--until RFC3339] [--limit N] [--offset N]
  audit export [same filters]   # CSV to stdout`

func auditCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", auditUsage)
	}
	switch args[0] {
	case "list":
		return auditList(ctx, c, out, args[1:])
	case "export":
		return auditExport(ctx, c, out, args[1:])
	default:
		return usagef("unknown audit action %q\n%s", args[0], auditUsage)
	}
}

func auditFilterFlags(fs *flag.FlagSet) func() map[string]string {
	method := fs.String("method", "", "password|totp|ldap|radius|oidc|saml|apikey|...")
	result := fs.String("result", "", "success|failure")
	actor := fs.String("actor", "", "actor user id")
	app := fs.String("app", "", "application id")
	since := fs.String("since", "", "RFC3339 start")
	until := fs.String("until", "", "RFC3339 end")
	page := pageFlags(fs)
	return func() map[string]string {
		m := map[string]string{}
		for k, v := range map[string]*string{"method": method, "result": result, "actor": actor, "app": app, "since": since, "until": until} {
			if *v != "" {
				m[k] = *v
			}
		}
		for k, vs := range page() {
			m[k] = vs[0]
		}
		return m
	}
}

func auditList(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	filters := auditFilterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	query := urlValues(filters())
	resp, err := c.do(ctx, "GET", "/api/admin/audit", query, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "entries") {
		a := asObj(e)
		rows = append(rows, []string{cell(a["id"]), cell(a["at"]), cell(a["actor_user_id"]),
			cell(a["method"]), cell(a["result"]), cell(a["ip"]), cell(a["detail"])})
	}
	out.table([]string{"ID", "AT", "ACTOR", "METHOD", "RESULT", "IP", "DETAIL"}, rows)
	out.line("total: %s", cell(asObj(resp)["total"]))
	return nil
}

func auditExport(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	filters := auditFilterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := c.doRaw(ctx, "GET", "/api/admin/audit/export", urlValues(filters()))
	if err != nil {
		return err
	}
	fmt.Fprint(out.w, string(raw))
	return nil
}

const ldapUsage = `usage:
  ldap test`

func ldapCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 || args[0] != "test" {
		return usagef("%s", ldapUsage)
	}
	resp, err := c.do(ctx, "POST", "/api/admin/ldap/test", nil, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	m := asObj(resp)
	out.table([]string{"CONFIGURED", "OK", "ERROR"},
		[][]string{{cell(m["configured"]), cell(m["ok"]), cell(m["error"])}})
	return nil
}

const brandingUsage = `usage:
  branding get
  branding update [--org-name NAME] [--tagline TEXT] [--logo-url URL] [--favicon-url URL]
      [--primary-color HEX] [--theme light|dark|system] [--login-background-url URL] [--custom-css CSS]`

func brandingCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", brandingUsage)
	}
	switch args[0] {
	case "get":
		resp, err := c.do(ctx, "GET", "/api/branding", nil, nil)
		if err != nil {
			return err
		}
		if out.json {
			return out.printJSON(resp)
		}
		b := obj(resp, "branding")
		out.table([]string{"FIELD", "VALUE"}, [][]string{
			{"org_name", cell(b["org_name"])},
			{"tagline", cell(b["tagline"])},
			{"logo_url", cell(b["logo_url"])},
			{"favicon_url", cell(b["favicon_url"])},
			{"primary_color", cell(b["primary_color"])},
			{"theme", cell(b["theme"])},
			{"login_background_url", cell(b["login_background_url"])},
			{"custom_css", cell(b["custom_css"])},
		})
		return nil
	case "update":
		return brandingUpdate(ctx, c, out, args[1:])
	default:
		return usagef("unknown branding action %q\n%s", args[0], brandingUsage)
	}
}

func brandingUpdate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("branding update", flag.ContinueOnError)
	fields := map[string]*optional{}
	for _, f := range []string{"org-name", "tagline", "logo-url", "favicon-url", "primary-color", "theme", "login-background-url", "custom-css"} {
		o := &optional{}
		fs.Var(o, f, "branding field "+f)
		fields[f] = o
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	body := map[string]any{}
	for f, o := range fields {
		if o.set {
			body[under(f)] = o.value
		}
	}
	if len(body) == 0 {
		return usagef("branding update needs at least one field flag")
	}
	resp, err := c.do(ctx, "PATCH", "/api/admin/branding", nil, body)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	b := obj(resp, "branding")
	out.line("branding updated: org=%s theme=%s", cell(b["org_name"]), cell(b["theme"]))
	return nil
}

const apiKeysUsage = `usage:
  apikeys list
  apikeys create --name NAME [--expires-in-days N] [--totp-code CODE]
  apikeys revoke <id>

Note: keys minted here are never MFA-verified, so admin keys must be
created in the browser instead (see /account/api-keys).`

func apiKeysCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", apiKeysUsage)
	}
	switch args[0] {
	case "list":
		resp, err := c.do(ctx, "GET", "/api/account/api-keys", nil, nil)
		if err != nil {
			return err
		}
		if out.json {
			return out.printJSON(resp)
		}
		var rows [][]string
		for _, e := range objList(resp, "api_keys") {
			k := asObj(e)
			rows = append(rows, []string{cell(k["id"]), cell(k["name"]), cell(k["prefix"]),
				cell(k["created_with_mfa"]), shortDate(k["expires_at"]), shortDate(k["revoked_at"]),
				shortDate(k["last_used_at"]), shortDate(k["created_at"])})
		}
		out.table([]string{"ID", "NAME", "PREFIX", "MFA", "EXPIRES", "REVOKED", "LAST_USED", "CREATED"}, rows)
		return nil
	case "create":
		return apiKeysCreate(ctx, c, out, args[1:])
	case "revoke":
		if len(args) != 2 {
			return usagef("apikeys revoke <id>")
		}
		if _, err := c.do(ctx, "DELETE", "/api/account/api-keys/"+args[1], nil, nil); err != nil {
			return err
		}
		out.line("revoked API key %s", args[1])
		return nil
	default:
		return usagef("unknown apikeys action %q\n%s", apiKeysUsage, args[0])
	}
}

func apiKeysCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("apikeys create", flag.ContinueOnError)
	name := fs.String("name", "", "key name (required)")
	expires := fs.Int("expires-in-days", 0, "TTL in days (0 = never)")
	totp := fs.String("totp-code", "", "re-auth code when the account has MFA")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return usagef("apikeys create requires --name")
	}
	body := map[string]any{"name": *name}
	if *expires > 0 {
		body["expires_in_days"] = *expires
	}
	if *totp != "" {
		body["totp_code"] = *totp
	}
	resp, err := c.do(ctx, "POST", "/api/account/api-keys", nil, body)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	k := obj(resp, "api_key")
	out.table([]string{"ID", "NAME", "PREFIX", "EXPIRES"},
		[][]string{{cell(k["id"]), cell(k["name"]), cell(k["prefix"]), shortDate(k["expires_at"])}})
	out.line("secret (shown once, store it now): %s", cell(asObj(resp)["secret"]))
	return nil
}
