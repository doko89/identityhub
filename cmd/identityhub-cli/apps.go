package main

import (
	"context"
	"flag"
)

const appsUsage = `usage:
  apps list [--group LABEL] [--limit N] [--offset N]
  apps get <id>
  apps create --slug SLUG --name NAME [--description TEXT] [--icon-url URL] [--launch-url URL]
      [--group-label LABEL] [--provider-type oidc|saml|ldap|radius] [--visible true|false]
      [--sort-order N] [--mfa-required true|false] [--new-tab true|false]
  apps update <id> [same flags as create]
  apps delete <id>`

var appHeader = []string{"ID", "SLUG", "NAME", "PROVIDER", "VISIBLE", "MFA", "LAUNCH_URL"}

func appRow(a map[string]any) []string {
	return []string{cell(a["id"]), cell(a["slug"]), cell(a["name"]),
		cell(a["provider_type"]), cell(a["is_visible"]), cell(a["mfa_required"]), cell(a["launch_url"])}
}

func appsCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", appsUsage)
	}
	switch args[0] {
	case "list":
		return appsList(ctx, c, out, args[1:])
	case "get":
		return appsGet(ctx, c, out, args[1:])
	case "create":
		return appsCreate(ctx, c, out, args[1:])
	case "update":
		return appsUpdate(ctx, c, out, args[1:])
	case "delete":
		return appsDelete(ctx, c, out, args[1:])
	default:
		return usagef("unknown apps action %q\n%s", args[0], appsUsage)
	}
}

// appFieldFlags registers every mutable app field as an optional flag.
func appFieldFlags(fs *flag.FlagSet) map[string]*optional {
	fields := []string{"slug", "name", "description", "icon-url", "launch-url",
		"group-label", "provider-type", "visible", "sort-order", "mfa-required", "new-tab"}
	m := map[string]*optional{}
	for _, f := range fields {
		o := &optional{}
		fs.Var(o, f, "app field "+f)
		m[f] = o
	}
	return m
}

// appBody builds the create/update JSON body from the set flags only.
func appBody(m map[string]*optional) (map[string]any, error) {
	body := map[string]any{}
	for _, f := range []string{"slug", "name", "description", "icon-url", "launch-url", "group-label", "provider-type"} {
		if m[f].set {
			body[under(f)] = m[f].value
		}
	}
	for _, f := range []string{"visible", "mfa-required", "new-tab"} {
		if v, ok, err := m[f].optBool(); err != nil {
			return nil, usagef("invalid --%s: %v", f, err)
		} else if ok {
			key := map[string]string{"visible": "is_visible", "mfa-required": "mfa_required", "new-tab": "open_in_new_tab"}[f]
			body[key] = v
		}
	}
	if v, ok, err := m["sort-order"].optInt(); err != nil {
		return nil, usagef("invalid --sort-order: %v", err)
	} else if ok {
		body["sort_order"] = v
	}
	return body, nil
}

func under(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '-' {
			out = append(out, '_')
		} else {
			out = append(out, r)
		}
	}
	return string(out)
}

func appsList(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("apps list", flag.ContinueOnError)
	group := fs.String("group", "", "dashboard group filter")
	page := pageFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	query := page()
	if *group != "" {
		query.Set("group", *group)
	}
	resp, err := c.do(ctx, "GET", "/api/admin/apps", query, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "apps") {
		rows = append(rows, appRow(asObj(e)))
	}
	out.table(appHeader, rows)
	out.line("total: %s", cell(asObj(resp)["total"]))
	return nil
}

func appsGet(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("apps get <id>")
	}
	resp, err := c.do(ctx, "GET", "/api/admin/apps/"+args[0], nil, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	out.table(appHeader, [][]string{appRow(obj(resp, "app"))})
	return nil
}

func appsCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("apps create", flag.ContinueOnError)
	fields := appFieldFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !fields["slug"].set || !fields["name"].set {
		return usagef("apps create requires --slug and --name")
	}
	body, err := appBody(fields)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, "POST", "/api/admin/apps", nil, body)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	out.table(appHeader, [][]string{appRow(obj(resp, "app"))})
	return nil
}

func appsUpdate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("apps update", flag.ContinueOnError)
	fields := appFieldFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return usagef("apps update <id> [flags]")
	}
	body, err := appBody(fields)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return usagef("apps update <id> needs at least one field flag")
	}
	resp, err := c.do(ctx, "PATCH", "/api/admin/apps/"+rest[0], nil, body)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	out.table(appHeader, [][]string{appRow(obj(resp, "app"))})
	return nil
}

func appsDelete(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("apps delete <id>")
	}
	if _, err := c.do(ctx, "DELETE", "/api/admin/apps/"+args[0], nil, nil); err != nil {
		return err
	}
	out.line("deleted app %s (bindings cascade)", args[0])
	return nil
}

const bindingsUsage = `usage:
  bindings list <app-id>
  bindings create <app-id> --type user|group|policy [--user <user-id>] [--group <group-id>]
      [--policy EXPR] [--eval any|all]
  bindings delete <app-id> <binding-id>`

func bindingsCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", bindingsUsage)
	}
	switch args[0] {
	case "list":
		if len(args) != 2 {
			return usagef("bindings list <app-id>")
		}
		resp, err := c.do(ctx, "GET", "/api/admin/apps/"+args[1]+"/bindings", nil, nil)
		if err != nil {
			return err
		}
		if out.json {
			return out.printJSON(resp)
		}
		var rows [][]string
		for _, e := range objList(resp, "bindings") {
			b := asObj(e)
			rows = append(rows, []string{cell(b["id"]), cell(b["binding_type"]),
				cell(b["user_id"]), cell(b["group_id"]), cell(b["policy_expr"]), cell(b["eval_mode"])})
		}
		out.table([]string{"ID", "TYPE", "USER_ID", "GROUP_ID", "POLICY", "EVAL"}, rows)
		return nil
	case "create":
		return bindingsCreate(ctx, c, out, args[1:])
	case "delete":
		if len(args) != 3 {
			return usagef("bindings delete <app-id> <binding-id>")
		}
		if _, err := c.do(ctx, "DELETE", "/api/admin/apps/"+args[1]+"/bindings/"+args[2], nil, nil); err != nil {
			return err
		}
		out.line("deleted binding %s", args[2])
		return nil
	default:
		return usagef("unknown bindings action %q\n%s", args[0], bindingsUsage)
	}
}

func bindingsCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("bindings create", flag.ContinueOnError)
	btype := fs.String("type", "", "user|group|policy (required)")
	userID := fs.String("user", "", "user id (for --type user)")
	groupID := fs.String("group", "", "group id (for --type group)")
	policy := fs.String("policy", "", "policy expression (for --type policy)")
	eval := fs.String("eval", "", "any|all")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 || *btype == "" {
		return usagef("bindings create <app-id> --type user|group|policy [...]")
	}
	resp, err := c.do(ctx, "POST", "/api/admin/apps/"+rest[0]+"/bindings", nil, map[string]any{
		"binding_type": *btype, "user_id": *userID, "group_id": *groupID,
		"policy_expr": *policy, "eval_mode": *eval,
	})
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	b := obj(resp, "binding")
	out.table([]string{"ID", "TYPE", "USER_ID", "GROUP_ID", "POLICY", "EVAL"},
		[][]string{{cell(b["id"]), cell(b["binding_type"]), cell(b["user_id"]),
			cell(b["group_id"]), cell(b["policy_expr"]), cell(b["eval_mode"])}})
	return nil
}
