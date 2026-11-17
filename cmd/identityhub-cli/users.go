package main

import (
	"context"
	"flag"
	"net/url"
)

const usersUsage = `usage:
  users list [--q QUERY] [--source local|ldap] [--active true|false] [--limit N] [--offset N]
  users get <id>
  users create --username NAME --email EMAIL --password PASS [--display-name NAME] [--source local|ldap] [--external-dn DN]
  users update <id> [--display-name NAME] [--email EMAIL] [--avatar-url URL] [--active true|false]
  users set-password <id> [--password PASS]
  users mfa-reset <id>`

func usersCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", usersUsage)
	}
	switch args[0] {
	case "list":
		return usersList(ctx, c, out, args[1:])
	case "get":
		return usersGet(ctx, c, out, args[1:])
	case "create":
		return usersCreate(ctx, c, out, args[1:])
	case "update":
		return usersUpdate(ctx, c, out, args[1:])
	case "set-password":
		return usersSetPassword(ctx, c, out, args[1:])
	case "mfa-reset":
		return usersMFAReset(ctx, c, out, args[1:])
	default:
		return usagef("unknown users action %q\n%s", args[0], usersUsage)
	}
}

var userHeader = []string{"ID", "USERNAME", "EMAIL", "SOURCE", "ACTIVE", "ADMIN", "GROUPS"}

func userRow(u map[string]any) []string {
	return []string{cell(u["id"]), cell(u["username"]), cell(u["email"]),
		cell(u["source"]), cell(u["is_active"]), cell(u["is_admin"]), cell(u["groups"])}
}

func usersList(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("users list", flag.ContinueOnError)
	q := fs.String("q", "", "search query")
	source := fs.String("source", "", "local|ldap")
	active := fs.String("active", "", "true|false")
	page := pageFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	query := page()
	if *q != "" {
		query.Set("q", *q)
	}
	if *source != "" {
		query.Set("source", *source)
	}
	if *active != "" {
		query.Set("active", *active)
	}
	resp, err := c.do(ctx, "GET", "/api/admin/users", query, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "users") {
		rows = append(rows, userRow(asObj(e)))
	}
	out.table(userHeader, rows)
	out.line("total: %s", cell(asObj(resp)["total"]))
	return nil
}

func usersGet(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("users get <id>")
	}
	resp, err := c.do(ctx, "GET", "/api/admin/users/"+args[0], nil, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	out.table(userHeader, [][]string{userRow(obj(resp, "user"))})
	return nil
}

func usersCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("users create", flag.ContinueOnError)
	username := fs.String("username", "", "login name (required)")
	email := fs.String("email", "", "email address (required)")
	password := fs.String("password", "", "initial password (prompted when omitted)")
	display := fs.String("display-name", "", "display name")
	source := fs.String("source", "", "local|ldap")
	externalDN := fs.String("external-dn", "", "directory DN for pre-provisioned LDAP users")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *email == "" {
		return usagef("users create requires --username and --email")
	}
	pass := *password
	if pass == "" && *source != "ldap" {
		var err error
		if pass, err = promptSecret("Password"); err != nil {
			return err
		}
	}
	resp, err := c.do(ctx, "POST", "/api/admin/users", nil, map[string]any{
		"username": *username, "email": *email, "password": pass,
		"display_name": *display, "source": *source, "external_dn": *externalDN,
	})
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	out.table(userHeader, [][]string{userRow(obj(resp, "user"))})
	return nil
}

func usersUpdate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("users update", flag.ContinueOnError)
	var display, email, avatar, active optional
	fs.Var(&display, "display-name", "new display name")
	fs.Var(&email, "email", "new email")
	fs.Var(&avatar, "avatar-url", "new avatar URL")
	fs.Var(&active, "active", "true|false (deactivation revokes sessions)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return usagef("users update <id> [flags]")
	}
	body := map[string]any{}
	if display.set {
		body["display_name"] = display.value
	}
	if email.set {
		body["email"] = email.value
	}
	if avatar.set {
		body["avatar_url"] = avatar.value
	}
	if v, ok, err := active.optBool(); err != nil {
		return usagef("invalid --active: %v", err)
	} else if ok {
		body["is_active"] = v
	}
	if len(body) == 0 {
		return usagef("users update <id> needs at least one field flag")
	}
	resp, err := c.do(ctx, "PATCH", "/api/admin/users/"+rest[0], nil, body)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	out.table(userHeader, [][]string{userRow(obj(resp, "user"))})
	return nil
}

func usersSetPassword(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("users set-password", flag.ContinueOnError)
	password := fs.String("password", "", "new password (prompted when omitted)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return usagef("users set-password <id> [--password PASS]")
	}
	pass := *password
	if pass == "" {
		var err error
		if pass, err = promptSecret("New password"); err != nil {
			return err
		}
	}
	if _, err := c.do(ctx, "POST", "/api/admin/users/"+rest[0]+"/password", nil,
		map[string]any{"new_password": pass}); err != nil {
		return err
	}
	out.line("password updated for %s", rest[0])
	return nil
}

func usersMFAReset(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("users mfa-reset <id>")
	}
	if _, err := c.do(ctx, "POST", "/api/admin/users/"+args[0]+"/mfa/reset", url.Values{}, nil); err != nil {
		return err
	}
	out.line("MFA factors cleared for %s; the user re-enrolls at next login", args[0])
	return nil
}
