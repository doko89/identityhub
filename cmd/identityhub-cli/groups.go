package main

import (
	"context"
	"flag"
)

const groupsUsage = `usage:
  groups list [--limit N] [--offset N]
  groups get <id>
  groups create --name NAME [--description TEXT]
  groups delete <id>
  groups members add <group-id> --user <user-id>
  groups members remove <group-id> --user <user-id>`

func groupsCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", groupsUsage)
	}
	switch args[0] {
	case "list":
		return groupsList(ctx, c, out, args[1:])
	case "get":
		return groupsGet(ctx, c, out, args[1:])
	case "create":
		return groupsCreate(ctx, c, out, args[1:])
	case "delete":
		return groupsDelete(ctx, c, out, args[1:])
	case "members":
		return groupMembers(ctx, c, out, args[1:])
	default:
		return usagef("unknown groups action %q\n%s", args[0], groupsUsage)
	}
}

func groupsList(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("groups list", flag.ContinueOnError)
	page := pageFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := c.do(ctx, "GET", "/api/admin/groups", page(), nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "groups") {
		g := asObj(e)
		rows = append(rows, []string{cell(g["id"]), cell(g["name"]), cell(g["description"]), cell(g["member_count"])})
	}
	out.table([]string{"ID", "NAME", "DESCRIPTION", "MEMBERS"}, rows)
	out.line("total: %s", cell(asObj(resp)["total"]))
	return nil
}

func groupsGet(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("groups get <id>")
	}
	resp, err := c.do(ctx, "GET", "/api/admin/groups/"+args[0], nil, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	g := obj(resp, "group")
	out.table([]string{"ID", "NAME", "DESCRIPTION", "MEMBER_IDS"},
		[][]string{{cell(g["id"]), cell(g["name"]), cell(g["description"]), cell(g["members"])}})
	return nil
}

func groupsCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("groups create", flag.ContinueOnError)
	name := fs.String("name", "", "group name (required)")
	desc := fs.String("description", "", "group description")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return usagef("groups create requires --name")
	}
	resp, err := c.do(ctx, "POST", "/api/admin/groups", nil,
		map[string]any{"name": *name, "description": *desc})
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	g := obj(resp, "group")
	out.table([]string{"ID", "NAME", "DESCRIPTION"},
		[][]string{{cell(g["id"]), cell(g["name"]), cell(g["description"])}})
	return nil
}

func groupsDelete(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("groups delete <id>")
	}
	if _, err := c.do(ctx, "DELETE", "/api/admin/groups/"+args[0], nil, nil); err != nil {
		return err
	}
	out.line("deleted group %s", args[0])
	return nil
}

func groupMembers(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) < 1 || (args[0] != "add" && args[0] != "remove") {
		return usagef("groups members <add|remove> <group-id> --user <user-id>")
	}
	action := args[0]
	fs := flag.NewFlagSet("groups members "+action, flag.ContinueOnError)
	userID := fs.String("user", "", "user id (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 || *userID == "" {
		return usagef("groups members %s <group-id> --user <user-id>", action)
	}
	path := "/api/admin/groups/" + rest[0] + "/members"
	if action == "add" {
		if _, err := c.do(ctx, "POST", path, nil, map[string]any{"user_id": *userID}); err != nil {
			return err
		}
		out.line("added %s to group %s", *userID, rest[0])
		return nil
	}
	if _, err := c.do(ctx, "DELETE", path+"/"+*userID, nil, nil); err != nil {
		return err
	}
	out.line("removed %s from group %s", *userID, rest[0])
	return nil
}
