package main

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"strings"
)

const attrsUsage = `usage:
  attrs defs list
  attrs defs create --key KEY --type string|number|boolean [--multi]
  attrs defs delete <key>
  attrs get <user-id>
  attrs set --set key=value [--set key=value] [--clear key] <user-id>`

func attrsCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", attrsUsage)
	}
	switch args[0] {
	case "defs":
		return attrsDefsCmd(ctx, c, out, args[1:])
	case "get":
		return attrsGet(ctx, c, out, args[1:])
	case "set":
		return attrsSet(ctx, c, out, args[1:])
	default:
		return usagef("unknown attrs action %q\n%s", args[0], attrsUsage)
	}
}

func attrsDefsCmd(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) == 0 {
		return usagef("%s", attrsUsage)
	}
	switch args[0] {
	case "list":
		return attrsDefsList(ctx, c, out, args[1:])
	case "create":
		return attrsDefsCreate(ctx, c, out, args[1:])
	case "delete":
		return attrsDefsDelete(ctx, c, out, args[1:])
	default:
		return usagef("unknown attrs defs action %q\n%s", args[0], attrsUsage)
	}
}

var attrDefHeader = []string{"KEY", "TYPE", "MULTI"}

func attrsDefsList(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 0 {
		return usagef("attrs defs list takes no arguments")
	}
	resp, err := c.do(ctx, "GET", "/api/admin/user-attrs", nil, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	var rows [][]string
	for _, e := range objList(resp, "defs") {
		d := asObj(e)
		rows = append(rows, []string{cell(d["key"]), cell(d["type"]), cell(d["multi"])})
	}
	out.table(attrDefHeader, rows)
	return nil
}

func attrsDefsCreate(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("attrs defs create", flag.ContinueOnError)
	key := fs.String("key", "", "attribute key, lowercase LDAP-safe (required)")
	typ := fs.String("type", "", "string|number|boolean (required)")
	multi := fs.Bool("multi", false, "allow multiple values")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" || *typ == "" {
		return usagef("attrs defs create requires --key and --type")
	}
	resp, err := c.do(ctx, "POST", "/api/admin/user-attrs", nil, map[string]any{
		"key": *key, "type": *typ, "multi": *multi,
	})
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	d := obj(resp, "def")
	out.table(attrDefHeader, [][]string{{cell(d["key"]), cell(d["type"]), cell(d["multi"])}})
	return nil
}

func attrsDefsDelete(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("attrs defs delete <key>")
	}
	if _, err := c.do(ctx, "DELETE", "/api/admin/user-attrs/"+args[0], nil, nil); err != nil {
		return err
	}
	out.line("attribute %q deleted with all its values", args[0])
	return nil
}

func attrsGet(ctx context.Context, c *Client, out *output, args []string) error {
	if len(args) != 1 {
		return usagef("attrs get <user-id>")
	}
	resp, err := c.do(ctx, "GET", "/api/admin/users/"+args[0]+"/attrs", nil, nil)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	printAttrs(out, obj(resp, "attrs"))
	return nil
}

// strSlice collects repeatable --set/--clear flags in order.
type strSlice []string

func (s *strSlice) String() string { return strings.Join(*s, ",") }

func (s *strSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func attrsSet(ctx context.Context, c *Client, out *output, args []string) error {
	fs := flag.NewFlagSet("attrs set", flag.ContinueOnError)
	var sets, clears strSlice
	fs.Var(&sets, "set", "key=value (repeat for multi-valued keys)")
	fs.Var(&clears, "clear", "key to clear (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return usagef("attrs set --set key=value [--set key=value] [--clear key] <user-id>")
	}
	if len(sets) == 0 && len(clears) == 0 {
		return usagef("attrs set needs at least one --set or --clear")
	}
	grouped := map[string][]string{}
	for _, s := range sets {
		key, val, ok := strings.Cut(s, "=")
		if !ok || key == "" {
			return usagef("invalid --set %q: want key=value", s)
		}
		grouped[key] = append(grouped[key], val)
	}
	body := map[string]any{}
	for key, vals := range grouped {
		if len(vals) == 1 {
			body[key] = vals[0]
		} else {
			arr := make([]any, 0, len(vals))
			for _, v := range vals {
				arr = append(arr, v)
			}
			body[key] = arr
		}
	}
	for _, key := range clears {
		if key == "" {
			return usagef("--clear needs a key")
		}
		if _, dup := body[key]; dup {
			return usagef("key %q is both --set and --clear", key)
		}
		body[key] = nil
	}
	resp, err := c.do(ctx, "PUT", "/api/admin/users/"+rest[0]+"/attrs", nil, body)
	if err != nil {
		return err
	}
	if out.json {
		return out.printJSON(resp)
	}
	printAttrs(out, obj(resp, "attrs"))
	return nil
}

// printAttrs renders a typed attrs map sorted by key.
func printAttrs(out *output, attrs map[string]any) {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{k, cell(attrs[k])})
	}
	if len(rows) == 0 {
		fmt.Fprintln(out.w, "(no attributes)")
		return
	}
	out.table([]string{"KEY", "VALUE"}, rows)
}
