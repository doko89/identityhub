package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// output prints command results: raw JSON with --json, human tables
// otherwise.
type output struct {
	w    io.Writer
	json bool
}

// printJSON writes v indented.
func (o *output) printJSON(v any) error {
	enc := json.NewEncoder(o.w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// table prints header + rows as padded columns.
func (o *output) table(header []string, rows [][]string) {
	fmt.Fprint(o.w, formatTable(header, rows))
}

// line prints one informational line (suppressed under --json, where the
// response body is the whole output).
func (o *output) line(format string, args ...any) {
	if o.json {
		return
	}
	fmt.Fprintf(o.w, format+"\n", args...)
}

// formatTable pads columns to their widest cell. Two spaces separate
// columns; no trailing whitespace per line.
func formatTable(header []string, rows [][]string) string {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	var b strings.Builder
	writeRow := func(cells []string) {
		for i := range header {
			var cell string
			if i < len(cells) {
				cell = cells[i]
			}
			b.WriteString(cell)
			if i < len(header)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len(cell)+2))
			}
		}
		b.WriteString("\n")
	}
	writeRow(header)
	for _, row := range rows {
		writeRow(row)
	}
	return b.String()
}

// obj navigates a decoded response: obj(resp, "user") returns the nested
// object, objList(resp, "users") the nested array.
func obj(v any, key string) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	o, _ := m[key].(map[string]any)
	if o == nil {
		return map[string]any{}
	}
	return o
}

func objList(v any, key string) []any {
	m, _ := v.(map[string]any)
	if m == nil {
		return nil
	}
	l, _ := m[key].([]any)
	return l
}

func asObj(v any) map[string]any {
	o, _ := v.(map[string]any)
	if o == nil {
		return map[string]any{}
	}
	return o
}

// cell renders one decoded value: nil is blank, numbers print without a
// decimal point when whole, lists join with commas, objects compact to
// JSON.
func cell(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, cell(e))
		}
		return strings.Join(parts, ", ")
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(raw)
	}
}

// shortDate trims an RFC3339 timestamp to its date for narrow tables.
func shortDate(v any) string {
	s, _ := v.(string)
	if len(s) >= 10 && s[4] == '-' {
		return s[:10]
	}
	return s
}
