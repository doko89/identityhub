package ldap

import (
	"fmt"
	"strconv"
	"strings"
)

// This file implements a minimal LDAP search-filter evaluator (RFC 4515
// subset): equality, presence, substrings, AND, OR and NOT. Real clients
// (go-ldap, SSSD, VPN boxes) bind with simple filters such as
// (uid=alice) or (&(objectClass=inetOrgPerson)(uid=alice)); the
// evaluator covers those plus the negations and substring forms that
// address books send. Approximate match (~=) is treated as equality;
// ordering (>=, <=) and extensible matches have no meaning on our
// string attributes and never match.

// filterOp is one evaluated filter node.
type filterOp int

const (
	opAnd filterOp = iota
	opOr
	opNot
	opEquality
	opPresent
	opSubstring
	opNever // valid syntax with no meaning here (>=, <=, extensible)
)

// filter is a parsed search filter ready to match entries.
type filter struct {
	op       filterOp
	attr     string // lowercase attribute name (equality/present/substring)
	value    string // unescaped assertion value (equality)
	norm     string // value canonicalized for DN-valued equality ("", unusable, when not a DN)
	sub      []string
	subFinal bool // substring ends with a literal (no trailing *)
	children []*filter
}

// dnValued reports whether attr holds DNs (distinguishedNameMatch:
// spacing/casing-insensitive comparison after normalization).
func dnValued(attr string) bool {
	switch attr {
	case "member", "memberof", "uniquemember":
		return true
	}
	return false
}

// unsupported reports whether the tree holds a node that can never match
// (>=, <=, extensible). Callers log these: a box sending nested-group
// matching rules would otherwise see silent empty results.
func (f *filter) unsupported() bool {
	if f.op == opNever {
		return true
	}
	for _, k := range f.children {
		if k.unsupported() {
			return true
		}
	}
	return false
}

// entry is one searchable directory entry: DN plus lowercase attribute
// names to values.
type entry struct {
	dn    string
	attrs map[string][]string
}

// attr returns the values of a lowercase attribute name.
func (e entry) attr(name string) []string { return e.attrs[strings.ToLower(name)] }

// parseFilter parses one LDAP filter string.
func parseFilter(s string) (*filter, error) {
	p := &filterParser{s: s}
	f, err := p.parse()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.s) {
		return nil, fmt.Errorf("ldap: trailing data after filter: %q", s[p.pos:])
	}
	return f, nil
}

type filterParser struct {
	s   string
	pos int
}

func (p *filterParser) parse() (*filter, error) {
	if !p.consume('(') {
		return nil, fmt.Errorf("ldap: filter must start with '(': %q", p.s)
	}
	f, err := p.parseBody()
	if err != nil {
		return nil, err
	}
	if !p.consume(')') {
		return nil, fmt.Errorf("ldap: unterminated filter: %q", p.s)
	}
	return f, nil
}

func (p *filterParser) parseBody() (*filter, error) {
	if p.pos >= len(p.s) {
		return nil, fmt.Errorf("ldap: empty filter: %q", p.s)
	}
	switch p.s[p.pos] {
	case '&':
		p.pos++
		kids, err := p.parseMany()
		if err != nil {
			return nil, err
		}
		if len(kids) == 0 {
			return nil, fmt.Errorf("ldap: empty AND filter: %q", p.s)
		}
		return &filter{op: opAnd, children: kids}, nil
	case '|':
		p.pos++
		kids, err := p.parseMany()
		if err != nil {
			return nil, err
		}
		if len(kids) == 0 {
			return nil, fmt.Errorf("ldap: empty OR filter: %q", p.s)
		}
		return &filter{op: opOr, children: kids}, nil
	case '!':
		p.pos++
		kid, err := p.parse()
		if err != nil {
			return nil, err
		}
		return &filter{op: opNot, children: []*filter{kid}}, nil
	}
	return p.parseSimple()
}

// parseMany parses one or more '(' filters (stops at the parent ')').
func (p *filterParser) parseMany() ([]*filter, error) {
	var out []*filter
	for p.pos < len(p.s) && p.s[p.pos] == '(' {
		kid, err := p.parse()
		if err != nil {
			return nil, err
		}
		out = append(out, kid)
	}
	return out, nil
}

// parseSimple parses attr=value, attr=*, attr=a*b, attr~=v, attr>=v,
// attr<=v and extensible attr:=v / attr:rule:=v forms.
func (p *filterParser) parseSimple() (*filter, error) {
	start := p.pos
	for p.pos < len(p.s) && !strings.ContainsRune("~=<>():", rune(p.s[p.pos])) {
		p.pos++
	}
	attr := strings.ToLower(p.s[start:p.pos])
	if attr == "" || p.pos >= len(p.s) {
		return nil, fmt.Errorf("ldap: bad filter attribute: %q", p.s)
	}
	// Extensible match (attr:rule:=value or attr:=value): valid syntax,
	// no meaning on our string attributes.
	if p.s[p.pos] == ':' {
		end := strings.IndexByte(p.s[p.pos:], ')')
		if end < 0 {
			return nil, fmt.Errorf("ldap: unterminated filter: %q", p.s)
		}
		p.pos += end
		return &filter{op: opNever}, nil
	}
	cmp := p.s[p.pos]
	p.pos++
	if cmp == '>' || cmp == '<' {
		if p.pos >= len(p.s) || p.s[p.pos] != '=' {
			return nil, fmt.Errorf("ldap: bad filter operator: %q", p.s)
		}
		p.pos++
		end := strings.IndexByte(p.s[p.pos:], ')')
		if end < 0 {
			return nil, fmt.Errorf("ldap: unterminated filter: %q", p.s)
		}
		p.pos += end
		return &filter{op: opNever}, nil
	}
	if cmp != '=' && cmp != '~' {
		return nil, fmt.Errorf("ldap: bad filter operator: %q", p.s)
	}
	if cmp == '~' {
		if p.pos >= len(p.s) || p.s[p.pos] != '=' {
			return nil, fmt.Errorf("ldap: bad filter operator: %q", p.s)
		}
		p.pos++
	}
	end := strings.IndexByte(p.s[p.pos:], ')')
	if end < 0 {
		return nil, fmt.Errorf("ldap: unterminated filter: %q", p.s)
	}
	raw := p.s[p.pos : p.pos+end]
	p.pos += end
	if raw == "*" {
		return &filter{op: opPresent, attr: attr}, nil
	}
	if !strings.Contains(raw, "*") {
		v, err := unescapeFilterValue(raw)
		if err != nil {
			return nil, err
		}
		f := &filter{op: opEquality, attr: attr, value: v}
		// Served DNs are already canonical, so normalizing the
		// assertion once at parse time is enough for the match.
		if dnValued(attr) {
			if norm, err := normalizeDN(v); err == nil {
				f.norm = norm
			}
		}
		return f, nil
	}
	parts := strings.Split(raw, "*")
	sub := make([]string, 0, len(parts))
	for _, part := range parts {
		v, err := unescapeFilterValue(part)
		if err != nil {
			return nil, err
		}
		sub = append(sub, v)
	}
	return &filter{op: opSubstring, attr: attr, sub: sub, subFinal: !strings.HasSuffix(raw, "*")}, nil
}

func (p *filterParser) consume(c byte) bool {
	if p.pos < len(p.s) && p.s[p.pos] == c {
		p.pos++
		return true
	}
	return false
}

// unescapeFilterValue decodes \XX hex escapes in an assertion value.
func unescapeFilterValue(s string) (string, error) {
	if !strings.Contains(s, "\\") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("ldap: bad escape in filter value %q", s)
		}
		n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", fmt.Errorf("ldap: bad escape in filter value %q", s)
		}
		b.WriteByte(byte(n))
		i += 2
	}
	return b.String(), nil
}

// shortCircuitUID extracts a uid equality from a filter when every match
// must satisfy it: a bare (uid=x) or an AND (possibly nested)
// containing one. It lets the search resolve one indexed row instead of
// scanning the tree. OR, NOT and substring filters keep the full scan.
func shortCircuitUID(f *filter) (string, bool) {
	switch f.op {
	case opEquality:
		if f.attr == "uid" {
			return f.value, true
		}
	case opAnd:
		for _, k := range f.children {
			if v, ok := shortCircuitUID(k); ok {
				return v, ok
			}
		}
	}
	return "", false
}

// match reports whether the filter matches the entry. Attribute names
// compare case-insensitively; string values use case-insensitive
// equality (caseIgnoreMatch, the rule for uid/cn/mail).
func (f *filter) match(e entry) bool {
	switch f.op {
	case opAnd:
		for _, k := range f.children {
			if !k.match(e) {
				return false
			}
		}
		return true
	case opOr:
		for _, k := range f.children {
			if k.match(e) {
				return true
			}
		}
		return false
	case opNot:
		return !f.children[0].match(e)
	case opPresent:
		if f.attr == "objectclass" {
			return true
		}
		return len(e.attr(f.attr)) > 0
	case opEquality:
		if f.attr == "objectclass" {
			// Every entry carries objectClass; "*" is handled as
			// presence above, so compare class names here.
			for _, v := range e.attr("objectclass") {
				if strings.EqualFold(v, f.value) {
					return true
				}
			}
			return false
		}
		if f.norm != "" {
			// DN-valued equality: the served values are canonical,
			// so the normalized assertion compares directly
			// (case-insensitively, like every other value here).
			for _, v := range e.attr(f.attr) {
				if strings.EqualFold(v, f.norm) {
					return true
				}
			}
			return false
		}
		for _, v := range e.attr(f.attr) {
			if strings.EqualFold(v, f.value) {
				return true
			}
		}
		return false
	case opSubstring:
		for _, v := range e.attr(f.attr) {
			if matchSubstring(v, f.sub, f.subFinal) {
				return true
			}
		}
		return false
	case opNever:
		return false
	}
	return false
}

// matchSubstring reports whether v contains the parts in order. The
// first part anchors at the start unless the filter began with '*'
// (empty parts[0]); the last part anchors at the end when final.
func matchSubstring(v string, parts []string, final bool) bool {
	v = strings.ToLower(v)
	pos := 0
	for i, part := range parts {
		part = strings.ToLower(part)
		if part == "" {
			continue
		}
		if i == 0 {
			if !strings.HasPrefix(v, part) {
				return false
			}
			pos = len(part)
			continue
		}
		idx := strings.Index(v[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}
	if final && len(parts) > 0 {
		if last := strings.ToLower(parts[len(parts)-1]); last != "" && !strings.HasSuffix(v, last) {
			return false
		}
	}
	return true
}
