// Package ldap serves IdentityHub users and groups over the LDAP
// protocol (TECH_SPEC §6.4) via github.com/vjeantet/ldapserver.
// Credentials always verify through usecase/auth (LoginLegacy), so
// legacy binds share password policy, directory JIT and audit with
// every other login path. Binds stay password-only: no MFA gate
// applies here (MFA is enforced at web login and app launch).
//
// Served tree (v1 is a single global tree; per-app search bases from
// ldap_provider_config arrive with the app catalog):
//
//	dc=identityhub
//	ou=users,dc=identityhub      (inetOrgPerson per active user)
//	ou=groups,dc=identityhub     (groupOfNames per group)
//
// Bind DN: uid=<username>,ou=users,dc=identityhub + password.
package ldap

import (
	"errors"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// Served naming contexts (TECH_SPEC §6.4 bind DN template). These are
// the defaults; LDAP_SERVE_BASE_DN overrides the base (see DNTree)
// while ou=users/ou=groups stay fixed.
const (
	BaseDN   = "dc=identityhub"
	UsersDN  = "ou=users,dc=identityhub"
	GroupsDN = "ou=groups,dc=identityhub"
)

// Connection modes, mirroring config LDAP_MODE values.
const (
	ModePlain    = "ldap"
	ModeLDAPS    = "ldaps"
	ModeStartTLS = "starttls"
)

// rdnAttr is one lowercased, trimmed type=value pair of a parsed base.
type rdnAttr struct {
	typ string
	val string
}

// DNTree is the served naming context: a base DN plus the fixed
// ou=users/ou=groups containers. Servers serving a configured base
// hold one; the package-level UserDN/GroupDN/ParseBindDN helpers below
// serve the default tree.
type DNTree struct {
	Base   string
	Users  string
	Groups string
	base   []rdnAttr
}

// NewDNTree validates a configured base DN. Multi-DC bases like
// dc=example,dc=com are fine; multi-valued RDNs are refused.
func NewDNTree(base string) (DNTree, error) {
	base = strings.TrimSpace(base)
	parsed, err := goldap.ParseDN(base)
	if err != nil || len(parsed.RDNs) == 0 {
		return DNTree{}, fmt.Errorf("ldap: invalid base DN %q", base)
	}
	attrs := make([]rdnAttr, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		if len(rdn.Attributes) != 1 {
			return DNTree{}, fmt.Errorf("ldap: base DN must use single-valued RDNs: %q", base)
		}
		a := rdn.Attributes[0]
		attrs = append(attrs, rdnAttr{
			typ: strings.ToLower(strings.TrimSpace(a.Type)),
			val: strings.TrimSpace(a.Value),
		})
	}
	return DNTree{
		Base: base, Users: "ou=users," + base, Groups: "ou=groups," + base,
		base: attrs,
	}, nil
}

var defaultTree = func() DNTree {
	t, err := NewDNTree(BaseDN)
	if err != nil {
		panic("ldap: invalid default base DN: " + err.Error())
	}
	return t
}()

// UserDN builds the bind/search DN for username under the default tree.
func UserDN(username string) string { return defaultTree.UserDN(username) }

// GroupDN builds the search DN for a group name under the default tree.
func GroupDN(name string) string { return defaultTree.GroupDN(name) }

// ParseBindDN extracts the username from a bind DN under the default
// tree (case and whitespace insensitive).
func ParseBindDN(dn string) (string, error) { return defaultTree.ParseBindDN(dn) }

// UserDN builds the bind/search DN for username.
func (t DNTree) UserDN(username string) string {
	return "uid=" + escapeDNValue(username) + "," + t.Users
}

// GroupDN builds the search DN for a group name.
func (t DNTree) GroupDN(name string) string {
	return "cn=" + escapeDNValue(name) + "," + t.Groups
}

// ParseBindDN extracts the username from a bind DN of the form
// uid=<username>,ou=users,<base> (case and whitespace insensitive).
// Anything else is rejected with a hint for integrators.
func (t DNTree) ParseBindDN(dn string) (string, error) {
	hint := "bind DN must look like uid=<username>," + t.Users
	parsed, err := goldap.ParseDN(strings.TrimSpace(dn))
	if err != nil {
		return "", fmt.Errorf("%s: %v", hint, err)
	}
	if len(parsed.RDNs) != len(t.base)+2 {
		return "", errors.New(hint)
	}
	uid := parsed.RDNs[0]
	if len(uid.Attributes) != 1 || !strings.EqualFold(uid.Attributes[0].Type, "uid") {
		return "", errors.New(hint)
	}
	username := strings.TrimSpace(uid.Attributes[0].Value)
	if username == "" {
		return "", errors.New(hint)
	}
	ou := parsed.RDNs[1]
	if len(ou.Attributes) != 1 || !strings.EqualFold(ou.Attributes[0].Type, "ou") ||
		!strings.EqualFold(strings.TrimSpace(ou.Attributes[0].Value), "users") {
		return "", errors.New(hint)
	}
	for i, want := range t.base {
		got := parsed.RDNs[i+2]
		if len(got.Attributes) != 1 ||
			!strings.EqualFold(strings.TrimSpace(got.Attributes[0].Type), want.typ) ||
			!strings.EqualFold(strings.TrimSpace(got.Attributes[0].Value), want.val) {
			return "", errors.New(hint)
		}
	}
	return username, nil
}

// ParseGroupDN extracts the group name from cn=<name>,ou=groups,<base>.
// The tail compares normalized so spaced multi-DC spellings
// ("ou=groups, dc=example, dc=com") match.
func (t DNTree) ParseGroupDN(dn string) (string, error) {
	rest, ok := cutPrefixFold(strings.TrimSpace(dn), "cn=")
	if !ok {
		return "", errors.New("not a group dn")
	}
	comma := strings.Index(rest, ",")
	if comma < 0 {
		return "", errors.New("not a group dn")
	}
	name := unescapeDNValue(strings.TrimSpace(rest[:comma]))
	normal, err := normalizeDN(strings.TrimSpace(rest[comma+1:]))
	want, werr := normalizeDN(t.Groups)
	if name == "" || err != nil || werr != nil || normal != want {
		return "", errors.New("not a group dn")
	}
	return name, nil
}

// parseGroupDN extracts the group name under the default tree.
func parseGroupDN(dn string) (string, error) { return defaultTree.ParseGroupDN(dn) }

// baseDomain is the domainEntry dc value: the first dc RDN of the base,
// else the first RDN value, else the raw base.
func (t DNTree) baseDomain() string {
	for _, a := range t.base {
		if a.typ == "dc" {
			return a.val
		}
	}
	if len(t.base) > 0 {
		return t.base[0].val
	}
	return t.Base
}

// escapeDNValue escapes characters that are special inside a DN
// attribute value (RFC 4514 §2.4).
func escapeDNValue(v string) string {
	var b strings.Builder
	for i, r := range v {
		special := r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';'
		leading := i == 0 && (r == ' ' || r == '#')
		if special || leading || (r == ' ' && i == len(v)-1) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sameDN reports DN equality under normalized comparison (the tree has
// one spelling, so lowercase comparison is enough here).
func sameDN(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// normalizeDN canonicalizes a DN for value comparison: lowercase
// attribute types, trimmed values, no whitespace between RDNs. VPN boxes
// and sync tools substitute their own DN templates into member= filters,
// and those spellings (extra spaces, uppercased OU/DC) must still match
// the served values.
func normalizeDN(dn string) (string, error) {
	parsed, err := goldap.ParseDN(strings.TrimSpace(dn))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i, rdn := range parsed.RDNs {
		if i > 0 {
			b.WriteByte(',')
		}
		for j, a := range rdn.Attributes {
			if j > 0 {
				b.WriteByte('+')
			}
			b.WriteString(strings.ToLower(strings.TrimSpace(a.Type)))
			b.WriteByte('=')
			// Values re-escape on rebuild: the parser decoded
			// `\,` to a bare comma, which must not leak back as
			// an RDN separator.
			b.WriteString(escapeDNValue(strings.TrimSpace(a.Value)))
		}
	}
	return b.String(), nil
}
