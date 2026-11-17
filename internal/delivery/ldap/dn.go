// Package ldap serves IdentityHub users and groups over the LDAP
// protocol (TECH_SPEC §6.4) via github.com/vjeantet/ldapserver.
// Credentials always verify through usecase/auth (LoginLegacy), so
// legacy binds share password policy, directory JIT, audit and the
// deny-when-MFA-required gate with every other login path.
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
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// Served naming contexts (TECH_SPEC §6.4 bind DN template).
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

// UserDN builds the bind/search DN for username.
func UserDN(username string) string {
	return "uid=" + escapeDNValue(username) + "," + UsersDN
}

// GroupDN builds the search DN for a group name.
func GroupDN(name string) string {
	return "cn=" + escapeDNValue(name) + "," + GroupsDN
}

// ParseBindDN extracts the username from a bind DN of the form
// uid=<username>,ou=users,dc=identityhub (case and whitespace
// insensitive). Anything else is rejected with a hint for integrators.
func ParseBindDN(dn string) (string, error) {
	parsed, err := goldap.ParseDN(strings.TrimSpace(dn))
	if err != nil {
		return "", fmt.Errorf("bind DN must look like uid=<username>,%s: %v", UsersDN, err)
	}
	if len(parsed.RDNs) != 3 ||
		len(parsed.RDNs[0].Attributes) != 1 ||
		!strings.EqualFold(parsed.RDNs[0].Attributes[0].Type, "uid") ||
		len(parsed.RDNs[1].Attributes) != 1 ||
		!strings.EqualFold(parsed.RDNs[1].Attributes[0].Type, "ou") ||
		!strings.EqualFold(strings.TrimSpace(parsed.RDNs[1].Attributes[0].Value), "users") ||
		len(parsed.RDNs[2].Attributes) != 1 ||
		!strings.EqualFold(parsed.RDNs[2].Attributes[0].Type, "dc") ||
		!strings.EqualFold(strings.TrimSpace(parsed.RDNs[2].Attributes[0].Value), "identityhub") {
		return "", fmt.Errorf("bind DN must look like uid=<username>,%s", UsersDN)
	}
	username := parsed.RDNs[0].Attributes[0].Value
	if username == "" {
		return "", fmt.Errorf("bind DN must look like uid=<username>,%s", UsersDN)
	}
	return username, nil
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
