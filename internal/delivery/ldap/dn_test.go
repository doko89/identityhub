package ldap

import (
	"testing"
)

func TestParseBindDN(t *testing.T) {
	cases := []struct {
		dn   string
		want string
	}{
		{"uid=ara,ou=users,dc=identityhub", "ara"},
		{"UID=ara,OU=users,DC=identityhub", "ara"},
		{"  uid=ara , ou=users , dc=identityhub  ", "ara"},
		{`uid=ara\,x,ou=users,dc=identityhub`, "ara,x"},
	}
	for _, tc := range cases {
		t.Run(tc.dn, func(t *testing.T) {
			got, err := ParseBindDN(tc.dn)
			if err != nil {
				t.Fatalf("ParseBindDN = %v", err)
			}
			if got != tc.want {
				t.Errorf("username = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeDN(t *testing.T) {
	cases := []struct {
		dn   string
		want string
	}{
		{"uid=ara,ou=users,dc=identityhub", "uid=ara,ou=users,dc=identityhub"},
		{"uid=ara, ou=users, dc=identityhub", "uid=ara,ou=users,dc=identityhub"},
		{"UID=Ara,OU=Users,DC=IdentityHub", "uid=Ara,ou=Users,dc=IdentityHub"},
		{`cn=a\,b,ou=groups,dc=identityhub`, `cn=a\,b,ou=groups,dc=identityhub`},
	}
	for _, tc := range cases {
		t.Run(tc.dn, func(t *testing.T) {
			got, err := normalizeDN(tc.dn)
			if err != nil {
				t.Fatalf("normalizeDN = %v", err)
			}
			if got != tc.want {
				t.Errorf("normalized = %q, want %q", got, tc.want)
			}
		})
	}
	if _, err := normalizeDN("not-a-dn"); err == nil {
		t.Error("normalizeDN(not-a-dn) succeeded, want error")
	}
}

func TestParseBindDNRejects(t *testing.T) {
	for _, dn := range []string{
		"",
		"ara",
		"cn=ara,ou=users,dc=identityhub",
		"uid=ara,ou=groups,dc=identityhub",
		"uid=ara,ou=users,dc=example,dc=com",
		"uid=ara,dc=identityhub",
		"uid=,ou=users,dc=identityhub",
		"uid=ara+cn=x,ou=users,dc=identityhub",
		"not a dn ((((",
	} {
		if got, err := ParseBindDN(dn); err == nil {
			t.Errorf("ParseBindDN(%q) = %q, want error", dn, got)
		}
	}
}

func TestDNTreeCustomBase(t *testing.T) {
	tree, err := NewDNTree("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	if tree.Users != "ou=users,dc=example,dc=com" || tree.Groups != "ou=groups,dc=example,dc=com" {
		t.Fatalf("containers = %q %q", tree.Users, tree.Groups)
	}
	if got := tree.UserDN("ara"); got != "uid=ara,ou=users,dc=example,dc=com" {
		t.Errorf("UserDN = %q", got)
	}
	if got := tree.GroupDN("eng"); got != "cn=eng,ou=groups,dc=example,dc=com" {
		t.Errorf("GroupDN = %q", got)
	}
	got, err := tree.ParseBindDN("uid=ara,ou=users,dc=example,dc=com")
	if err != nil || got != "ara" {
		t.Errorf("ParseBindDN = %q, %v", got, err)
	}
	// Spaced multi-DC spellings match; other bases do not.
	got, err = tree.ParseBindDN("uid=ara, ou=users, dc=example, dc=com")
	if err != nil || got != "ara" {
		t.Errorf("spaced ParseBindDN = %q, %v", got, err)
	}
	if _, err := tree.ParseBindDN("uid=ara,ou=users,dc=identityhub"); err == nil {
		t.Error("foreign base accepted, want error")
	}
	if _, err := tree.ParseBindDN("uid=ara,ou=users,dc=example"); err == nil {
		t.Error("short base accepted, want error")
	}
	if got, err := tree.ParseGroupDN("cn=eng, ou=groups, dc=example, dc=com"); err != nil || got != "eng" {
		t.Errorf("ParseGroupDN = %q, %v", got, err)
	}
	for _, bad := range []string{"", "not-a-dn", "cn=eng+ou=x,dc=example,dc=com"} {
		if _, err := NewDNTree(bad); err == nil {
			t.Errorf("NewDNTree(%q) succeeded, want error", bad)
		}
	}
}

func TestUserAndGroupDN(t *testing.T) {
	if got := UserDN("ara"); got != "uid=ara,ou=users,dc=identityhub" {
		t.Errorf("UserDN = %q", got)
	}
	if got := GroupDN("eng"); got != "cn=eng,ou=groups,dc=identityhub" {
		t.Errorf("GroupDN = %q", got)
	}
	// Special characters are escaped so the DN round-trips.
	roundTrip, err := ParseBindDN(UserDN("ara,x"))
	if err != nil {
		t.Fatalf("escaped DN rejected: %v", err)
	}
	if roundTrip != "ara,x" {
		t.Errorf("round trip = %q, want %q", roundTrip, "ara,x")
	}
}
