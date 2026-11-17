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
