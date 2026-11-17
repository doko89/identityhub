package ldap

import (
	"testing"
)

func testEntry() entry {
	return entry{
		dn: UserDN("ara"),
		attrs: map[string][]string{
			"objectclass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
			"uid":         {"ara"},
			"cn":          {"Ara Example"},
			"sn":          {"Ara Example"},
			"mail":        {"ara@example.com"},
			"memberof":    {GroupDN("eng")},
		},
	}
}

func TestFilterMatch(t *testing.T) {
	e := testEntry()
	cases := []struct {
		filter string
		want   bool
	}{
		{"(objectClass=*)", true},
		{"(uid=*)", true},
		{"(nosuchattr=*)", false},
		{"(uid=ara)", true},
		{"(UID=ARA)", true},
		{"(uid=bob)", false},
		{"(cn=Ara Example)", true},
		{"(mail=ara@example.com)", true},
		{"(objectClass=inetOrgPerson)", true},
		{"(objectClass=groupOfNames)", false},
		{"(&(uid=ara)(mail=ara@example.com))", true},
		{"(&(uid=ara)(mail=bob@example.com))", false},
		{"(|(uid=bob)(uid=ara))", true},
		{"(|(uid=bob)(uid=ann))", false},
		{"(!(uid=ara))", false},
		{"(!(uid=bob))", true},
		{"(uid=ar*)", true},
		{"(uid=*ra)", true},
		{"(uid=*r*)", true},
		{"(uid=a*a)", true},
		{"(uid=b*)", false},
		{"(uid=*b)", false},
		{"(uid=ara*bob)", false},
		{"(uid~=ara)", true}, // approximate degrades to equality
		{"(uid>=ara)", false},
		{"(uid<=ara)", false},
		{"(uid:caseExactMatch:=ara)", false},
		{`(|(uid=ara)(uid=b\6fb))`, true}, // hex escape decodes to 'bob'
		{"(&(|(uid=bob)(uid=ara))(!(mail=bob@example.com)))", true},
	}
	for _, tc := range cases {
		t.Run(tc.filter, func(t *testing.T) {
			f, err := parseFilter(tc.filter)
			if err != nil {
				t.Fatalf("parseFilter(%q) = %v", tc.filter, err)
			}
			if got := f.match(e); got != tc.want {
				t.Errorf("match(%q) = %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

func TestShortCircuitUID(t *testing.T) {
	cases := []struct {
		filter string
		uid    string
		ok     bool
	}{
		{"(uid=ara)", "ara", true},
		{"(UID=ARA)", "ARA", true}, // value keeps its case; lookup folds
		{"(&(uid=ara)(mail=ara@example.com))", "ara", true},
		{"(&(objectClass=inetOrgPerson)(uid=ara))", "ara", true},
		{"(&(&(uid=ara)(cn=x))(mail=y))", "ara", true}, // nested AND
		{"(&(uid=a)(uid=b))", "a", true},               // full match still rejects
		{"(uid=*)", "", false},
		{"(uid=ar*)", "", false},
		{"(cn=ara)", "", false},
		{"(|(uid=ara)(uid=bob))", "", false},
		{"(!(uid=ara))", "", false},
		{"(|(&(uid=ara)(cn=x))(uid=bob))", "", false},
		{"(uid~=ara)", "ara", true}, // approximate degrades to equality
		{"(uid>=ara)", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.filter, func(t *testing.T) {
			f, err := parseFilter(tc.filter)
			if err != nil {
				t.Fatalf("parseFilter(%q) = %v", tc.filter, err)
			}
			uid, ok := shortCircuitUID(f)
			if uid != tc.uid || ok != tc.ok {
				t.Errorf("shortCircuitUID(%q) = (%q, %v), want (%q, %v)",
					tc.filter, uid, ok, tc.uid, tc.ok)
			}
		})
	}
}

func TestFilterParseErrors(t *testing.T) {
	for _, s := range []string{
		"",
		"uid=ara",
		"(uid=ara",
		"(uid=ara))",
		"()",
		"(&)",
		"(|)",
		"(!)",
		"(=ara)",
		"(!(!(uid=ara)))extra",
		`(uid=ab\zz)`,
		`(uid=ab\1)`,
	} {
		if _, err := parseFilter(s); err == nil {
			t.Errorf("parseFilter(%q) = nil, want error", s)
		}
	}
}
