package ldapclient

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func validConfig() Config {
	return Config{
		URL:     "ldap://127.0.0.1:38990",
		BaseDN:  "dc=example,dc=com",
		Timeout: 2 * time.Second,
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(validConfig()); err != nil {
		t.Fatalf("New(valid) = %v", err)
	}
	bad := []Config{
		{},
		{BaseDN: "dc=x", Timeout: time.Second}, // no URL
		{URL: "http://x:389", BaseDN: "dc=x", Timeout: time.Second},  // bad scheme
		{URL: "ldap://x:389", Timeout: time.Second},                  // no base DN
		{URL: "ldap://x:389", BaseDN: "dc=x"},                        // no timeout
		{URL: "ldap://x:389", BaseDN: "dc=x", Timeout: -time.Second}, // negative timeout
		{URL: "ldap://", BaseDN: "dc=x", Timeout: time.Second},       // no host
		{URL: "ldap://[::1", BaseDN: "dc=x", Timeout: time.Second},   // unparseable
	}
	for i, cfg := range bad {
		if _, err := New(cfg); err == nil {
			t.Errorf("case %d (%+v): New = nil error, want failure", i, cfg)
		}
	}
}

func TestDefaultsApplied(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.UserAttr != DefaultUserAttr || c.cfg.MailAttr != DefaultMailAttr ||
		c.cfg.DisplayNameAttr != DefaultDisplayNameAttr || c.cfg.MemberOfAttr != DefaultMemberOfAttr ||
		c.cfg.GroupNameAttr != DefaultGroupNameAttr || c.cfg.GroupMemberAttr != DefaultGroupMemberAttr {
		t.Errorf("defaults not applied: %+v", c.cfg)
	}
	custom, err := New(Config{URL: "ldap://x", BaseDN: "dc=x", Timeout: time.Second, UserAttr: "sAMAccountName"})
	if err != nil {
		t.Fatal(err)
	}
	if custom.cfg.UserAttr != "sAMAccountName" {
		t.Errorf("custom UserAttr overwritten: %q", custom.cfg.UserAttr)
	}
}

func TestUserFilterEscapesInput(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := c.userFilter("ara*)(uid=*")
	want := `(uid=ara\2a\29\28uid=\2a)`
	if got != want {
		t.Errorf("userFilter = %q, want %q", got, want)
	}
	withExtra, err := New(Config{URL: "ldap://x", BaseDN: "dc=x", Timeout: time.Second, UserFilter: "(department=IT)"})
	if err != nil {
		t.Fatal(err)
	}
	got = withExtra.userFilter("ara")
	want = `(&(uid=ara)(department=IT))`
	if got != want {
		t.Errorf("userFilter with extra = %q, want %q", got, want)
	}
	if f := withExtra.allGroupsFilter(); f != `(objectClass=groupOfNames)` {
		t.Errorf("allGroupsFilter = %q, want base filter without wrapper", f)
	}
}

func TestMapUser(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	e := ldap.NewEntry("uid=ara,ou=users,dc=example,dc=com", map[string][]string{
		"uid":         {"ara"},
		"mail":        {"ara@example.com"},
		"displayName": {"Ara Example"},
		"memberOf":    {"cn=admins,ou=groups,dc=example,dc=com", "cn=it,ou=groups,dc=example,dc=com"},
	})
	u := c.mapUser(e)
	if u.Username != "ara" || u.Email != "ara@example.com" || u.DisplayName != "Ara Example" {
		t.Errorf("mapped user = %+v", u)
	}
	if len(u.MemberOf) != 2 || u.DN == "" {
		t.Errorf("mapped DN/memberOf = %+v", u)
	}
	// displayName falls back to cn.
	e2 := ldap.NewEntry("uid=bob,ou=users,dc=example,dc=com", map[string][]string{
		"uid": {"bob"}, "cn": {"Bob"},
	})
	if u := c.mapUser(e2); u.DisplayName != "Bob" {
		t.Errorf("displayName fallback = %q, want Bob", u.DisplayName)
	}
	if u.Attrs != nil {
		t.Errorf("unmapped Attrs = %v, want nil", u.Attrs)
	}
}

func TestMapUserAttrMap(t *testing.T) {
	cfg := validConfig()
	cfg.AttrMap = map[string]string{"department": "dept", "employeeID": "employee-id"}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := ldap.NewEntry("uid=ara,ou=users,dc=example,dc=com", map[string][]string{
		"uid":        {"ara"},
		"department": {"IT"},
		"employeeID": {"E1", "E2"},
		"title":      {"Engineer"}, // unmapped: dropped
	})
	u := c.mapUser(e)
	if len(u.Attrs) != 2 || len(u.Attrs["dept"]) != 1 || u.Attrs["dept"][0] != "IT" {
		t.Errorf("mapped dept = %v", u.Attrs)
	}
	if len(u.Attrs["employee-id"]) != 2 {
		t.Errorf("mapped employee-id = %v", u.Attrs)
	}
	// Mapped-but-absent attributes are skipped, not stored empty.
	e2 := ldap.NewEntry("uid=bob,ou=users,dc=example,dc=com", map[string][]string{
		"uid": {"bob"},
	})
	if u := c.mapUser(e2); len(u.Attrs) != 0 {
		t.Errorf("absent mapping Attrs = %v, want empty", u.Attrs)
	}
	// The import rides the requested attribute list.
	want := []string{"uid", "mail", "displayName", "cn", "memberOf", "department", "employeeID"}
	if got := c.userAttributes(); !reflect.DeepEqual(got, want) {
		t.Errorf("userAttributes = %v, want %v", got, want)
	}
}

func TestSameDN(t *testing.T) {
	a := "cn=Admins, ou=Groups, dc=example,dc=com"
	b := "CN=admins,OU=groups,DC=EXAMPLE,DC=COM"
	if !SameDN(a, b) {
		t.Errorf("SameDN(%q, %q) = false, want true", a, b)
	}
	if SameDN(a, "cn=other,ou=groups,dc=example,dc=com") {
		t.Error("SameDN(different) = true, want false")
	}
}

func TestRedactURL(t *testing.T) {
	if got := redactURL("ldap://svc:s3cret@dir:389"); got != "ldap://dir:389" {
		t.Errorf("redactURL = %q", got)
	}
	if got := redactURL("ldaps://dir:636"); got != "ldaps://dir:636" {
		t.Errorf("redactURL untouched = %q", got)
	}
}

// TestUnreachableFailsFast proves directory outages surface explicit errors
// instead of hanging (PRD §5.1). 127.0.0.1:38990 is a closed port, so the
// dial refuses immediately.
func TestUnreachableFailsFast(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	err = c.Ping(ctx)
	if err == nil {
		t.Fatal("Ping(closed port) = nil, want error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Ping took %v, want a fast explicit failure", d)
	}
	if _, err := c.Authenticate(ctx, "ara", "pw"); err == nil {
		t.Fatal("Authenticate(closed port) = nil, want error")
	}
	if _, err := c.Snapshot(ctx); err == nil {
		t.Fatal("Snapshot(closed port) = nil, want error")
	}
}

func TestAuthenticateRejectsEmpty(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Authenticate(ctx, "", "pw"); err == nil {
		t.Error("empty username accepted, want rejection")
	}
	if _, err := c.Authenticate(ctx, "ara", ""); err == nil {
		t.Error("empty password accepted, want rejection")
	}
}

func TestCancelledContext(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Ping(ctx); err == nil {
		t.Error("Ping(cancelled) = nil, want error")
	}
}
