package saml

import (
	"testing"

	"github.com/identityhub/identityhub/internal/domain"
)

func TestMapSessionCustomAttributes(t *testing.T) {
	s := mapSession(domain.SAMLDecision{
		NameID: "alice", Email: "alice@example.com", DisplayName: "Alice",
		Groups:     []string{"eng"},
		Attributes: map[string][]string{"dept": {"it"}, "tags": {"a", "b"}, "empty": {}},
	})
	// 3 built-ins + 2 custom (empty skipped), custom sorted by key.
	if len(s.CustomAttributes) != 5 {
		t.Fatalf("attributes = %d, want 5", len(s.CustomAttributes))
	}
	if s.CustomAttributes[3].Name != "dept" || len(s.CustomAttributes[3].Values) != 1 ||
		s.CustomAttributes[3].Values[0].Value != "it" {
		t.Errorf("dept attr = %+v", s.CustomAttributes[3])
	}
	if s.CustomAttributes[4].Name != "tags" || len(s.CustomAttributes[4].Values) != 2 {
		t.Errorf("tags attr = %+v", s.CustomAttributes[4])
	}
	if s.CustomAttributes[0].Name != domain.SAMLAttrEmail {
		t.Errorf("built-ins moved: %+v", s.CustomAttributes[0])
	}
}
