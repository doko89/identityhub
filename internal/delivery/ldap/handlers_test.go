package ldap

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// Fake stores backing collectEntries leaf-scope tests. They embed the
// shared stubs so only the leafEntry path (ByUsername, ByID,
// GroupsOfUser, ByName, MemberIDs) needs explicit behavior.
type leafUsers struct {
	stubUsers
	byName map[string]domain.User
	byID   map[uuid.UUID]domain.User
}

func (f leafUsers) ByUsername(_ context.Context, u string) (domain.User, error) {
	if usr, ok := f.byName[u]; ok {
		return usr, nil
	}
	return domain.User{}, domain.ErrNotFound
}

func (f leafUsers) ByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	if usr, ok := f.byID[id]; ok {
		return usr, nil
	}
	return domain.User{}, domain.ErrNotFound
}

type leafGroups struct {
	stubGroups
	byName map[string]domain.Group
	member map[uuid.UUID][]uuid.UUID
	ofUser map[uuid.UUID][]domain.Group
}

func (f leafGroups) ByName(_ context.Context, n string) (domain.Group, error) {
	if g, ok := f.byName[n]; ok {
		return g, nil
	}
	return domain.Group{}, domain.ErrNotFound
}

func (f leafGroups) MemberIDs(_ context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	return f.member[id], nil
}

func (f leafGroups) GroupsOfUser(_ context.Context, id uuid.UUID) ([]domain.Group, error) {
	return f.ofUser[id], nil
}

func leafTestServer() *Server {
	uid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	gid := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	usr := domain.User{ID: uid, Username: "sundoko", DisplayName: "sundoko",
		Email: "sundoko@example.com", UIDNumber: 10001, IsActive: true}
	grp := domain.Group{ID: gid, Name: "it", GIDNumber: 30219}
	tree, err := NewDNTree("dc=ho,dc=waterfront,dc=co,dc=id")
	if err != nil {
		panic(err)
	}
	return &Server{
		dn: tree,
		users: leafUsers{
			byName: map[string]domain.User{"sundoko": usr},
			byID:   map[uuid.UUID]domain.User{uid: usr},
		},
		groups: leafGroups{
			byName: map[string]domain.Group{"it": grp},
			member: map[uuid.UUID][]uuid.UUID{gid: {uid}},
			ofUser: map[uuid.UUID][]domain.Group{uid: {grp}},
		},
	}
}

// matchCount replicates the handleSearch candidate loop so the test
// proves end-to-end visibility, not just candidate collection.
func matchCount(cands []*entry, f *filter) int {
	n := 0
	for _, e := range cands {
		if f.match(*e) {
			n++
		}
	}
	return n
}

func TestCollectEntriesLeafScopes(t *testing.T) {
	s := leafTestServer()
	ctx := context.Background()
	groupDN := "cn=it,ou=groups,dc=ho,dc=waterfront,dc=co,dc=id"
	userDN := "uid=sundoko,ou=users,dc=ho,dc=waterfront,dc=co,dc=id"

	// Harbor's SearchGroupByDN shape: leaf base + subtree scope.
	harborFilter, err := parseFilter("(&(objectClass=posixGroup)(cn=*))")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("group leaf subtree matches (Harbor)", func(t *testing.T) {
		out, noSuch, err := s.collectEntries(ctx, groupDN, scopeWholeSubtree, harborFilter)
		if err != nil || noSuch {
			t.Fatalf("collectEntries = err %v noSuch %v, want success", err, noSuch)
		}
		if got := matchCount(out, harborFilter); got != 1 {
			t.Fatalf("matched %d entries, want 1", got)
		}
	})

	t.Run("group leaf base still matches", func(t *testing.T) {
		out, noSuch, err := s.collectEntries(ctx, groupDN, scopeBaseObject, harborFilter)
		if err != nil || noSuch {
			t.Fatalf("collectEntries = err %v noSuch %v, want success", err, noSuch)
		}
		if got := matchCount(out, harborFilter); got != 1 {
			t.Fatalf("matched %d entries, want 1", got)
		}
	})

	t.Run("group leaf single-level matches nothing", func(t *testing.T) {
		out, noSuch, err := s.collectEntries(ctx, groupDN, scopeSingleLevel, harborFilter)
		if err != nil || noSuch {
			t.Fatalf("collectEntries = err %v noSuch %v, want empty success", err, noSuch)
		}
		if len(out) != 0 {
			t.Fatalf("got %d candidates, want 0", len(out))
		}
	})

	t.Run("unknown group leaf is NoSuchObject", func(t *testing.T) {
		dd := "cn=nope,ou=groups,dc=ho,dc=waterfront,dc=co,dc=id"
		for _, scope := range []int{scopeBaseObject, scopeSingleLevel, scopeWholeSubtree} {
			_, noSuch, err := s.collectEntries(ctx, dd, scope, harborFilter)
			if err != nil || !noSuch {
				t.Fatalf("scope %d: err %v noSuch %v, want noSuch", scope, err, noSuch)
			}
		}
	})

	t.Run("user leaf subtree matches", func(t *testing.T) {
		f, err := parseFilter("(uid=sundoko)")
		if err != nil {
			t.Fatal(err)
		}
		out, noSuch, err := s.collectEntries(ctx, userDN, scopeWholeSubtree, f)
		if err != nil || noSuch {
			t.Fatalf("collectEntries = err %v noSuch %v, want success", err, noSuch)
		}
		if got := matchCount(out, f); got != 1 {
			t.Fatalf("matched %d entries, want 1", got)
		}
	})

	t.Run("unknown user leaf is NoSuchObject", func(t *testing.T) {
		f, err := parseFilter("(uid=ghost)")
		if err != nil {
			t.Fatal(err)
		}
		dd := "uid=ghost,ou=users,dc=ho,dc=waterfront,dc=co,dc=id"
		_, noSuch, err := s.collectEntries(ctx, dd, scopeWholeSubtree, f)
		if err != nil || !noSuch {
			t.Fatalf("err %v noSuch %v, want noSuch", err, noSuch)
		}
	})
}
