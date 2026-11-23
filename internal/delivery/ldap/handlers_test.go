package ldap

import (
	"context"
	"net"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// fakeClient exposes a chosen conn behind the library's GetConn
// accessor so bind-state tests need no network server.
type fakeClient struct{ conn net.Conn }

func (f *fakeClient) GetConn() net.Conn { return f.conn }

func trackedPair(t *testing.T) (*trackedConn, *fakeClient) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	tc := &trackedConn{Conn: a}
	return tc, &fakeClient{conn: tc}
}

// TestBoundConnectionNeverExpires is the Stalwart-pool regression
// test: a bind authorizes its connection for the connection's whole
// life, with no timer in between. The old 30-minute sliding expiry
// silently unbound idle pool connections, and Stalwart only binds
// when it opens a connection — so every operation failed until a
// manual restart, while per-operation binders (Harbor, Sonar) never
// noticed.
func TestBoundConnectionNeverExpires(t *testing.T) {
	s := leafTestServer()
	s.log = testLogger()
	_, fc := trackedPair(t)
	if s.isBound(fc) {
		t.Fatal("fresh connection is bound, want unbound")
	}
	s.markBound(fc, "svc.internal")
	for i := 0; i < 100; i++ {
		if !s.isBound(fc) {
			t.Fatalf("bound connection lost its bind on check %d", i)
		}
	}
}

func TestBindStateIsPerConnection(t *testing.T) {
	s := leafTestServer()
	s.log = testLogger()
	_, a := trackedPair(t)
	_, b := trackedPair(t)
	s.markBound(a, "svc.internal")
	if !s.isBound(a) {
		t.Error("bound connection reads unbound")
	}
	if s.isBound(b) {
		t.Error("second connection reads bound, want per-connection isolation")
	}
}

func TestUntrackedClientFailsClosed(t *testing.T) {
	s := leafTestServer()
	s.log = testLogger()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	plain := &fakeClient{conn: a} // never wrapped by Serve
	s.markBound(plain, "svc.internal")
	if s.isBound(plain) {
		t.Error("untracked connection reads bound, want fail-closed")
	}
	if s.isBound("not a client") {
		t.Error("non-client value reads bound, want fail-closed")
	}
}

func TestTrackingListenerWrapsAccepted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tracked := &trackingListener{ln}
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := tracked.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(*trackedConn); !ok {
		t.Errorf("accepted conn type = %T, want *trackedConn", c)
	}
}

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
