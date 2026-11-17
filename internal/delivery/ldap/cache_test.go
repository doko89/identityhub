package ldap

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// ---------- tree cache ----------

type stubVersioner struct {
	v   int64
	err error
}

func (s *stubVersioner) Current(context.Context) (int64, error) { return s.v, s.err }

type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time { return c.now }

func testSnapshot() *treeSnapshot {
	return &treeSnapshot{
		users:   []domain.User{{ID: uuid.New(), Username: "ara"}},
		groups:  []domain.Group{{ID: uuid.New(), Name: "eng"}},
		members: map[string][]string{},
	}
}

func TestTreeCacheRefreshesOnVersionMove(t *testing.T) {
	ctx := context.Background()
	ver := &stubVersioner{v: 7}
	clock := &manualClock{now: time.Now()}
	c := newTreeCache(ver, time.Minute, slog.Default())
	c.now = clock.Now
	loads := 0
	load := func(context.Context) (*treeSnapshot, error) {
		loads++
		return testSnapshot(), nil
	}

	if _, err := c.get(ctx, load); err != nil {
		t.Fatalf("first get: %v", err)
	}
	if _, err := c.get(ctx, load); err != nil {
		t.Fatalf("second get: %v", err)
	}
	if loads != 1 {
		t.Fatalf("loads = %d, want 1 (second hit cached)", loads)
	}
	ver.v = 8
	if _, err := c.get(ctx, load); err != nil {
		t.Fatalf("get after bump: %v", err)
	}
	if loads != 2 {
		t.Fatalf("loads = %d, want 2 (version move refreshes)", loads)
	}
}

func TestTreeCacheTTLExpiry(t *testing.T) {
	ctx := context.Background()
	clock := &manualClock{now: time.Now()}
	c := newTreeCache(&stubVersioner{v: 1}, time.Minute, slog.Default())
	c.now = clock.Now
	loads := 0
	load := func(context.Context) (*treeSnapshot, error) {
		loads++
		return testSnapshot(), nil
	}
	if _, err := c.get(ctx, load); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if _, err := c.get(ctx, load); err != nil {
		t.Fatal(err)
	}
	if loads != 2 {
		t.Fatalf("loads = %d, want 2 (TTL lapse refreshes)", loads)
	}
}

func TestTreeCacheServesStaleOnErrors(t *testing.T) {
	ctx := context.Background()
	ver := &stubVersioner{v: 1}
	c := newTreeCache(ver, time.Minute, slog.Default())
	loads := 0
	load := func(context.Context) (*treeSnapshot, error) {
		loads++
		return testSnapshot(), nil
	}
	first, err := c.get(ctx, load)
	if err != nil {
		t.Fatal(err)
	}
	// A version-check failure serves the snapshot instead of failing.
	ver.err = errors.New("db down")
	if got, err := c.get(ctx, load); err != nil || got != first {
		t.Fatalf("version error: got %v, %v; want cached snapshot", got, err)
	}
	// So does a refresh failure after a real version move.
	ver.err = nil
	ver.v = 2
	fail := func(context.Context) (*treeSnapshot, error) { return nil, errors.New("db down") }
	if got, err := c.get(ctx, fail); err != nil || got != first {
		t.Fatalf("refresh error: got %v, %v; want stale snapshot", got, err)
	}
	// With nothing cached, the error surfaces.
	empty := newTreeCache(&stubVersioner{v: 1}, time.Minute, slog.Default())
	if _, err := empty.get(ctx, fail); err == nil {
		t.Fatal("want refresh error with cold cache")
	}
}

func TestTreeCacheDegradesToTTLOnly(t *testing.T) {
	ctx := context.Background()
	// Version store permanently unreadable (migration not run): the
	// cache still serves snapshots bounded by the TTL.
	ver := &stubVersioner{err: errors.New("relation directory_version does not exist")}
	clock := &manualClock{now: time.Now()}
	c := newTreeCache(ver, time.Minute, slog.Default())
	c.now = clock.Now
	loads := 0
	load := func(context.Context) (*treeSnapshot, error) {
		loads++
		return testSnapshot(), nil
	}
	if _, err := c.get(ctx, load); err != nil {
		t.Fatalf("cold get: %v", err)
	}
	if _, err := c.get(ctx, load); err != nil {
		t.Fatalf("warm get: %v", err)
	}
	if loads != 1 {
		t.Fatalf("loads = %d, want 1 (TTL-only within TTL)", loads)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if _, err := c.get(ctx, load); err != nil {
		t.Fatalf("get after TTL: %v", err)
	}
	if loads != 2 {
		t.Fatalf("loads = %d, want 2 (TTL lapse reloads)", loads)
	}
}

func TestTreeCacheDisabled(t *testing.T) {
	ctx := context.Background()
	c := newTreeCache(&stubVersioner{v: 1}, 0, slog.Default())
	loads := 0
	load := func(context.Context) (*treeSnapshot, error) {
		loads++
		return testSnapshot(), nil
	}
	if _, err := c.get(ctx, load); err != nil {
		t.Fatal(err)
	}
	if _, err := c.get(ctx, load); err != nil {
		t.Fatal(err)
	}
	if loads != 2 {
		t.Fatalf("loads = %d, want 2 (TTL<=0 always fresh)", loads)
	}
}

// ---------- bind cache ----------

func TestBindCache(t *testing.T) {
	clock := &manualClock{now: time.Now()}
	c := newBindCache(time.Minute)
	c.now = clock.Now
	uid := uuid.New()
	key := bindCacheKey("ara", "correct-horse-12")

	if _, ok := c.lookup(key, 3); ok {
		t.Fatal("cold lookup hit")
	}
	c.store(key, uid, 3)
	if got, ok := c.lookup(key, 3); !ok || got != uid {
		t.Fatalf("lookup = %v, %v; want hit", got, ok)
	}
	if _, ok := c.lookup(bindCacheKey("ara", "wrong"), 3); ok {
		t.Fatal("wrong password hit")
	}
	// A version move invalidates every entry.
	if _, ok := c.lookup(key, 4); ok {
		t.Fatal("lookup after version move hit")
	}
	c.store(key, uid, 4)
	clock.now = clock.now.Add(2 * time.Minute)
	if _, ok := c.lookup(key, 4); ok {
		t.Fatal("expired entry hit")
	}
}

func TestBindCacheKeySeparatesCredentials(t *testing.T) {
	if bindCacheKey("ab", "c") == bindCacheKey("a", "bc") {
		t.Fatal("credential pairs collide")
	}
	if bindCacheKey("ara", "x") == bindCacheKey("ara", "y") {
		t.Fatal("passwords collide")
	}
}

func TestBindCacheDisabled(t *testing.T) {
	c := newBindCache(0)
	uid := uuid.New()
	key := bindCacheKey("ara", "pw")
	c.store(key, uid, 1)
	if _, ok := c.lookup(key, 1); ok {
		t.Fatal("disabled cache hit")
	}
}
