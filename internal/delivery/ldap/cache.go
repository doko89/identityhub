package ldap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/identityhub/identityhub/internal/domain"
)

// treeSnapshot is one cached whole-directory listing: the same rows the
// subtree searches assemble, minus password hashes (AllActive projects
// only served fields).
type treeSnapshot struct {
	users   []domain.User
	groups  []domain.Group
	members map[string][]string // group-id -> member user DNs
	custom  map[string]map[string][]string
}

// treeCache serves whole-tree searches from memory. A snapshot refreshes
// when the directory version moves (every user/group/membership/MFA
// write bumps it, in any process) or when the TTL lapses; concurrent
// refreshes collapse into one load. Point lookups ((uid=...), leaf DNs)
// bypass it and always read fresh.
type treeCache struct {
	version domain.DirectoryVersioner // nil: TTL-only mode (tests)
	ttl     time.Duration             // <=0 disables the cache (always fresh)
	now     func() time.Time
	log     *slog.Logger
	mu      sync.Mutex
	snap    *treeSnapshot
	at      int64
	expires time.Time
	group   singleflight.Group
}

func newTreeCache(version domain.DirectoryVersioner, ttl time.Duration, log *slog.Logger) *treeCache {
	if log == nil {
		log = slog.Default()
	}
	return &treeCache{version: version, ttl: ttl, now: time.Now, log: log}
}

// get returns a snapshot, refreshing through load when the version moved
// or the TTL lapsed. A failed refresh still serves the previous snapshot
// (a sick database degrades directory reads instead of failing them).
func (c *treeCache) get(ctx context.Context, load func(context.Context) (*treeSnapshot, error)) (*treeSnapshot, error) {
	if c.ttl <= 0 {
		return load(ctx)
	}
	if s, at := c.cached(); s != nil {
		if c.version == nil {
			return s, nil
		}
		v, err := c.version.Current(ctx)
		if err != nil {
			c.log.Warn("ldap version check failed; serving cached tree", "error", err)
			return s, nil
		}
		if v == at {
			return s, nil
		}
	}
	snap, err, _ := c.group.Do("tree", func() (any, error) {
		loaded, err := load(ctx)
		if err != nil {
			return nil, err
		}
		var v int64
		if c.version != nil {
			// Read after the load: a write landing mid-load is
			// recorded newer than the snapshot, so the next
			// lookup refreshes again instead of serving mixed
			// data as current.
			if v, err = c.version.Current(ctx); err != nil {
				// Version unreadable (migration not run, sick
				// database): keep the loaded snapshot under the
				// previous generation so the cache degrades to
				// TTL-only instead of failing every search.
				c.log.Warn("ldap version check failed; caching snapshot TTL-only", "error", err)
				v = c.generation()
			}
		}
		c.store(loaded, v)
		return loaded, nil
	})
	if err != nil {
		if s, _ := c.cached(); s != nil {
			c.log.Warn("ldap tree refresh failed; serving stale snapshot", "error", err)
			return s, nil
		}
		return nil, err
	}
	return snap.(*treeSnapshot), nil
}

func (c *treeCache) cached() (*treeSnapshot, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap == nil || !c.now().Before(c.expires) {
		return nil, 0
	}
	return c.snap, c.at
}

func (c *treeCache) store(snap *treeSnapshot, v int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snap, c.at = snap, v
	c.expires = c.now().Add(c.ttl)
}

func (c *treeCache) generation() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

// maxBindCacheEntries bounds the bind-result map; overflows drop the
// whole map (a stampede back to argon2, never unbounded memory).
const maxBindCacheEntries = 4096

// bindCache remembers recent successful local binds so clients that
// re-bind every operation skip argon2. Entries key off
// sha256(username + NUL + password) and die with the TTL or when the
// directory version moves (password/MFA/active changes bump it).
// Directory (upstream LDAP) users are never cached: their passwords live
// outside this database, so no local write marks them stale.
type bindCache struct {
	ttl time.Duration // <=0 disables the cache (always verify)
	now func() time.Time
	mu  sync.Mutex
	gen int64
	set bool
	m   map[string]bindEntry
}

type bindEntry struct {
	userID  uuid.UUID
	expires time.Time
}

func newBindCache(ttl time.Duration) *bindCache {
	return &bindCache{ttl: ttl, now: time.Now, m: map[string]bindEntry{}}
}

// bindCacheKey derives the lookup key. The separator keeps ("ab","c")
// and ("a","bc") apart.
func bindCacheKey(username, password string) string {
	sum := sha256.Sum256([]byte(username + "\x00" + password))
	return hex.EncodeToString(sum[:])
}

// lookup resolves a key to its user when the entry is live and belongs
// to the current directory generation.
func (c *bindCache) lookup(key string, version int64) (uuid.UUID, bool) {
	if c.ttl <= 0 {
		return uuid.Nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set || c.gen != version {
		c.m, c.gen, c.set = map[string]bindEntry{}, version, true
		return uuid.Nil, false
	}
	e, ok := c.m[key]
	if !ok || !c.now().Before(e.expires) {
		delete(c.m, key)
		return uuid.Nil, false
	}
	return e.userID, true
}

// store records a verified bind under the current generation.
func (c *bindCache) store(key string, userID uuid.UUID, version int64) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set || c.gen != version {
		c.m, c.gen, c.set = map[string]bindEntry{}, version, true
	}
	if len(c.m) >= maxBindCacheEntries {
		for k, e := range c.m {
			if !c.now().Before(e.expires) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxBindCacheEntries {
			c.m = map[string]bindEntry{}
		}
	}
	c.m[key] = bindEntry{userID: userID, expires: c.now().Add(c.ttl)}
}
