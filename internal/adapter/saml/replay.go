package saml

import (
	"errors"
	"sync"
	"time"

	"github.com/identityhub/identityhub/internal/domain"
)

// replayCache answers each AuthnRequest ID at most once (TECH_SPEC §2:
// harden M3 against replayed signed requests). It is process-local: the
// v1 single binary is the only issuer, so no shared store is needed.
type replayCache struct {
	mu       sync.Mutex
	max      int
	entries  map[string]time.Time
	earliest time.Time
}

// newReplayCache builds a cache holding at most max unexpired IDs.
func newReplayCache(max int) *replayCache {
	return &replayCache{max: max, entries: map[string]time.Time{}}
}

// consume records id until expiresAt. A live duplicate fails closed with
// ErrConflict; the caller turns it into a rejected SSO attempt.
func (c *replayCache) consume(id string, expiresAt time.Time) error {
	now := domain.SystemClock{}.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[id]; ok && !now.After(exp) {
		return errors.New("saml: duplicate or replayed AuthnRequest")
	}
	c.entries[id] = expiresAt
	if c.earliest.IsZero() || expiresAt.Before(c.earliest) {
		c.earliest = expiresAt
	}
	if len(c.entries) > c.max {
		c.evictLocked(now)
	}
	return nil
}

// evictLocked drops expired IDs; if the cache is still over budget (a
// flood of distinct live IDs), it drops the earliest-expiring ones.
func (c *replayCache) evictLocked(now time.Time) {
	for id, exp := range c.entries {
		if !now.After(exp) {
			continue
		}
		delete(c.entries, id)
	}
	for len(c.entries) > c.max {
		oldest, oldestExp := "", time.Time{}
		for id, exp := range c.entries {
			if oldestExp.IsZero() || exp.Before(oldestExp) {
				oldest, oldestExp = id, exp
			}
		}
		delete(c.entries, oldest)
	}
	c.earliest = time.Time{}
	for _, exp := range c.entries {
		if c.earliest.IsZero() || exp.Before(c.earliest) {
			c.earliest = exp
		}
	}
}
