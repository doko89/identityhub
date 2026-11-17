package radius

import (
	"sync"
	"time"
)

// Per-NAS flood protection (M7 hardening). RADIUS is UDP with client
// retransmits, so a stuck NAS — or a deliberate flood — can bury the
// auth path in argon2 verifications; packets past the budget are dropped
// before the NAS lookup and the NAS backs off on its own retry timer.
// The budget is generous on purpose: legitimate NAS bursts (VPN login
// storms) must never trip it.
const (
	DefaultPerNASLimit  = 300
	DefaultPerNASWindow = time.Minute
)

// nasLimiter is a fixed-window limiter keyed by NAS source IP. One
// instance lives in each Server; NAS counts are tiny so no purge pass is
// needed.
type nasLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*nasBucket
	now     func() time.Time
}

type nasBucket struct {
	count int
	reset time.Time
}

// newNASLimiter builds a limiter; non-positive limit/window fall back to
// the defaults.
func newNASLimiter(limit int, window time.Duration) *nasLimiter {
	if limit <= 0 {
		limit = DefaultPerNASLimit
	}
	if window <= 0 {
		window = DefaultPerNASWindow
	}
	return &nasLimiter{
		limit: limit, window: window,
		buckets: map[string]*nasBucket{}, now: time.Now,
	}
}

// Allow consumes one unit of the host's budget and reports whether the
// packet may proceed.
func (l *nasLimiter) Allow(host string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[host]
	if !ok || !now.Before(b.reset) {
		l.buckets[host] = &nasBucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}
