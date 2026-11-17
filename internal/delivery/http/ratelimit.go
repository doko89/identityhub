package http

import (
	"sync"
	"time"
)

// Rate limits (TECH_SPEC §8).
const (
	LoginPerIPLimit    = 10
	LoginPerIPWindow   = time.Minute
	LoginPerUserLimit  = 5
	LoginPerUserWindow = time.Minute
	// Progressive lockout after consecutive login failures.
	LockoutThreshold = 5
	LockoutBase      = time.Minute
	LockoutMax       = 30 * time.Minute

	ForgotPerLoginLimit  = 3
	ForgotPerLoginWindow = time.Hour
	ForgotPerIPLimit     = 10
	ForgotPerIPWindow    = time.Hour

	ResetPerIPLimit  = 10
	ResetPerIPWindow = time.Minute

	ChangePerUserLimit  = 10
	ChangePerUserWindow = time.Minute
)

type window struct {
	count int
	reset time.Time
}

type failureTrack struct {
	count       int
	lockedUntil time.Time
}

// Limiter is an in-memory fixed-window rate limiter with progressive
// lockout for repeated failures. v1 runs a single binary, so process
// memory is sufficient; a Redis backend can replace it behind the same
// methods if IdentityHub ever scales horizontally.
type Limiter struct {
	mu       sync.Mutex
	windows  map[string]*window
	failures map[string]*failureTrack
	now      func() time.Time
}

// NewLimiter builds an empty Limiter.
func NewLimiter() *Limiter {
	return &Limiter{windows: map[string]*window{}, failures: map[string]*failureTrack{}, now: time.Now}
}

// Allow reports whether a request under key may proceed, consuming one
// unit of the limit-per-window budget.
func (l *Limiter) Allow(key string, limit int, per time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w, ok := l.windows[key]
	if !ok || !now.Before(w.reset) {
		l.windows[key] = &window{count: 1, reset: now.Add(per)}
		l.maybePurge(now)
		return true
	}
	if w.count >= limit {
		return false
	}
	w.count++
	return true
}

// Locked reports whether key is under progressive lockout and, if so,
// how long until it lifts.
func (l *Limiter) Locked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.failures[key]
	if !ok {
		return false, 0
	}
	now := l.now()
	if now.Before(f.lockedUntil) {
		return true, f.lockedUntil.Sub(now)
	}
	return false, 0
}

// NoteFailure records a failed attempt. Once failures reach
// LockoutThreshold, the key locks for LockoutBase, doubling per further
// failure up to LockoutMax.
func (l *Limiter) NoteFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.failures[key]
	if !ok {
		f = &failureTrack{}
		l.failures[key] = f
	}
	f.count++
	if f.count < LockoutThreshold {
		return
	}
	backoff := LockoutBase << (f.count - LockoutThreshold)
	if backoff > LockoutMax || backoff <= 0 {
		backoff = LockoutMax
	}
	l.failures[key].lockedUntil = l.now().Add(backoff)
}

// Reset clears failures and lockout for key (called on success).
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// maybePurge drops expired buckets when the table grows. Callers must
// hold the mutex.
func (l *Limiter) maybePurge(now time.Time) {
	if len(l.windows)%128 != 0 {
		return
	}
	for k, w := range l.windows {
		if !now.Before(w.reset) {
			delete(l.windows, k)
		}
	}
	for k, f := range l.failures {
		if f.count < LockoutThreshold && now.After(f.lockedUntil.Add(time.Hour)) {
			delete(l.failures, k)
		}
	}
}
