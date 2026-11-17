package http

import (
	"testing"
	"time"
)

func TestAllowFixedWindow(t *testing.T) {
	now := time.Now()
	l := NewLimiter()
	l.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if !l.Allow("k", 5, time.Minute) {
			t.Fatalf("Allow #%d = false, want true", i+1)
		}
	}
	if l.Allow("k", 5, time.Minute) {
		t.Fatal("Allow over limit = true, want false")
	}
	if !l.Allow("other", 5, time.Minute) {
		t.Fatal("Allow(other key) = false, want true")
	}
	now = now.Add(time.Minute)
	if !l.Allow("k", 5, time.Minute) {
		t.Fatal("Allow after window = false, want true")
	}
}

func TestLockoutProgression(t *testing.T) {
	now := time.Now()
	l := NewLimiter()
	l.now = func() time.Time { return now }

	for i := 0; i < LockoutThreshold-1; i++ {
		l.NoteFailure("u")
	}
	if locked, _ := l.Locked("u"); locked {
		t.Fatal("Locked below threshold = true, want false")
	}
	l.NoteFailure("u")
	locked, wait := l.Locked("u")
	if !locked || wait <= 0 || wait > LockoutBase {
		t.Fatalf("Locked = %v, %v; want true, (0,%v]", locked, wait, LockoutBase)
	}
	// Expiry then another failure doubles the backoff.
	now = now.Add(LockoutBase + time.Second)
	if locked, _ := l.Locked("u"); locked {
		t.Fatal("Locked after expiry = true, want false")
	}
	l.NoteFailure("u")
	_, wait = l.Locked("u")
	if wait <= LockoutBase || wait > 2*LockoutBase {
		t.Fatalf("doubled wait = %v, want (%v,%v]", wait, LockoutBase, 2*LockoutBase)
	}
	// Success clears everything.
	l.Reset("u")
	if locked, _ := l.Locked("u"); locked {
		t.Fatal("Locked after reset = true, want false")
	}
}

func TestLockoutCapsAtMax(t *testing.T) {
	now := time.Now()
	l := NewLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < 50; i++ {
		l.NoteFailure("u")
	}
	_, wait := l.Locked("u")
	if wait > LockoutMax {
		t.Fatalf("wait = %v, want <= %v", wait, LockoutMax)
	}
}

func TestPurgeKeepsTableBounded(t *testing.T) {
	now := time.Now()
	l := NewLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < 300; i++ {
		l.Allow(string(rune(i)), 1, time.Second)
	}
	now = now.Add(time.Hour)
	for i := 300; i < 600; i++ {
		l.Allow(string(rune(1000+i)), 1, time.Second)
	}
	l.mu.Lock()
	n := len(l.windows)
	l.mu.Unlock()
	if n > 400 {
		t.Fatalf("windows = %d, want purge to bound growth", n)
	}
}
