package radius

import (
	"testing"
	"time"
)

func TestNASLimiterBudget(t *testing.T) {
	l := newNASLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("request %d denied, want allow", i+1)
		}
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("request past the budget allowed, want deny")
	}
	// Other NAS hosts keep their own budget.
	if !l.Allow("10.0.0.2") {
		t.Fatal("different host denied, want allow")
	}
}

func TestNASLimiterWindowReset(t *testing.T) {
	l := newNASLimiter(1, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	if !l.Allow("10.0.0.1") {
		t.Fatal("first request denied, want allow")
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("second request in-window allowed, want deny")
	}
	now = now.Add(time.Minute)
	if !l.Allow("10.0.0.1") {
		t.Fatal("request after window reset denied, want allow")
	}
}

func TestNewNASLimiterDefaults(t *testing.T) {
	l := newNASLimiter(0, 0)
	if l.limit != DefaultPerNASLimit || l.window != DefaultPerNASWindow {
		t.Fatalf("got limit=%d window=%v, want defaults", l.limit, l.window)
	}
}
