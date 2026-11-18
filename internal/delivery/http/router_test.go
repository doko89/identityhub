package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identityhub/identityhub/internal/metrics"
)

type stubSessions struct{}

func (stubSessions) LoadAndSave(next http.Handler) http.Handler { return next }
func (stubSessions) Token(context.Context) string               { return "" }
func (stubSessions) RenewToken(context.Context) error           { return nil }
func (stubSessions) Put(context.Context, string, any)           {}
func (stubSessions) GetString(context.Context, string) string   { return "" }
func (stubSessions) GetBytes(context.Context, string) []byte    { return nil }
func (stubSessions) Remove(context.Context, string)             {}
func (stubSessions) Destroy(context.Context) error              { return nil }

type stubDB struct{ err error }

func (s stubDB) Ping(context.Context) error { return s.err }

func testRouter(dbErr error) http.Handler {
	return NewRouter(Deps{Sessions: stubSessions{}, DB: stubDB{err: dbErr}})
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestMetricsExposed(t *testing.T) {
	// Series appear only after their first observation.
	metrics.ObserveAuthFailure("password", metrics.AppGlobal)
	metrics.ObserveLegacyBind("ldap", true)
	testRouter(nil).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/nope", nil))
	rec := httptest.NewRecorder()
	testRouter(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	for _, name := range []string{
		"identityhub_auth_failures_total",
		"identityhub_legacy_binds_total",
		"identityhub_http_requests_total",
		"identityhub_http_request_duration_seconds",
	} {
		if !strings.Contains(rec.Body.String(), name) {
			t.Errorf("/metrics body misses %s", name)
		}
	}
}

func TestReadyz(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready DB: GET /readyz = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	testRouter(errors.New("db down")).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("sick DB: GET /readyz = %d, want 503", rec.Code)
	}
}

func TestAPIUnknownIsJSON404(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/nope = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestSPAFallbackServesIndex(t *testing.T) {
	for _, p := range []string{"/", "/login", "/admin/users"} {
		rec := httptest.NewRecorder()
		testRouter(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("GET %s Content-Type = %q", p, ct)
		}
	}
}
