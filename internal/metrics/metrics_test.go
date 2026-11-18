package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func TestObserveAuthFailure(t *testing.T) {
	before := testutil.ToFloat64(AuthFailures.WithLabelValues("password", AppGlobal))
	ObserveAuthFailure("password", AppGlobal)
	ObserveAuthFailure("launch", "wiki")
	if got := testutil.ToFloat64(AuthFailures.WithLabelValues("password", AppGlobal)); got != before+1 {
		t.Errorf("password/global = %v, want %v", got, before+1)
	}
	if got := testutil.ToFloat64(AuthFailures.WithLabelValues("launch", "wiki")); got != 1 {
		t.Errorf("launch/wiki = %v, want 1", got)
	}
}

func TestObserveLegacyBind(t *testing.T) {
	before := testutil.ToFloat64(LegacyBinds.WithLabelValues("ldap", "success"))
	ObserveLegacyBind("ldap", true)
	ObserveLegacyBind("radius", false)
	if got := testutil.ToFloat64(LegacyBinds.WithLabelValues("ldap", "success")); got != before+1 {
		t.Errorf("ldap/success = %v, want %v", got, before+1)
	}
	if got := testutil.ToFloat64(LegacyBinds.WithLabelValues("radius", "failure")); got != 1 {
		t.Errorf("radius/failure = %v, want 1", got)
	}
}

func histogramCount(t *testing.T, method, path string) uint64 {
	t.Helper()
	var m dto.Metric
	observer, ok := HTTPDuration.WithLabelValues(method, path).(prometheus.Histogram)
	if !ok {
		t.Fatal("histogram observer has no Write method")
	}
	if err := observer.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestMiddlewareLabels(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	r.Get("/api/apps/{slug}/launch", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	beforeCount := testutil.ToFloat64(HTTPRequests.WithLabelValues("GET", "/api/apps/{slug}/launch", "418"))
	beforeHist := histogramCount(t, "GET", "/api/apps/{slug}/launch")
	req := httptest.NewRequest(http.MethodGet, "/api/apps/wiki/launch", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d", rec.Code)
	}
	// Route pattern (not the raw path) and numeric status label the series.
	if got := testutil.ToFloat64(HTTPRequests.WithLabelValues("GET", "/api/apps/{slug}/launch", "418")); got != beforeCount+1 {
		t.Errorf("request count = %v, want %v", got, beforeCount+1)
	}
	if got := histogramCount(t, "GET", "/api/apps/{slug}/launch"); got != beforeHist+1 {
		t.Errorf("histogram count = %v, want %v", got, beforeHist+1)
	}
}

func TestMiddlewareSkipsProbes(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	r.Get("/metrics", func(w http.ResponseWriter, _ *http.Request) {})
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {})
	before := testutil.CollectAndCount(HTTPRequests, "identityhub_http_requests_total")
	for _, path := range []string{"/metrics", "/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	}
	if got := testutil.CollectAndCount(HTTPRequests, "identityhub_http_requests_total"); got != before {
		t.Errorf("probe requests created series: %d -> %d", before, got)
	}
}
