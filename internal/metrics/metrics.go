// Package metrics exposes Prometheus counters for authentication
// outcomes and HTTP latency. Delivery layers record observations;
// usecases stay pure. All instruments live on the default registry,
// served by the /metrics route (router.go).
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Scopes for the app label when no single application is involved.
const (
	// AppGlobal marks interactive logins (SSO login page, MFA step-up),
	// which authenticate the user outside any application context.
	AppGlobal = "global"
)

var (
	// AuthFailures counts failed interactive authentications: password
	// and MFA verification on the HTTP surface, launch denials per app
	// slug, and legacy LDAP/RADIUS rejects (app holds the NAS id for
	// RADIUS, "global" for LDAP tree binds).
	AuthFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identityhub_auth_failures_total",
		Help: "Failed authentication attempts by method and application.",
	}, []string{"method", "app"})

	// LegacyBinds counts LDAP and RADIUS bind outcomes (volume, not
	// just failures, so success rate is computable).
	LegacyBinds = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identityhub_legacy_binds_total",
		Help: "Legacy protocol bind attempts by protocol and result.",
	}, []string{"protocol", "result"})

	// HTTPRequests counts served HTTP requests by method, route pattern
	// (never raw paths, so label cardinality stays bounded) and status.
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "identityhub_http_requests_total",
		Help: "Served HTTP requests by method, route pattern and status.",
	}, []string{"method", "path", "status"})

	// HTTPDuration observes HTTP handler latency in seconds.
	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "identityhub_http_request_duration_seconds",
		Help:    "HTTP handler latency by method and route pattern.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

// ObserveAuthFailure records one failed authentication.
func ObserveAuthFailure(method, app string) {
	AuthFailures.WithLabelValues(method, app).Inc()
}

// ObserveLegacyBind records one LDAP or RADIUS bind outcome.
func ObserveLegacyBind(protocol string, ok bool) {
	result := "success"
	if !ok {
		result = "failure"
	}
	LegacyBinds.WithLabelValues(protocol, result).Inc()
}

// skippedPaths are excluded from HTTP metrics: scrape and probe traffic
// would otherwise dominate request and latency series.
var skippedPaths = map[string]bool{
	"/metrics": true, "/healthz": true, "/readyz": true,
}

// Middleware records per-request count and latency. It runs outermost so
// latency covers the full chain; the route pattern is read after the
// inner mux has matched.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skippedPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		pattern := chi.RouteContext(r.Context()).RoutePattern()
		if pattern == "" {
			pattern = "other"
		}
		status := strconv.Itoa(ww.Status())
		HTTPRequests.WithLabelValues(r.Method, pattern, status).Inc()
		HTTPDuration.WithLabelValues(r.Method, pattern).Observe(time.Since(start).Seconds())
	})
}
