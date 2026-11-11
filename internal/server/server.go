// Package server exposes the engine over stdlib net/http: the public decide
// API, the admin API (bearer token), and the SSE event stream, behind shared
// middleware (body limit, JSON content-type, request-id + access log, panic
// recovery).
package server

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/ratelimit"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Deps are the collaborators the handlers need. Engine may be nil in tests
// that only exercise health/ready/panic paths.
type Deps struct {
	Engine     *engine.Engine
	Store      *policy.Store
	Audit      *audit.Logger
	Limiter    *ratelimit.Limiter
	Cluster    ClusterConfig
	AdminToken string
	Version    string
}

// Server is the full Cerberus HTTP handler; it also exposes ShutdownStreams
// for http.Server.RegisterOnShutdown (graceful shutdown must end SSE streams).
type Server struct {
	deps Deps
	log  *slog.Logger

	limiter      *ratelimit.Limiter
	breakGlass   *breakGlassManager
	cluster      *ClusterManager
	adminLimiter *rateLimiter
	queryLimiter *rateLimiter

	handler       http.Handler
	streamsCtx    context.Context    // cancelled by ShutdownStreams
	streamsCancel context.CancelFunc // registered on http.Server via main
}

type rateLimiter struct {
	mu       sync.Mutex
	capacity int
	tokens   float64
	rate     float64
	last     time.Time
}

func newRateLimiter(limitPerMin int) *rateLimiter {
	return &rateLimiter{
		capacity: limitPerMin,
		tokens:   float64(limitPerMin),
		rate:     float64(limitPerMin) / 60.0,
		last:     time.Now(),
	}
}

func (rl *rateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.last = now
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.capacity) {
		rl.tokens = float64(rl.capacity)
	}
	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}
	return false
}

// New builds the full handler: routes + middleware. One ServeMux, Go 1.22
// method patterns (CONVENTIONS.md "HTTP"). Register the returned Server's
// ShutdownStreams with http.Server.RegisterOnShutdown so a graceful shutdown
// ends SSE streams instead of draining on them.
func New(d Deps) *Server {
	lim := d.Limiter
	if lim == nil && d.Store != nil {
		lim = ratelimit.NewLimiter(d.Store, d.Audit)
	}
	s := &Server{
		deps:         d,
		log:          slog.Default(),
		limiter:      lim,
		breakGlass:   newBreakGlassManager(),
		adminLimiter: newRateLimiter(1000), // generous general admin limiter
		queryLimiter: newRateLimiter(10),   // strict 10/min for POST /v1/query
	}
	s.cluster = newClusterManager(s, d.Cluster)
	s.streamsCtx, s.streamsCancel = context.WithCancel(context.Background())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", promhttp.Handler().ServeHTTP)
	mux.HandleFunc("GET /v1/metrics", promhttp.Handler().ServeHTTP)

	mux.HandleFunc("POST /v1/decide", s.decide(""))
	mux.HandleFunc("POST /v1/decide/llm", s.decide("llm"))
	mux.HandleFunc("POST /v1/decide/tool", s.decide("tool"))

	mux.HandleFunc("GET /v1/admin/data", s.admin(s.getData))
	mux.HandleFunc("PUT /v1/admin/data", s.admin(s.putData))
	mux.HandleFunc("POST /v1/admin/reload", s.admin(s.reload))
	mux.HandleFunc("POST /v1/admin/policy/validate", s.admin(s.validatePolicy))
	mux.HandleFunc("GET /v1/audit", s.admin(s.queryAudit))
	mux.HandleFunc("GET /v1/events", s.admin(s.events))
	mux.HandleFunc("GET /v1/status", s.getStatus)
	mux.HandleFunc("GET /v1/admin/status", s.admin(s.getStatus))
	mux.HandleFunc("POST /v1/admin/decisions/erase", s.admin(s.eraseDecision))
	mux.HandleFunc("GET /v1/admin/bundle", s.admin(s.getBundle))
	mux.HandleFunc("POST /v1/admin/bundle", s.admin(s.uploadBundle))
	mux.HandleFunc("PUT /v1/admin/bundle", s.admin(s.uploadBundle))
	mux.HandleFunc("POST /v1/admin/bundle/rollback", s.admin(s.rollbackBundle))
	mux.HandleFunc("POST /v1/internal/sync", s.admin(s.handleInternalSync))
	mux.HandleFunc("POST /v1/admin/break-glass", s.admin(s.postBreakGlass))
	mux.HandleFunc("GET /v1/admin/break-glass", s.admin(s.getBreakGlass))
	mux.HandleFunc("DELETE /v1/admin/break-glass", s.admin(s.deleteBreakGlass))

	// SPRINT 2C REST API parity
	mux.HandleFunc("GET /v1/policies", s.admin(s.listPolicies))
	mux.HandleFunc("GET /v1/data", s.admin(s.getV1Data))
	mux.HandleFunc("GET /v1/data/", s.admin(s.getV1Data))
	mux.HandleFunc("POST /v1/query", s.admin(s.postQuery))

	s.handler = s.withMiddleware(mux)
	return s
}

// ServeHTTP serves the routed, middleware-wrapped handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// ShutdownStreams ends every live /v1/events stream. Register it with
// http.Server.RegisterOnShutdown: SSE handlers otherwise end only on client
// disconnect or audit-logger close (which main runs after Shutdown), so one
// parked dashboard holds graceful shutdown out to its full drain deadline.
func (s *Server) ShutdownStreams() {
	if s.cluster != nil {
		s.cluster.Close()
	}
	s.streamsCancel()
}

// healthz is an unconditional liveness answer.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// readyz reads 200 once a policy snapshot is live, 503 before that.
func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.deps.Store == nil || s.deps.Store.Current() == nil {
		writeErr(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}
