// Package server exposes the engine over stdlib net/http: the public decide
// API, the admin API (bearer token), and the SSE event stream, behind shared
// middleware (body limit, JSON content-type, request-id + access log, panic
// recovery).
package server

import (
	"log/slog"
	"net/http"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Deps are the collaborators the handlers need. Engine may be nil in tests
// that only exercise health/ready/panic paths.
type Deps struct {
	Engine     *engine.Engine
	Store      *policy.Store
	Audit      *audit.Logger
	AdminToken string
	Version    string
}

type server struct {
	deps Deps
	log  *slog.Logger
}

// New builds the full handler: routes + middleware. One ServeMux, Go 1.22
// method patterns (CONVENTIONS.md "HTTP").
func New(d Deps) http.Handler {
	s := &server{deps: d, log: slog.Default()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", promhttp.Handler().ServeHTTP)

	mux.HandleFunc("POST /v1/decide", s.decide(""))
	mux.HandleFunc("POST /v1/decide/llm", s.decide("llm"))
	mux.HandleFunc("POST /v1/decide/tool", s.decide("tool"))

	mux.HandleFunc("GET /v1/admin/data", s.admin(s.getData))
	mux.HandleFunc("PUT /v1/admin/data", s.admin(s.putData))
	mux.HandleFunc("POST /v1/admin/reload", s.admin(s.reload))
	mux.HandleFunc("POST /v1/admin/policy/validate", s.admin(s.validatePolicy))
	mux.HandleFunc("GET /v1/audit", s.admin(s.queryAudit))
	mux.HandleFunc("GET /v1/events", s.admin(s.events))

	return s.withMiddleware(mux)
}

// healthz is an unconditional liveness answer.
func (s *server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// readyz reads 200 once a policy snapshot is live, 503 before that.
func (s *server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.deps.Store == nil || s.deps.Store.Current() == nil {
		writeErr(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}
