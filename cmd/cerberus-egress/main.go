// Command cerberus-egress is the egress shield proxy binary: it intercepts
// outbound HTTP and HTTPS (via CONNECT) traffic and evaluates destination hosts
// against Cerberus policy via the central engine HTTP endpoint (or local engine in standalone mode).
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/config"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/proxy"
	"github.com/metabbe3/cerberus/internal/ratelimit"
	"github.com/metabbe3/cerberus/internal/util"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Printf("cerberus-egress %s\n", version)
		os.Exit(0)
	}

	if err := run(); err != nil {
		slog.Error("cerberus-egress: fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listenAddr = ":8080"
		engineURL  = "http://127.0.0.1:8089"
		standalone = false
		defaultKey = "k-default-agent"
		policyDir  = "policies"
		dataFile   = "data/prod.json"
		auditDB    = "cerberus.db"
		adminToken = os.Getenv("CERBERUS_ADMIN_TOKEN")
		logLevel   = "info"
	)

	if v := os.Getenv("CERBERUS_EGRESS_ADDR"); v != "" {
		listenAddr = v
	} else if v := os.Getenv("CERBERUS_PROXY_EGRESS_ADDR"); v != "" {
		listenAddr = v
	}
	if v := os.Getenv("CERBERUS_ENGINE_URL"); v != "" {
		engineURL = v
	}
	if v := os.Getenv("CERBERUS_STANDALONE"); v == "true" || v == "1" {
		standalone = true
	}
	if v := os.Getenv("CERBERUS_PROXY_DEFAULT_KEY"); v != "" {
		defaultKey = v
	}
	if v := os.Getenv("CERBERUS_POLICY_DIR"); v != "" {
		policyDir = v
	}
	if v := os.Getenv("CERBERUS_DATA_FILE"); v != "" {
		dataFile = v
	}
	if v := os.Getenv("CERBERUS_AUDIT_DB"); v != "" {
		auditDB = v
	}
	if v := os.Getenv("CERBERUS_LOG_LEVEL"); v != "" {
		logLevel = v
	}

	fs := flag.NewFlagSet("cerberus-egress", flag.ContinueOnError)
	fs.StringVar(&listenAddr, "listen", listenAddr, "listen address (TCP :8080) ($CERBERUS_EGRESS_ADDR)")
	fs.StringVar(&engineURL, "engine-url", engineURL, "Cerberus engine URL ($CERBERUS_ENGINE_URL)")
	fs.BoolVar(&standalone, "standalone", standalone, "run with local embedded engine instead of remote HTTP engine ($CERBERUS_STANDALONE)")
	fs.StringVar(&defaultKey, "default-key", defaultKey, "fallback policy key ID")
	fs.StringVar(&policyDir, "policy-dir", policyDir, "policies directory (standalone mode only)")
	fs.StringVar(&dataFile, "data-file", dataFile, "data JSON file (standalone mode only)")
	fs.StringVar(&auditDB, "audit-db", auditDB, "audit database path (standalone mode only)")
	fs.StringVar(&adminToken, "admin-token", adminToken, "admin token for bearer auth")
	fs.StringVar(&logLevel, "log-level", logLevel, "log level (debug|info|warn|error)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	log := util.NewLogger(logLevel)
	slog.SetDefault(log)

	if adminToken == "" {
		log.Warn("UNAUTHENTICATED mode: CERBERUS_ADMIN_TOKEN not set, egress requests are unauthenticated")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		dec      engine.Decider
		lim      *ratelimit.Limiter
		auditLog *audit.Logger
	)

	if standalone {
		log.Info("cerberus-egress running in STANDALONE mode with local engine")
		store, err := policy.NewStore(ctx, policyDir, dataFile)
		if err != nil {
			return fmt.Errorf("cerberus-egress: load policy: %w", err)
		}

		aLog, err := audit.Open(ctx, auditDB, audit.Options{})
		if err != nil {
			return fmt.Errorf("cerberus-egress: open audit db: %w", err)
		}
		defer func() { _ = aLog.Close() }()
		auditLog = aLog

		eng, err := engine.New(store, auditLog, engineOptions())
		if err != nil {
			return fmt.Errorf("cerberus-egress: engine: %w", err)
		}
		defer eng.Close()

		lim = ratelimit.NewLimiter(store, auditLog)
		defer lim.Close()

		dec = eng
	} else {
		if strings.TrimSpace(engineURL) == "" {
			return errors.New("cerberus-egress: -engine-url is required (or run with CERBERUS_STANDALONE=true)")
		}
		log.Info("cerberus-egress running in UNIFIED mode forwarding to engine", "engine_url", engineURL)
		dec = engine.NewHTTPDecider(engineURL, adminToken)
	}

	ep, err := proxy.NewEgressProxy(dec, proxy.EgressConfig{
		FallbackKeyID: defaultKey,
		Limiter:       lim,
		Audit:         auditLog,
	})
	if err != nil {
		return fmt.Errorf("cerberus-egress: init egress proxy: %w", err)
	}

	el, err := net.Listen("tcp", listenAddr) //nolint:gosec // G102 binds to configured address
	if err != nil {
		return fmt.Errorf("cerberus-egress: listen on %s: %w", listenAddr, err)
	}
	defer func() { _ = el.Close() }()

	srv := &http.Server{
		Handler:           requireAdminAuth(adminToken, ep),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(el) }()
	log.Info("cerberus-egress proxy listening", "addr", listenAddr)

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func requireAdminAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func engineOptions() engine.Options {
	timeout := config.DefaultEvalTimeout
	if v := os.Getenv("CERBERUS_EVAL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			timeout = d
		}
	}
	return engine.Options{
		CacheSize:   10000,
		EvalTimeout: timeout,
	}
}
