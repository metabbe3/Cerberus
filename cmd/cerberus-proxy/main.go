// Command cerberus-proxy is the enforcer proxy binary: it intercepts Docker
// API traffic and HTTP egress traffic, evaluating every operation against the
// Cerberus policy engine before transparently forwarding to the backend.
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
	"net/url"
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
		fmt.Printf("cerberus-proxy %s\n", version)
		os.Exit(0)
	}

	if err := run(); err != nil {
		slog.Error("cerberus-proxy: fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listenAddr = ":2375"
		dockerHost = "unix:///var/run/docker.sock"
		egressAddr = ""
		engineURL  = "http://127.0.0.1:8089"
		standalone = false
		defaultKey = "k-default-agent"
		policyDir  = "policies"
		dataFile   = "data/prod.json"
		auditDB    = "cerberus.db"
		adminToken = os.Getenv("CERBERUS_ADMIN_TOKEN")
		logLevel   = "info"
	)

	if v := os.Getenv("CERBERUS_PROXY_LISTEN"); v != "" {
		listenAddr = v
	}
	if v := os.Getenv("CERBERUS_PROXY_DOCKER_HOST"); v != "" {
		dockerHost = v
	}
	if v := os.Getenv("CERBERUS_PROXY_EGRESS_ADDR"); v != "" {
		egressAddr = v
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

	fs := flag.NewFlagSet("cerberus-proxy", flag.ContinueOnError)
	fs.StringVar(&listenAddr, "listen", listenAddr, "listen address (TCP :2375 or unix:///path/to/sock, or empty/none to disable)")
	fs.StringVar(&dockerHost, "docker-host", dockerHost, "backend Docker host URL (unix:///var/run/docker.sock or http://127.0.0.1:2375)")
	fs.StringVar(&egressAddr, "egress-addr", egressAddr, "optional HTTP egress proxy listen address (:8080)")
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

	log := newLogger(logLevel)
	slog.SetDefault(log)

	if adminToken == "" {
		log.Warn("UNAUTHENTICATED mode: CERBERUS_ADMIN_TOKEN not set, proxy requests are unauthenticated")
	}

	if (listenAddr == "" || listenAddr == "none") && egressAddr == "" {
		return errors.New("cerberus-proxy: at least one of -listen or -egress-addr must be specified")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		dec      engine.Decider
		lim      *ratelimit.Limiter
		auditLog *audit.Logger
	)

	if standalone {
		log.Info("cerberus-proxy running in STANDALONE mode with local engine")
		store, err := policy.NewStore(ctx, policyDir, dataFile)
		if err != nil {
			return fmt.Errorf("cerberus-proxy: load policy: %w", err)
		}

		aLog, err := audit.Open(ctx, auditDB, audit.Options{})
		if err != nil {
			return fmt.Errorf("cerberus-proxy: open audit db: %w", err)
		}
		defer func() { _ = aLog.Close() }()
		auditLog = aLog

		eng, err := engine.New(store, auditLog, engineOptions())
		if err != nil {
			return fmt.Errorf("cerberus-proxy: engine: %w", err)
		}
		defer eng.Close()

		lim = ratelimit.NewLimiter(store, auditLog)
		defer lim.Close()

		dec = eng
	} else {
		if strings.TrimSpace(engineURL) == "" {
			return errors.New("cerberus-proxy: -engine-url is required (or run with CERBERUS_STANDALONE=true)")
		}
		log.Info("cerberus-proxy running in UNIFIED mode forwarding to engine", "engine_url", engineURL)
		dec = engine.NewHTTPDecider(engineURL, adminToken)
	}

	serveErr := make(chan error, 2)
	var (
		srv          *http.Server
		listener     net.Listener
		isUnix       bool
		bindPath     string
		egressSrv    *http.Server
		egressListen net.Listener
	)

	if listenAddr != "" && listenAddr != "none" {
		parsedDockerHost, err := url.Parse(dockerHost)
		if err != nil {
			return fmt.Errorf("cerberus-proxy: invalid docker host: %w", err)
		}

		dp, err := proxy.NewDockerProxy(dec, proxy.DockerConfig{
			TargetURL:     parsedDockerHost,
			FallbackKeyID: defaultKey,
			Limiter:       lim,
			Audit:         auditLog,
		})
		if err != nil {
			return fmt.Errorf("cerberus-proxy: init docker proxy: %w", err)
		}

		isUnix = strings.HasPrefix(listenAddr, "unix://") || strings.HasPrefix(listenAddr, "/")
		network := "tcp"
		bindPath = listenAddr
		if isUnix {
			network = "unix"
			bindPath = strings.TrimPrefix(listenAddr, "unix://")
			_ = os.Remove(bindPath) //nolint:gosec // G703 operator-set unix path
		}

		l, err := net.Listen(network, bindPath) //nolint:gosec // G703/G704 bindPath is operator-set flag
		if err != nil {
			return fmt.Errorf("cerberus-proxy: listen on %s: %w", listenAddr, err)
		}
		listener = l
		defer func() {
			_ = listener.Close()
			if isUnix {
				_ = os.Remove(bindPath) //nolint:gosec // G703 operator-set unix path
			}
		}()

		srv = &http.Server{
			Handler:           requireAdminAuth(adminToken, dp),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() { serveErr <- srv.Serve(listener) }()
		log.Info("cerberus-proxy listening", "network", network, "addr", bindPath, "docker_host", dockerHost)
	}

	if egressAddr != "" {
		ep, err := proxy.NewEgressProxy(dec, proxy.EgressConfig{
			FallbackKeyID: defaultKey,
			Limiter:       lim,
			Audit:         auditLog,
		})
		if err != nil {
			return fmt.Errorf("cerberus-proxy: init egress proxy: %w", err)
		}
		el, err := net.Listen("tcp", egressAddr)
		if err != nil {
			return fmt.Errorf("cerberus-proxy: egress listen on %s: %w", egressAddr, err)
		}
		egressListen = el
		defer func() { _ = egressListen.Close() }()

		egressSrv = &http.Server{
			Handler:           requireAdminAuth(adminToken, ep),
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() { serveErr <- egressSrv.Serve(egressListen) }()
		log.Info("cerberus-proxy egress proxy listening", "addr", egressAddr)
	}

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if egressSrv != nil {
		_ = egressSrv.Shutdown(shutdownCtx)
	}
	if srv != nil {
		return srv.Shutdown(shutdownCtx)
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	return util.NewLogger(level)
}

// requireAdminAuth wraps an http.Handler with Bearer token authentication when token is non-empty.
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

// engineOptions returns engine options using config.DefaultEvalTimeout (or CERBERUS_EVAL_TIMEOUT override).
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
