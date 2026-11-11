// Command cerberus-proxy is the enforcer proxy binary: it intercepts Docker
// API traffic and HTTP egress traffic, evaluating every operation against the
// Cerberus policy engine before transparently forwarding to the backend.
package main

import (
	"context"
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
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/proxy"
	"github.com/metabbe3/cerberus/internal/ratelimit"
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
		listenAddr    = ":2375"
		dockerHost    = "unix:///var/run/docker.sock"
		egressAddr    = ""
		defaultKey    = "k-default-agent"
		policyDir     = "policies"
		dataFile      = "data/prod.json"
		auditDB       = "cerberus.db"
		adminToken    = os.Getenv("CERBERUS_ADMIN_TOKEN")
		logLevel      = "info"
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
	fs.StringVar(&listenAddr, "listen", listenAddr, "listen address (TCP :2375 or unix:///path/to/sock)")
	fs.StringVar(&dockerHost, "docker-host", dockerHost, "backend Docker host URL (unix:///var/run/docker.sock or http://127.0.0.1:2375)")
	fs.StringVar(&egressAddr, "egress-addr", egressAddr, "optional HTTP egress proxy listen address (:8080)")
	fs.StringVar(&defaultKey, "default-key", defaultKey, "fallback policy key ID")
	fs.StringVar(&policyDir, "policy-dir", policyDir, "policies directory")
	fs.StringVar(&dataFile, "data-file", dataFile, "data JSON file")
	fs.StringVar(&auditDB, "audit-db", auditDB, "audit database path")
	fs.StringVar(&logLevel, "log-level", logLevel, "log level (debug|info|warn|error)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	log := newLogger(logLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := policy.NewStore(ctx, policyDir, dataFile)
	if err != nil {
		return fmt.Errorf("cerberus-proxy: load policy: %w", err)
	}

	auditLog, err := audit.Open(ctx, auditDB, audit.Options{})
	if err != nil {
		return fmt.Errorf("cerberus-proxy: open audit db: %w", err)
	}
	defer func() { _ = auditLog.Close() }()

	eng, err := engine.New(store, auditLog, engine.Options{
		CacheSize:   10000,
		EvalTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("cerberus-proxy: engine: %w", err)
	}

	lim := ratelimit.NewLimiter(store, auditLog)

	parsedDockerHost, err := url.Parse(dockerHost)
	if err != nil {
		return fmt.Errorf("cerberus-proxy: invalid docker host: %w", err)
	}

	dp, err := proxy.NewDockerProxy(eng, proxy.DockerConfig{
		TargetURL:     parsedDockerHost,
		FallbackKeyID: defaultKey,
		Limiter:       lim,
		Audit:         auditLog,
	})
	if err != nil {
		return fmt.Errorf("cerberus-proxy: init docker proxy: %w", err)
	}

	isUnix := strings.HasPrefix(listenAddr, "unix://") || strings.HasPrefix(listenAddr, "/")
	network := "tcp"
	bindPath := listenAddr
	if isUnix {
		network = "unix"
		bindPath = strings.TrimPrefix(listenAddr, "unix://")
		_ = os.Remove(bindPath)
	}

	listener, err := net.Listen(network, bindPath)
	if err != nil {
		return fmt.Errorf("cerberus-proxy: listen on %s: %w", listenAddr, err)
	}
	defer func() {
		_ = listener.Close()
		if isUnix {
			_ = os.Remove(bindPath)
		}
	}()

	srv := &http.Server{
		Handler:           dp,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 2)
	go func() { serveErr <- srv.Serve(listener) }()
	log.Info("cerberus-proxy listening", "network", network, "addr", bindPath, "docker_host", dockerHost)

	var egressSrv *http.Server
	if egressAddr != "" {
		ep, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
			FallbackKeyID: defaultKey,
			Limiter:       lim,
			Audit:         auditLog,
		})
		if err != nil {
			return fmt.Errorf("cerberus-proxy: init egress proxy: %w", err)
		}
		egressListener, err := net.Listen("tcp", egressAddr)
		if err != nil {
			return fmt.Errorf("cerberus-proxy: egress listen on %s: %w", egressAddr, err)
		}
		defer func() { _ = egressListener.Close() }()

		egressSrv = &http.Server{
			Handler:           ep,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() { serveErr <- egressSrv.Serve(egressListener) }()
		log.Info("cerberus-proxy egress proxy listening", "addr", egressAddr)
	}

	_ = adminToken
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
	return srv.Shutdown(shutdownCtx)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
