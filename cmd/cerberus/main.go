// Command cerberus is the Cerberus policy-engine binary: HTTP :8089 serving
// the decide API, admin API, SSE events and Prometheus metrics, with async
// SQLite audit and SIGHUP policy reload.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/config"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/server"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Printf("cerberus %s\n", version)
		os.Exit(0)
	}
	if len(os.Args) > 2 && os.Args[1] == "--erase" {
		id, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid id: %v\n", err)
			os.Exit(1)
		}
		dbPath := "cerberus.db"
		if v := os.Getenv("CERBERUS_AUDIT_DB"); v != "" {
			dbPath = v
		}
		al, err := audit.Open(context.Background(), dbPath, audit.Options{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "open audit db: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = al.Close() }()
		ok, err := al.Erase(context.Background(), id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erase error: %v\n", err)
			os.Exit(1)
		}
		if !ok {
			fmt.Printf("event %d not found\n", id)
			os.Exit(1)
		}
		fmt.Printf("event %d erased\n", id)
		os.Exit(0)
	}
	if err := run(); err != nil {
		slog.Error("cerberus: fatal", "err", err)
		os.Exit(1)
	}
}

// run wires config → store → audit → engine → server, serves until SIGINT or
// SIGTERM, then shuts the HTTP server down (10s) and closes the audit logger.
func run() error {
	cfg, err := config.Load(os.Args[1:], os.Getenv)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := policy.NewStore(ctx, cfg.PolicyDir, cfg.DataFile)
	if err != nil {
		return fmt.Errorf("cerberus: load policy: %w", err)
	}
	auditLog, err := audit.Open(ctx, cfg.AuditDB, audit.Options{})
	if err != nil {
		return fmt.Errorf("cerberus: open audit db %s: %w", cfg.AuditDB, err)
	}
	eng, err := engine.New(store, auditLog, engine.Options{
		CacheSize:   cfg.CacheSize,
		EvalTimeout: cfg.EvalTimeout,
	})
	if err != nil {
		return fmt.Errorf("cerberus: engine: %w", err)
	}

	stopHUP := watchHUP(ctx, store, log)
	defer stopHUP()

	api := server.New(server.Deps{Engine: eng, Store: store, Audit: auditLog, AdminToken: cfg.AdminToken, Version: version})
	srv := newHTTPServer(cfg.Addr, api)
	// End SSE streams when shutdown begins; the events handler otherwise ends
	// only on client disconnect or audit close (below), and Shutdown would wait
	// out its full deadline on any parked dashboard.
	srv.RegisterOnShutdown(api.ShutdownStreams)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	log.Info("cerberus listening",
		"addr", cfg.Addr, "epoch", store.Current().Epoch, "version", version)

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown incomplete", "err", err)
	}
	if err := auditLog.Close(); err != nil {
		log.Error("audit close", "err", err)
	}
	return nil
}

// newHTTPServer builds the public listener: ReadTimeout bounds the whole
// request read (headers+body) so slow-loris body tricklers are cut off instead
// of parking a goroutine in readBody forever. It does not set WriteTimeout —
// SSE streams write for minutes after the request is fully read. IdleTimeout
// reaps keep-alive connections parked between requests.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// watchHUP reloads policy+data from disk on SIGHUP; a failed reload keeps the
// previous snapshot live and is logged. The watcher ends when ctx is done or
// the returned stop is called (which also unregisters the signal and waits for
// an in-flight reload to return).
func watchHUP(ctx context.Context, store *policy.Store, log *slog.Logger) (stop func()) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				snap, err := store.Reload(ctx)
				if err != nil {
					log.Error("sighup reload failed; previous snapshot stays live",
						"err", err, "epoch", store.Current().Epoch)
					continue
				}
				log.Info("sighup reload ok", "epoch", snap.Epoch)
			}
		}
	}()
	return func() {
		signal.Stop(hup)
		cancel()
		<-done
	}
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
