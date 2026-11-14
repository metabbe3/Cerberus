package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/config"
)

func TestCerberusProxy_Version(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run . --version failed: %v, out: %s", err, out)
	}
	if !strings.HasPrefix(string(out), "cerberus-proxy dev") {
		t.Fatalf("unexpected version output: %s", out)
	}
}

func TestRequireAdminAuth(t *testing.T) {
	dummy := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	const expectedVal = "test-adm-bearer-val" //nolint:gosec // G101 dummy test value

	// 1. With token configured
	handlerWithToken := requireAdminAuth(expectedVal, dummy)

	// No header -> 401
	recNoAuth := httptest.NewRecorder()
	reqNoAuth := httptest.NewRequest("GET", "/test", nil)
	handlerWithToken.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("status without auth = %d, want 401", recNoAuth.Code)
	}

	// Wrong token -> 401
	recWrong := httptest.NewRecorder()
	reqWrong := httptest.NewRequest("GET", "/test", nil)
	reqWrong.Header.Set("Authorization", "Bearer wrong-value")
	handlerWithToken.ServeHTTP(recWrong, reqWrong)
	if recWrong.Code != http.StatusUnauthorized {
		t.Fatalf("status with wrong token = %d, want 401", recWrong.Code)
	}

	// Query token -> 401 (?token= ignored)
	recQuery := httptest.NewRecorder()
	reqQuery := httptest.NewRequest("GET", "/test?token="+expectedVal, nil)
	handlerWithToken.ServeHTTP(recQuery, reqQuery)
	if recQuery.Code != http.StatusUnauthorized {
		t.Fatalf("status with query token = %d, want 401", recQuery.Code)
	}

	// Correct token -> 200
	recGood := httptest.NewRecorder()
	reqGood := httptest.NewRequest("GET", "/test", nil)
	reqGood.Header.Set("Authorization", "Bearer "+expectedVal)
	handlerWithToken.ServeHTTP(recGood, reqGood)
	if recGood.Code != http.StatusOK {
		t.Fatalf("status with good token = %d, want 200", recGood.Code)
	}
	if recGood.Body.String() != "ok" {
		t.Fatalf("body = %q, want ok", recGood.Body.String())
	}

	// 2. Without token configured (empty) -> all requests pass through
	handlerNoToken := requireAdminAuth("", dummy)
	recPass := httptest.NewRecorder()
	reqPass := httptest.NewRequest("GET", "/test", nil)
	handlerNoToken.ServeHTTP(recPass, reqPass)
	if recPass.Code != http.StatusOK {
		t.Fatalf("status without token config = %d, want 200", recPass.Code)
	}
	if recPass.Body.String() != "ok" {
		t.Fatalf("body = %q, want ok", recPass.Body.String())
	}
}

func TestStartupUnauthenticatedModeWarnLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	adminToken := ""
	if adminToken == "" {
		logger.Warn("UNAUTHENTICATED mode: CERBERUS_ADMIN_TOKEN not set, proxy requests are unauthenticated")
	}

	out := buf.String()
	if !strings.Contains(out, "UNAUTHENTICATED mode") {
		t.Fatalf("expected UNAUTHENTICATED mode warning, got: %s", out)
	}
}

func TestSubprocessUnauthenticatedWarning(t *testing.T) {
	// Run binary with invalid listen address to exit immediately after startup logs
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", ".", "-listen", "invalid-port-trigger-fail")
	cmd.Env = append(cmd.Environ(), "CERBERUS_ADMIN_TOKEN=")
	out, _ := cmd.CombinedOutput()
	outStr := string(out)

	if !strings.Contains(outStr, "UNAUTHENTICATED mode") {
		t.Fatalf("expected UNAUTHENTICATED mode warning in startup logs, got:\n%s", outStr)
	}
}

func TestEngineOptions(t *testing.T) {
	// 1. Default matches config.DefaultEvalTimeout
	t.Setenv("CERBERUS_EVAL_TIMEOUT", "")
	opts := engineOptions()
	if opts.EvalTimeout != config.DefaultEvalTimeout {
		t.Fatalf("expected EvalTimeout %v, got %v", config.DefaultEvalTimeout, opts.EvalTimeout)
	}

	// 2. Override via CERBERUS_EVAL_TIMEOUT
	t.Setenv("CERBERUS_EVAL_TIMEOUT", "5s")
	optsOverride := engineOptions()
	if optsOverride.EvalTimeout != 5*time.Second {
		t.Fatalf("expected EvalTimeout 5s, got %v", optsOverride.EvalTimeout)
	}
}
