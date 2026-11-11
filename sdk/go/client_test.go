package cerberus_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	cerberus "github.com/metabbe3/cerberus/sdk/go"
)

func TestClient_DecideToolAndGuardedExecutor_Allow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cerberus.Decision{
			Decision: "allow",
			RuleID:   "tool.allow",
			Reason:   "tool allowed",
		})
	}))
	defer server.Close()

	client := cerberus.NewClient(cerberus.ClientOptions{
		BaseURL: server.URL,
		KeyID:   "test-key",
	})
	guard := cerberus.NewGuardedExecutor(client)

	executed := false
	runner := func(ctx context.Context, tool string, args any) (any, error) {
		executed = true
		return "tool-result", nil
	}

	guardedRunner := guard.Wrap(runner)
	res, err := guardedRunner(context.Background(), "bash", map[string]any{"cmd": "ls -la"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !executed {
		t.Fatal("expected tool runner to be executed")
	}
	if res != "tool-result" {
		t.Fatalf("unexpected result: %v", res)
	}

	m := client.Metrics()
	if m.TotalCalls != 1 || m.AllowedCalls != 1 || m.DeniedCalls != 0 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
}

func TestClient_DecideToolAndGuardedExecutor_Deny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cerberus.Decision{
			Decision: "deny",
			RuleID:   "shield.cmd.dangerous",
			Reason:   "rm -rf forbidden",
		})
	}))
	defer server.Close()

	client := cerberus.NewClient(cerberus.ClientOptions{
		BaseURL: server.URL,
		KeyID:   "test-key",
	})
	guard := cerberus.NewGuardedExecutor(client)

	executed := false
	runner := func(ctx context.Context, tool string, args any) (any, error) {
		executed = true
		return "tool-result", nil
	}

	guardedRunner := guard.Wrap(runner)
	_, err := guardedRunner(context.Background(), "bash", map[string]any{"cmd": "rm -rf /"})
	if err == nil {
		t.Fatal("expected error on denied tool, got nil")
	}
	if executed {
		t.Fatal("tool runner must NOT be executed on deny")
	}

	var deniedErr *cerberus.ErrDenied
	if !errors.As(err, &deniedErr) {
		t.Fatalf("expected ErrDenied, got: %T (%v)", err, err)
	}
	if deniedErr.RuleID != "shield.cmd.dangerous" {
		t.Fatalf("expected rule_id shield.cmd.dangerous, got %s", deniedErr.RuleID)
	}

	m := client.Metrics()
	if m.TotalCalls != 1 || m.AllowedCalls != 0 || m.DeniedCalls != 1 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
}

func TestClient_CachingTTL60s(t *testing.T) {
	var requestCount atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cerberus.Decision{
			Decision: "allow",
			RuleID:   "tool.allow",
			Reason:   "tool allowed",
		})
	}))
	defer server.Close()

	client := cerberus.NewClient(cerberus.ClientOptions{
		BaseURL:  server.URL,
		KeyID:    "test-key",
		CacheTTL: 50 * time.Millisecond,
	})

	// First call -> misses cache, hits server
	dec1, err := client.DecideTool(context.Background(), "read_file", map[string]any{"path": "file.txt"})
	if err != nil {
		t.Fatalf("dec1: %v", err)
	}
	if dec1.Cached {
		t.Fatal("dec1 should not be cached")
	}
	if requestCount.Load() != 1 {
		t.Fatalf("expected 1 server request, got %d", requestCount.Load())
	}

	// Second call with same args -> hits cache
	dec2, err := client.DecideTool(context.Background(), "read_file", map[string]any{"path": "file.txt"})
	if err != nil {
		t.Fatalf("dec2: %v", err)
	}
	if !dec2.Cached {
		t.Fatal("dec2 should be cached")
	}
	if requestCount.Load() != 1 {
		t.Fatalf("expected 1 server request (cached), got %d", requestCount.Load())
	}

	// Wait for cache TTL to expire
	time.Sleep(70 * time.Millisecond)

	// Third call -> cache expired, hits server again
	dec3, err := client.DecideTool(context.Background(), "read_file", map[string]any{"path": "file.txt"})
	if err != nil {
		t.Fatalf("dec3: %v", err)
	}
	if dec3.Cached {
		t.Fatal("dec3 should not be cached after TTL expired")
	}
	if requestCount.Load() != 2 {
		t.Fatalf("expected 2 server requests after expiry, got %d", requestCount.Load())
	}

	m := client.Metrics()
	if m.CacheHits != 1 || m.CacheMisses != 2 {
		t.Fatalf("unexpected cache metrics: hits=%d misses=%d", m.CacheHits, m.CacheMisses)
	}
}

func TestClient_AutoRetryBackoff(t *testing.T) {
	var attempts atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := attempts.Add(1)
		if att < 3 {
			// Fail first two attempts with 503
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		// Third attempt succeeds
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cerberus.Decision{
			Decision: "allow",
			RuleID:   "tool.allow",
			Reason:   "ok",
		})
	}))
	defer server.Close()

	client := cerberus.NewClient(cerberus.ClientOptions{
		BaseURL:    server.URL,
		KeyID:      "test-key",
		MaxRetries: 3,
		RetryDelay: 5 * time.Millisecond,
	})

	dec, err := client.DecideTool(context.Background(), "fetch_data", nil)
	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if !dec.Allowed() {
		t.Fatalf("expected allow, got: %s", dec.Decision)
	}

	m := client.Metrics()
	if m.Retries != 2 {
		t.Fatalf("expected 2 retries, got %d", m.Retries)
	}
	if m.TotalCalls != 1 || m.AllowedCalls != 1 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
}
