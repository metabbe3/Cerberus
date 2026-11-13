package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/proxy"
)

func setupTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	repoRoot := findRepoRoot(t)
	policyDir := filepath.Join(repoRoot, "policies")
	dataFile := filepath.Join(repoRoot, "policies", "testdata", "data.json")

	ctx := context.Background()
	store, err := policy.NewStore(ctx, policyDir, dataFile)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}

	auditDB := filepath.Join(t.TempDir(), "audit.db")
	auditLog, err := audit.Open(ctx, auditDB, audit.Options{})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	eng, err := engine.New(store, auditLog, engine.Options{
		CacheSize:   1000,
		EvalTimeout: 5 * time.Second, // generous: OPA cold compile on slow CI runners
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func setupTestEngineWithStore(t *testing.T) (*engine.Engine, *policy.Store) {
	t.Helper()
	repoRoot := findRepoRoot(t)
	policyDir := filepath.Join(repoRoot, "policies")
	dataFile := filepath.Join(repoRoot, "policies", "testdata", "data.json")

	ctx := context.Background()
	store, err := policy.NewStore(ctx, policyDir, dataFile)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}

	auditDB := filepath.Join(t.TempDir(), "audit.db")
	auditLog, err := audit.Open(ctx, auditDB, audit.Options{})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	eng, err := engine.New(store, auditLog, engine.Options{
		CacheSize:   1000,
		EvalTimeout: 5 * time.Second, // generous: OPA cold compile on slow CI runners
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng, store
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", dir)
		}
		dir = parent
	}
}

// fakeDockerDaemon simulates a Docker Engine daemon.
func newFakeDockerDaemon(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1.41/containers/{id}/stop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"stopped"}`))
	})
	mux.HandleFunc("DELETE /v1.41/containers/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"removed"}`))
	})
	mux.HandleFunc("POST /v1.41/containers/create", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"c123456","Warnings":[]}`))
	})
	mux.HandleFunc("POST /v1.41/containers/{id}/exec", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"exec123"}`))
	})
	mux.HandleFunc("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		w.Header().Set("Content-Type", "application/json")
		if id == "labeled-container" {
			_, _ = w.Write([]byte(`{"Config":{"Labels":{"cerberus.policy-key":"k-test-labeled"}}}`))
		} else {
			_, _ = w.Write([]byte(`{"Config":{"Labels":{}}}`))
		}
	})

	// Streaming attach endpoint that upgrades to raw TCP hijack
	mux.HandleFunc("POST /v1.41/containers/{id}/attach", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "tcp") &&
			!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			http.Error(w, "must upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = conn.Close() }()

		// Send 101 UPGRADED
		_, _ = bufrw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		_ = bufrw.Flush()

		// Echo loop
		buf := make([]byte, 1024)
		for {
			n, err := bufrw.Read(buf)
			if n > 0 {
				_, _ = bufrw.Write(append([]byte("echo:"), buf[:n]...))
				_ = bufrw.Flush()
			}
			if err != nil {
				break
			}
		}
	})

	return httptest.NewServer(mux)
}

func TestDockerProxy_NormalContainerStopAndRm(t *testing.T) {
	eng := setupTestEngine(t)
	daemon := newFakeDockerDaemon(t)
	defer daemon.Close()

	daemonURL, _ := url.Parse(daemon.URL)
	dp, err := proxy.NewDockerProxy(eng, proxy.DockerConfig{
		TargetURL:     daemonURL,
		FallbackKeyID: "k-agent-normal",
	})
	if err != nil {
		t.Fatalf("NewDockerProxy: %v", err)
	}
	proxyServer := httptest.NewServer(dp)
	defer proxyServer.Close()

	client := proxyServer.Client()

	// 1. Stop normal container -> should allow (200 OK)
	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1.41/containers/normal-worker-1/stop", nil)
	req.Header.Set("X-Cerberus-Key", "k-test-open")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("stop request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d, body: %s", resp.StatusCode, body)
	}

	// 2. Rm normal container -> should allow (200 OK)
	req, _ = http.NewRequest(http.MethodDelete, proxyServer.URL+"/v1.41/containers/normal-worker-1", nil)
	req.Header.Set("X-Cerberus-Key", "k-test-open")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("rm request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d, body: %s", resp.StatusCode, body)
	}
}

func TestDockerProxy_ProtectedContainerDenied(t *testing.T) {
	eng := setupTestEngine(t)
	daemon := newFakeDockerDaemon(t)
	defer daemon.Close()

	daemonURL, _ := url.Parse(daemon.URL)
	dp, err := proxy.NewDockerProxy(eng, proxy.DockerConfig{
		TargetURL:     daemonURL,
		FallbackKeyID: "k-agent-normal",
	})
	if err != nil {
		t.Fatalf("NewDockerProxy: %v", err)
	}
	proxyServer := httptest.NewServer(dp)
	defer proxyServer.Close()

	client := proxyServer.Client()

	// 1. Stop protected container (teknikalidnew-db-1) -> should be 403 Forbidden
	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1.41/containers/teknikalidnew-db-1/stop", nil)
	req.Header.Set("X-Cerberus-Key", "k-test-open")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("stop protected request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}

	var errBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody["rule_id"] != "shield.container.protected" {
		t.Fatalf("expected rule_id shield.container.protected, got %v", errBody["rule_id"])
	}

	// 2. Rm protected container (teknikalidnew-db-1) -> should be 403 Forbidden
	req, _ = http.NewRequest(http.MethodDelete, proxyServer.URL+"/v1.41/containers/teknikalidnew-db-1", nil)
	req.Header.Set("X-Cerberus-Key", "k-test-open")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("rm protected request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}

	var errBodyRm map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&errBodyRm); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBodyRm["rule_id"] != "shield.container.protected" {
		t.Fatalf("expected rule_id shield.container.protected, got %v", errBodyRm["rule_id"])
	}
}

func TestDockerProxy_SecurityChecks(t *testing.T) {
	eng := setupTestEngine(t)
	daemon := newFakeDockerDaemon(t)
	defer daemon.Close()

	daemonURL, _ := url.Parse(daemon.URL)
	dp, err := proxy.NewDockerProxy(eng, proxy.DockerConfig{
		TargetURL:     daemonURL,
		FallbackKeyID: "k-agent-normal",
	})
	if err != nil {
		t.Fatalf("NewDockerProxy: %v", err)
	}
	proxyServer := httptest.NewServer(dp)
	defer proxyServer.Close()

	client := proxyServer.Client()

	tests := []struct {
		name           string
		endpoint       string
		method         string
		body           string
		expectedStatus int
		expectedRuleID string
	}{
		{
			name:     "mount docker.sock forbidden in create",
			endpoint: "/v1.41/containers/create",
			method:   http.MethodPost,
			body: `{
				"Image": "alpine:latest",
				"HostConfig": {
					"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]
				}
			}`,
			expectedStatus: http.StatusForbidden,
			expectedRuleID: "docker.mount_forbidden",
		},
		{
			name:     "privileged mode forbidden in create",
			endpoint: "/v1.41/containers/create",
			method:   http.MethodPost,
			body: `{
				"Image": "alpine:latest",
				"HostConfig": {
					"Privileged": true
				}
			}`,
			expectedStatus: http.StatusForbidden,
			expectedRuleID: "docker.privileged_forbidden",
		},
		{
			name:     "cap-add ALL forbidden in create",
			endpoint: "/v1.41/containers/create",
			method:   http.MethodPost,
			body: `{
				"Image": "alpine:latest",
				"HostConfig": {
					"CapAdd": ["ALL"]
				}
			}`,
			expectedStatus: http.StatusForbidden,
			expectedRuleID: "docker.capability_forbidden",
		},
		{
			name:     "mount docker.sock forbidden in exec",
			endpoint: "/v1.41/containers/c123/exec",
			method:   http.MethodPost,
			body: `{
				"AttachStdin": true,
				"Cmd": ["sh"],
				"Mounts": ["/var/run/docker.sock:/var/run/docker.sock"]
			}`,
			expectedStatus: http.StatusForbidden,
			expectedRuleID: "docker.mount_forbidden",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, proxyServer.URL+tc.endpoint, bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Cerberus-Key", "k-test-open")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.expectedStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d, got %d, body: %s", tc.expectedStatus, resp.StatusCode, body)
			}

			var errBody map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
				t.Fatalf("decode json: %v", err)
			}
			if errBody["rule_id"] != tc.expectedRuleID {
				t.Fatalf("expected rule_id %s, got %v", tc.expectedRuleID, errBody["rule_id"])
			}
		})
	}
}

func TestDockerProxy_StreamingAttachNotBroken(t *testing.T) {
	eng := setupTestEngine(t)
	daemon := newFakeDockerDaemon(t)
	defer daemon.Close()

	daemonURL, _ := url.Parse(daemon.URL)
	dp, err := proxy.NewDockerProxy(eng, proxy.DockerConfig{
		TargetURL:     daemonURL,
		FallbackKeyID: "k-agent-normal",
	})
	if err != nil {
		t.Fatalf("NewDockerProxy: %v", err)
	}
	proxyServer := httptest.NewServer(dp)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req := "POST /v1.41/containers/normal-worker-1/attach HTTP/1.1\r\n" +
		"Host: " + proxyURL.Host + "\r\n" +
		"Upgrade: tcp\r\n" +
		"Connection: Upgrade\r\n" +
		"X-Cerberus-Key: k-test-open\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write req: %v", err)
	}

	bufrw := bufio.NewReader(conn)
	statusLine, err := bufrw.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 status, got: %s", statusLine)
	}

	// Consume headers until empty line
	for {
		line, err := bufrw.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Test bidirectional streaming
	testPayload := "hello-docker-attach\n"
	if _, err := conn.Write([]byte(testPayload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	echoed, err := bufrw.ReadString('\n')
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if !strings.Contains(echoed, "echo:hello-docker-attach") {
		t.Fatalf("expected echoed payload, got: %q", echoed)
	}
}

func TestDockerProxy_ContainerLabelResolution(t *testing.T) {
	eng := setupTestEngine(t)
	daemon := newFakeDockerDaemon(t)
	defer daemon.Close()

	daemonURL, _ := url.Parse(daemon.URL)
	dp, err := proxy.NewDockerProxy(eng, proxy.DockerConfig{
		TargetURL:     daemonURL,
		FallbackKeyID: "k-fallback",
	})
	if err != nil {
		t.Fatalf("NewDockerProxy: %v", err)
	}
	proxyServer := httptest.NewServer(dp)
	defer proxyServer.Close()

	client := proxyServer.Client()

	// Calling /containers/labeled-container/stop without X-Cerberus-Key header
	// Should fetch label "cerberus.policy-key" = "k-test-labeled" from daemon
	req, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/v1.41/containers/labeled-container/stop", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d, body: %s", resp.StatusCode, body)
	}
}

func BenchmarkDockerProxy_Overhead(b *testing.B) {
	eng := setupTestEngine(&testing.T{})
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer daemon.Close()

	daemonURL, _ := url.Parse(daemon.URL)
	dp, err := proxy.NewDockerProxy(eng, proxy.DockerConfig{
		TargetURL:     daemonURL,
		FallbackKeyID: "k-test-open",
	})
	if err != nil {
		b.Fatalf("NewDockerProxy: %v", err)
	}
	proxyServer := httptest.NewServer(dp)
	defer proxyServer.Close()

	client := proxyServer.Client()

	b.Run("Direct", func(b *testing.B) {
		reqURL := daemon.URL + "/containers/json"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp, err := client.Get(reqURL)
			if err != nil {
				b.Fatal(err)
			}
			_ = resp.Body.Close()
		}
	})

	b.Run("Proxied", func(b *testing.B) {
		reqURL := proxyServer.URL + "/v1.41/containers/normal-worker-1/start"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequest(http.MethodPost, reqURL, nil)
			req.Header.Set("X-Cerberus-Key", "k-test-open")
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			_ = resp.Body.Close()
		}
	})
}
