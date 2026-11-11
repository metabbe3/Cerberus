package proxy_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/proxy"
	"github.com/metabbe3/cerberus/internal/ratelimit"
)

func TestEgressProxy_HTTPForward(t *testing.T) {
	eng := setupTestEngine(t)

	// Target backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// 1. Normal HTTP request -> allowed
	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/api/v1/resource", nil)
	req.Header.Set("X-Cerberus-Key", "k-open")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestEgressProxy_ProdShieldIPBlocked(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer proxyServer.Close()

	client := proxyServer.Client()

	// 1. CONNECT to 10.0.0.5:443 (which is in prod_shield.cidrs "10.0.0.0/8")
	// Agent k-open does NOT have prod_access
	req, _ := http.NewRequest(http.MethodConnect, proxyServer.URL, nil)
	req.Host = "10.0.0.5:443"
	req.Header.Set("X-Cerberus-Key", "k-open")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("CONNECT request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
	var errBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode err body: %v", err)
	}
	if errBody["rule_id"] != "shield.prod.ip_blocked" {
		t.Fatalf("expected rule_id shield.prod.ip_blocked, got %v", errBody["rule_id"])
	}

	// 2. CONNECT to prod-db.internal:443 (touches host_keyword / db_keyword "prod")
	req, _ = http.NewRequest(http.MethodConnect, proxyServer.URL, nil)
	req.Host = "prod-db.internal:443"
	req.Header.Set("X-Cerberus-Key", "k-open")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("CONNECT request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
	var errBodyHost map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&errBodyHost); err != nil {
		t.Fatalf("decode err body: %v", err)
	}
	if errBodyHost["rule_id"] != "shield.prod.no_access" {
		t.Fatalf("expected rule_id shield.prod.no_access, got %v", errBodyHost["rule_id"])
	}
}

func TestEgressProxy_DNSResolveToProdIPBlocked(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		FallbackKeyID: "k-open",
		LookupIP: func(host string) ([]net.IP, error) {
			if host == "sneaky-external.com" {
				// Resolves to an internal prod IP (10.1.2.3)
				return []net.IP{net.ParseIP("10.1.2.3")}, nil
			}
			return net.LookupIP(host)
		},
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer proxyServer.Close()

	client := proxyServer.Client()

	req, _ := http.NewRequest(http.MethodConnect, proxyServer.URL, nil)
	req.Host = "sneaky-external.com:443"
	req.Header.Set("X-Cerberus-Key", "k-open")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("CONNECT request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
	var errBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode err body: %v", err)
	}
	if errBody["rule_id"] != "shield.prod.ip_blocked" {
		t.Fatalf("expected rule_id shield.prod.ip_blocked, got %v", errBody["rule_id"])
	}
}

func TestEgressProxy_ConnectTunnelSuccess(t *testing.T) {
	eng := setupTestEngine(t)

	// Target TCP server simulating external service
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer func() { _ = targetListener.Close() }()

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write(append([]byte("tunnel:"), buf[:n]...))
				}
			}(conn)
		}
	}()

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	connectReq := "CONNECT " + targetListener.Addr().String() + " HTTP/1.1\r\n" +
		"Host: " + targetListener.Addr().String() + "\r\n" +
		"X-Cerberus-Key: k-open\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	bufrw := bufio.NewReader(conn)
	statusLine, err := bufrw.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 Connection Established, got: %s", statusLine)
	}

	// Consume headers until newline
	for {
		line, _ := bufrw.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Send message through tunnel
	msg := "ping-tunnel\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write to tunnel: %v", err)
	}

	resp, err := bufrw.ReadString('\n')
	if err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	if !strings.Contains(resp, "tunnel:ping-tunnel") {
		t.Fatalf("expected tunnel:ping-tunnel, got %q", resp)
	}
}

func TestEgressProxy_FailClosedWhenUnreachable(t *testing.T) {
	// A client configured with an unreachable proxy MUST fail (fail-closed, no silent direct bypass)
	dummyProxyURL, _ := url.Parse("http://127.0.0.1:54321") // closed port
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(dummyProxyURL),
		},
		Timeout: 500 * time.Millisecond,
	}

	_, err := client.Get("http://example.com/foo")
	if err == nil {
		t.Fatal("expected request through unreachable proxy to fail, but succeeded")
	}
}

func TestEgressProxy_RateLimit(t *testing.T) {
	eng, store := setupTestEngineWithStore(t)
	lim := ratelimit.NewLimiter(store, nil)
	ep, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		FallbackKeyID: "k-rate-limited",
		Limiter:       lim,
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}

	proxySrv := httptest.NewServer(ep)
	defer proxySrv.Close()

	pURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pURL),
		},
	}

	// k-rate-limited has bursts: 2
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://api.internal.corp/data", nil)
		req.Header.Set("X-Cerberus-Key", "k-rate-limited")
		resp, _ := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
	}

	// 3rd request should hit 429
	req, _ := http.NewRequest(http.MethodGet, "http://api.internal.corp/data", nil)
	req.Header.Set("X-Cerberus-Key", "k-rate-limited")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header")
	}
}

func TestEgressProxy_HostHeaderSpoofBlocked(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer proxyServer.Close()

	// 1. Plain HTTP request to external URL with Host header spoofed to internal prod IP (10.0.0.1)
	conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	rawReq := "GET http://api.openai.com/v1/models HTTP/1.1\r\nHost: 10.0.0.1\r\nX-Cerberus-Key: k-open\r\n\r\n"
	if _, err := conn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write rawReq: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "403") {
		t.Fatalf("expected 403 Forbidden on host-header spoof, got: %s", statusLine)
	}

	// 2. CONNECT to 10.0.0.1:443
	conn2, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	rawReq2 := "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\nX-Cerberus-Key: k-open\r\n\r\n"
	if _, err := conn2.Write([]byte(rawReq2)); err != nil {
		t.Fatalf("write rawReq2: %v", err)
	}

	reader2 := bufio.NewReader(conn2)
	statusLine2, err := reader2.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line 2: %v", err)
	}
	if !strings.Contains(statusLine2, "403") {
		t.Fatalf("expected 403 Forbidden on destination spoof, got: %s", statusLine2)
	}
}

func TestEgressProxy_ConnectMissingHost(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer proxyServer.Close()

	conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	rawReq := "CONNECT  HTTP/1.1\r\n\r\n"
	if _, err := conn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(statusLine, "400") {
		t.Fatalf("expected 400 Bad Request, got: %s", statusLine)
	}
}
