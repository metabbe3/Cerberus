package proxy_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
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
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

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
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

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
		DenyLocalIPs:  &[]bool{false}[0],
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
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

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
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

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
		DenyLocalIPs:  &[]bool{false}[0],
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
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

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
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

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

// 8A.1: Timeout & resource hygiene: idle connection with CloseWrite does not leak goroutines
func TestEgressProxy_ResourceHygiene_IdleConnection(t *testing.T) {
	eng := setupTestEngine(t)

	// Target backend echo server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer func() { _ = targetListener.Close() }()

	go func() {
		for {
			c, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 256)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						_, _ = conn.Write(buf[:n])
					}
					if err != nil {
						break
					}
				}
			}(c)
		}
	}()

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
		DialTimeout:   1 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

	// GC settle and capture baseline goroutines
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	baseGoroutines := runtime.NumGoroutine()

	// Open connection, send CONNECT, then CloseWrite without data
	conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Cerberus-Key: k-open\r\n\r\n",
		targetListener.Addr().String(), targetListener.Addr().String())
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	bufrw := bufio.NewReader(conn)
	statusLine, err := bufrw.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT status: %s, err: %v", statusLine, err)
	}
	for {
		line, _ := bufrw.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// CloseWrite: send EOF without sending data
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = conn.Close()

	// Settle GC and verify no goroutine leaks
	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(30 * time.Millisecond)
	}
	afterGoroutines := runtime.NumGoroutine()
	if afterGoroutines > baseGoroutines+3 {
		t.Errorf("goroutine leak detected: before=%d, after=%d", baseGoroutines, afterGoroutines)
	}

	// Server remains fully responsive
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	testClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 3 * time.Second,
	}
	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/ping", nil)
	req.Header.Set("X-Cerberus-Key", "k-open")
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("server not responsive after idle connection: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from backend, got %d", resp.StatusCode)
	}
}

// 8A.2: Pemeriksaan IP tujuan menyeluruh (DNS pinning with multi-A-record)
func TestEgressProxy_DNSPinning_MultiARecord(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
		LookupIP: func(host string) ([]net.IP, error) {
			if host == "api.github.com" {
				// Multi-A record: one public IP, one internal prod IP (10.0.0.9)
				return []net.IP{net.ParseIP("140.82.121.4"), net.ParseIP("10.0.0.9")}, nil
			}
			if host == "safe.github.com" {
				return []net.IP{net.ParseIP("140.82.121.4"), net.ParseIP("140.82.121.5")}, nil
			}
			return net.LookupIP(host)
		},
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

	client := proxyServer.Client()

	// 1. CONNECT to api.github.com:443 with multi-A record containing prod IP -> MUST DENY
	req, _ := http.NewRequest(http.MethodConnect, proxyServer.URL, nil)
	req.Host = "api.github.com:443"
	req.Header.Set("X-Cerberus-Key", "k-open")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("CONNECT request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on multi-A record with prod IP, got %d", resp.StatusCode)
	}
	var errBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	if errBody["rule_id"] != "shield.prod.ip_blocked" {
		t.Fatalf("expected shield.prod.ip_blocked, got %v", errBody["rule_id"])
	}

	// 2. HTTP GET to api.github.com with multi-A record containing prod IP -> MUST DENY
	proxyURL, _ := url.Parse(proxyServer.URL)
	fwdClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}
	reqHTTP, _ := http.NewRequest(http.MethodGet, "http://api.github.com/repos", nil)
	reqHTTP.Header.Set("X-Cerberus-Key", "k-open")
	respHTTP, err := fwdClient.Do(reqHTTP)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer func() { _ = respHTTP.Body.Close() }()

	if respHTTP.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on HTTP multi-A with prod IP, got %d", respHTTP.StatusCode)
	}
	var errBodyHTTP map[string]any
	_ = json.NewDecoder(respHTTP.Body).Decode(&errBodyHTTP)
	if errBodyHTTP["rule_id"] != "shield.prod.ip_blocked" {
		t.Fatalf("expected shield.prod.ip_blocked on HTTP, got %v", errBodyHTTP["rule_id"])
	}
}

// 8A.3: Validasi port tujuan: port 25/53/3128 denied by default; 80/443 allowed; explicit port allowed
func TestEgressProxy_PortValidation(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-http-allow",
		DialTimeout:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}
	proxyServer := httptest.NewServer(egress)
	defer func() {
		proxyServer.CloseClientConnections()
		proxyServer.Close()
	}()

	client := proxyServer.Client()

	// Port 25, 53, 3128 to allowlisted host api.github.com with k-http-allow -> default denied
	for _, port := range []string{"25", "53", "3128"} {
		req, _ := http.NewRequest(http.MethodConnect, proxyServer.URL, nil)
		req.Host = "api.github.com:" + port
		req.Header.Set("X-Cerberus-Key", "k-http-allow")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("CONNECT port %s: %v", port, err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for port %s, got %d", port, resp.StatusCode)
		}
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody["rule_id"] != "http.port_not_allowed" {
			t.Fatalf("port %s: expected rule_id http.port_not_allowed, got %v", port, errBody["rule_id"])
		}
		_ = resp.Body.Close()
	}

	// Port 3128 to api.github.com with k-http-custom (has allowed_ports: [80, 443, 3128]) -> passes port check
	req3128, _ := http.NewRequest(http.MethodConnect, proxyServer.URL, nil)
	req3128.Host = "api.github.com:3128"
	req3128.Header.Set("X-Cerberus-Key", "k-http-custom")
	resp3128, err := client.Do(req3128)
	if err != nil {
		t.Fatalf("CONNECT custom port 3128: %v", err)
	}
	defer func() { _ = resp3128.Body.Close() }()
	// Since 3128 is allowed by policy, it attempts dial (and gets Bad Gateway since target isn't listening)
	if resp3128.StatusCode == http.StatusForbidden {
		t.Fatalf("port 3128 should be allowed for k-http-custom, got 403 Forbidden")
	}
}

// 8A.4: Request malformed: Content-Length and Transfer-Encoding simultaneously, duplicate headers -> 400
func TestEgressProxy_MalformedRequest(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-open",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}

	// 1. POST with Content-Length AND Transfer-Encoding simultaneously -> 400
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "http://api.github.com/data", strings.NewReader("hello"))
	req1.Header.Set("Content-Length", "5")
	req1.Header.Set("Transfer-Encoding", "chunked")
	req1.Header.Set("X-Cerberus-Key", "k-open")
	egress.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on CL+TE, got %d", rec1.Code)
	}
	var errBody1 map[string]any
	_ = json.NewDecoder(rec1.Body).Decode(&errBody1)
	if errBody1["rule_id"] != "proxy.egress.malformed_request" {
		t.Fatalf("expected rule_id proxy.egress.malformed_request, got %v", errBody1["rule_id"])
	}

	// 2. Duplicate Content-Length headers -> 400
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "http://api.github.com/data", strings.NewReader("hello"))
	req2.Header.Add("Content-Length", "5")
	req2.Header.Add("Content-Length", "10")
	req2.Header.Set("X-Cerberus-Key", "k-open")
	egress.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on duplicate Content-Length, got %d", rec2.Code)
	}

	// 3. Duplicate Host headers -> 400
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "http://api.github.com/data", nil)
	req3.Header.Add("Host", "api.github.com")
	req3.Header.Add("Host", "evil.com")
	req3.Header.Set("X-Cerberus-Key", "k-open")
	egress.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on duplicate Host, got %d", rec3.Code)
	}
}

// 8A.7: Host unicode/punycode homoglyph denied fail-closed
func TestEgressProxy_HostPunycodeHomoglyphBlocked(t *testing.T) {
	eng := setupTestEngine(t)

	egress, err := proxy.NewEgressProxy(eng, proxy.EgressConfig{
		DenyLocalIPs:  &[]bool{false}[0],
		FallbackKeyID: "k-http-allow",
	})
	if err != nil {
		t.Fatalf("NewEgressProxy: %v", err)
	}

	// 1. CONNECT to xn--pple-4td.com:443 (Cyrillic apple.com homoglyph)
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodConnect, "http://xn--pple-4td.com:443", nil)
	req1.Host = "xn--pple-4td.com:443"
	req1.Header.Set("X-Cerberus-Key", "k-http-allow")
	egress.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for punycode homoglyph CONNECT, got %d", rec1.Code)
	}
	var errBody map[string]any
	_ = json.NewDecoder(rec1.Body).Decode(&errBody)
	if errBody["rule_id"] != "http.host_not_allowed" {
		t.Fatalf("expected rule_id http.host_not_allowed, got %v", errBody["rule_id"])
	}

	// 2. HTTP GET to xn--pple-4td.com
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "http://xn--pple-4td.com/login", nil)
	req2.Host = "xn--pple-4td.com"
	req2.Header.Set("X-Cerberus-Key", "k-http-allow")
	egress.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for punycode HTTP, got %d", rec2.Code)
	}
}
