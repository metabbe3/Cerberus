package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type AttackResult struct {
	Attack string `json:"attack"`
	Result string `json:"result"` // "blocked" | "warn" | "exposed"
	Detail string `json:"detail"`
}

func main() {
	engineURL := flag.String("engine-url", "http://127.0.0.1:8089", "Cerberus engine base URL")
	egressAddr := flag.String("egress-addr", "127.0.0.1:8088", "Cerberus egress proxy host:port")
	dockerProxy := flag.String("docker-proxy", "127.0.0.1:2377", "Cerberus Docker proxy host:port")
	adminToken := flag.String("admin-token", "", "Cerberus admin bearer token")
	dockerSock := flag.String("docker-sock", "/var/run/docker.sock", "Original Docker unix socket path")
	flag.Parse()

	tok := *adminToken
	if tok == "" {
		tok = os.Getenv("CERBERUS_ADMIN_TOKEN")
	}
	if tok == "" {
		// Try reading /tmp/owl_deploy.env
		if b, err := os.ReadFile("/tmp/owl_deploy.env"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "CERBERUS_ADMIN_TOKEN=") {
					tok = strings.TrimSpace(strings.TrimPrefix(line, "CERBERUS_ADMIN_TOKEN="))
					break
				}
			}
		}
	}
	if tok == "" {
		tok = "IQk1EHpteAAdgxrEcbBsPUC6ZM2uGTxjQtkChlLR"
	}

	macSock := "/Users/nicholasandriansurjadi/.docker/run/docker.sock"
	if _, err := os.Stat(macSock); err == nil {
		*dockerSock = macSock
	}

	attacks := []struct {
		name string
		fn   func() AttackResult
	}{
		{"docker_direct_socket_bypass", func() AttackResult { return testDockerSocketBypass(*dockerSock) }},
		{"egress_host_header_spoof", func() AttackResult { return testEgressHostHeaderSpoof(*egressAddr) }},
		{"egress_raw_ip_connect", func() AttackResult { return testEgressRawIPConnect(*egressAddr) }},
		{"egress_no_proxy_stripping", func() AttackResult { return testEgressNoProxyStripping(*egressAddr) }},
		{"decide_bypass_key_spoof", func() AttackResult { return testDecideKeySpoof(*engineURL, tok) }},
		{"rate_limit_bypass_burst", func() AttackResult { return testRateLimitBurst(*engineURL) }},
		{"kill_switch_honor", func() AttackResult { return testKillSwitch(*engineURL, tok) }},
		{"audit_tamper_permissions", func() AttackResult { return testAuditTamper() }},
		{"auth_missing_admin_endpoints", func() AttackResult { return testAuthMissing(*engineURL) }},
		{"fuzz_regress_half_requests", func() AttackResult { return testFuzzHalfRequests(*engineURL, *egressAddr, *dockerProxy) }},
	}

	var results []AttackResult
	var exposedCount, blockedCount, warnCount int

	for _, a := range attacks {
		res := a.fn()
		results = append(results, res)
		switch res.Result {
		case "exposed":
			exposedCount++
		case "warn":
			warnCount++
		case "blocked":
			blockedCount++
		}

		b, _ := json.Marshal(res)
		fmt.Println(string(b))
	}

	fmt.Println("\n--- CERBERUS RED TEAM AUDIT SUMMARY ---")
	fmt.Printf("Total attacks: %d\n", len(results))
	fmt.Printf("Blocked:       %d\n", blockedCount)
	fmt.Printf("Warn:          %d\n", warnCount)
	fmt.Printf("Exposed:       %d\n", exposedCount)
	if exposedCount > 0 {
		fmt.Printf("OVERALL: FAIL (%d attacks bypassed/exposed)\n", exposedCount)
	} else {
		fmt.Println("OVERALL: PASS (0 bypasses detected)")
	}

	os.Exit(exposedCount)
}

// 1. Docker direct-socket bypass: detect direct unix socket accessibility
func testDockerSocketBypass(sockPath string) AttackResult {
	conn, err := net.DialTimeout("unix", sockPath, 1*time.Second)
	if err != nil {
		return AttackResult{
			Attack: "docker_direct_socket_bypass",
			Result: "blocked",
			Detail: "socket asli TIDAK reachable dari konteks non-root (" + err.Error() + ")",
		}
	}
	_ = conn.Close()
	return AttackResult{
		Attack: "docker_direct_socket_bypass",
		Result: "warn",
		Detail: "socket asli masih bisa diakses user → enforcement Docker = advisory di mesin ini kecuali socket dipindah/chmod",
	}
}

// 2. Egress host-header spoof: CONNECT to allowlisted host BUT Host header/SNI changed to internal host
func testEgressHostHeaderSpoof(egressAddr string) AttackResult {
	// Attack 2A: Plain HTTP request with Host header set to internal prod IP (10.0.0.1)
	conn, err := net.DialTimeout("tcp", egressAddr, 2*time.Second)
	if err != nil {
		return AttackResult{
			Attack: "egress_host_header_spoof",
			Result: "exposed",
			Detail: "failed to connect to egress proxy: " + err.Error(),
		}
	}
	defer func() { _ = conn.Close() }()

	rawReq := "GET http://api.openai.com/v1/models HTTP/1.1\r\nHost: 10.0.0.1\r\nX-Cerberus-Key: k-open\r\n\r\n"
	if _, err := conn.Write([]byte(rawReq)); err != nil {
		return AttackResult{Attack: "egress_host_header_spoof", Result: "exposed", Detail: "write failed: " + err.Error()}
	}

	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadString('\n')
	if err != nil {
		return AttackResult{Attack: "egress_host_header_spoof", Result: "exposed", Detail: "read failed: " + err.Error()}
	}
	if !strings.Contains(respLine, "403") {
		return AttackResult{
			Attack: "egress_host_header_spoof",
			Result: "exposed",
			Detail: fmt.Sprintf("expected 403 on Host header spoof to 10.0.0.1, got: %s", strings.TrimSpace(respLine)),
		}
	}

	// Attack 2B: CONNECT request to prod IP
	conn2, err := net.DialTimeout("tcp", egressAddr, 2*time.Second)
	if err != nil {
		return AttackResult{Attack: "egress_host_header_spoof", Result: "exposed", Detail: "dial 2 failed: " + err.Error()}
	}
	defer func() { _ = conn2.Close() }()

	rawReq2 := "CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nX-Cerberus-Key: k-open\r\n\r\n"
	if _, err := conn2.Write([]byte(rawReq2)); err != nil {
		return AttackResult{Attack: "egress_host_header_spoof", Result: "exposed", Detail: "write 2 failed: " + err.Error()}
	}
	reader2 := bufio.NewReader(conn2)
	respLine2, err := reader2.ReadString('\n')
	if err != nil {
		return AttackResult{Attack: "egress_host_header_spoof", Result: "exposed", Detail: "read 2 failed: " + err.Error()}
	}
	if !strings.Contains(respLine2, "403") {
		return AttackResult{
			Attack: "egress_host_header_spoof",
			Result: "exposed",
			Detail: fmt.Sprintf("expected 403 on CONNECT spoof to 10.0.0.1, got: %s", strings.TrimSpace(respLine2)),
		}
	}

	return AttackResult{
		Attack: "egress_host_header_spoof",
		Result: "blocked",
		Detail: "host-header spoof requests blocked with 403 (prod shield enforced)",
	}
}

// 3. Egress raw-IP CONNECT: CONNECT directly to prod IP without hostname -> 403
func testEgressRawIPConnect(egressAddr string) AttackResult {
	conn, err := net.DialTimeout("tcp", egressAddr, 2*time.Second)
	if err != nil {
		return AttackResult{Attack: "egress_raw_ip_connect", Result: "exposed", Detail: "dial failed: " + err.Error()}
	}
	defer func() { _ = conn.Close() }()

	req := "CONNECT 10.0.3.7:443 HTTP/1.1\r\nHost: 10.0.3.7:443\r\nX-Cerberus-Key: k-open\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return AttackResult{Attack: "egress_raw_ip_connect", Result: "exposed", Detail: "write failed: " + err.Error()}
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return AttackResult{Attack: "egress_raw_ip_connect", Result: "exposed", Detail: "read failed: " + err.Error()}
	}

	if strings.Contains(line, "403") {
		return AttackResult{
			Attack: "egress_raw_ip_connect",
			Result: "blocked",
			Detail: "CONNECT 10.0.3.7:443 blocked with 403 (shield.prod.ip_blocked)",
		}
	}
	return AttackResult{
		Attack: "egress_raw_ip_connect",
		Result: "exposed",
		Detail: fmt.Sprintf("raw IP CONNECT not blocked: %s", strings.TrimSpace(line)),
	}
}

// 4. Egress NO_PROXY stripping: weird Proxy-Connection/absolute-URI headers still evaluated
func testEgressNoProxyStripping(egressAddr string) AttackResult {
	conn, err := net.DialTimeout("tcp", egressAddr, 2*time.Second)
	if err != nil {
		return AttackResult{Attack: "egress_no_proxy_stripping", Result: "exposed", Detail: "dial failed: " + err.Error()}
	}
	defer func() { _ = conn.Close() }()

	req := "GET http://10.0.3.7/api HTTP/1.1\r\nHost: 10.0.3.7\r\nProxy-Connection: keep-alive\r\nX-Cerberus-Key: k-open\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return AttackResult{Attack: "egress_no_proxy_stripping", Result: "exposed", Detail: "write failed: " + err.Error()}
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return AttackResult{Attack: "egress_no_proxy_stripping", Result: "exposed", Detail: "read failed: " + err.Error()}
	}

	if strings.Contains(line, "403") {
		return AttackResult{
			Attack: "egress_no_proxy_stripping",
			Result: "blocked",
			Detail: "Proxy-Connection/absolute-URI request evaluated and blocked with 403; no parser bypass",
		}
	}
	return AttackResult{
		Attack: "egress_no_proxy_stripping",
		Result: "exposed",
		Detail: fmt.Sprintf("request with Proxy-Connection was not blocked: %s", strings.TrimSpace(line)),
	}
}

// 5. Decide bypass via key spoof: POST /v1/decide with k-owner without admin token -> 401
func testDecideKeySpoof(engineURL, adminToken string) AttackResult {
	client := &http.Client{Timeout: 3 * time.Second}
	body := `{"stage":"tool","key_id":"k-owner","tool_call":"bash","args":{"cmd":"whoami"}}`

	// 5A: unauthenticated request
	req, _ := http.NewRequest(http.MethodPost, engineURL+"/v1/decide", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return AttackResult{Attack: "decide_bypass_key_spoof", Result: "exposed", Detail: "do failed: " + err.Error()}
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return AttackResult{
			Attack: "decide_bypass_key_spoof",
			Result: "exposed",
			Detail: fmt.Sprintf("unauthenticated k-owner decide returned %d, want 401", resp.StatusCode),
		}
	}

	// 5B: request with junk token
	reqJunk, _ := http.NewRequest(http.MethodPost, engineURL+"/v1/decide", strings.NewReader(body))
	reqJunk.Header.Set("Content-Type", "application/json")
	reqJunk.Header.Set("Authorization", "Bearer junk-token-12345")
	respJunk, err := client.Do(reqJunk)
	if err != nil {
		return AttackResult{Attack: "decide_bypass_key_spoof", Result: "exposed", Detail: "do junk failed: " + err.Error()}
	}
	_ = respJunk.Body.Close()

	if respJunk.StatusCode != http.StatusUnauthorized {
		return AttackResult{
			Attack: "decide_bypass_key_spoof",
			Result: "exposed",
			Detail: fmt.Sprintf("junk-token k-owner decide returned %d, want 401", respJunk.StatusCode),
		}
	}

	return AttackResult{
		Attack: "decide_bypass_key_spoof",
		Result: "blocked",
		Detail: "POST /v1/decide with k-owner without valid admin token rejected with 401",
	}
}

// 6. Rate limit bypass: burst: 50 requests < 1s with rate-limited key -> some must be 429
func testRateLimitBurst(engineURL string) AttackResult {
	client := &http.Client{Timeout: 2 * time.Second}
	body := `{"stage":"tool","key_id":"k-rate-limited","tool_call":"read","args":{}}`

	var count200, count429 atomic.Int64
	var wg sync.WaitGroup
	totalReqs := 50

	start := time.Now()
	for i := 0; i < totalReqs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, engineURL+"/v1/decide", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				count200.Add(1)
			} else if resp.StatusCode == http.StatusTooManyRequests {
				count429.Add(1)
			}
		}()
	}
	wg.Wait()
	duration := time.Since(start)

	n200 := count200.Load()
	n429 := count429.Load()

	if n429 == 0 {
		return AttackResult{
			Attack: "rate_limit_bypass_burst",
			Result: "exposed",
			Detail: fmt.Sprintf("all %d requests passed in %v without any 429", n200, duration),
		}
	}

	return AttackResult{
		Attack: "rate_limit_bypass_burst",
		Result: "blocked",
		Detail: fmt.Sprintf("burst rate limit held: %d allowed, %d blocked (429) across 50 reqs in %v", n200, n429, duration),
	}
}

// 7. Kill switch honor: set kill switch on -> all decide deny; set off -> normal restored
func testKillSwitch(engineURL, adminToken string) AttackResult {
	client := &http.Client{Timeout: 5 * time.Second}
	decideBody := `{"stage":"tool","key_id":"k-open","tool_call":"read","args":{}}`

	// 1. Initial check
	req1, _ := http.NewRequest(http.MethodPost, engineURL+"/v1/decide", strings.NewReader(decideBody))
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := client.Do(req1)
	if err != nil {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: "initial decide failed: " + err.Error()}
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: fmt.Sprintf("initial decide returned %d", resp1.StatusCode)}
	}

	// 2. Fetch current config data
	getReq, _ := http.NewRequest(http.MethodGet, engineURL+"/v1/admin/data", nil)
	getReq.Header.Set("Authorization", "Bearer "+adminToken)
	getResp, err := client.Do(getReq)
	if err != nil {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: "get data failed: " + err.Error()}
	}
	defer func() { _ = getResp.Body.Close() }()

	var doc map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&doc); err != nil {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: "decode data failed: " + err.Error()}
	}

	cfg, _ := doc["config"].(map[string]any)
	if cfg == nil {
		cfg = make(map[string]any)
		doc["config"] = cfg
	}
	ks, _ := cfg["kill_switch"].(map[string]any)
	if ks == nil {
		ks = make(map[string]any)
		cfg["kill_switch"] = ks
	}

	// Function to update config
	putDoc := func(globalKill bool) error {
		ks["global"] = globalKill
		payload, _ := json.Marshal(doc)
		putReq, _ := http.NewRequest(http.MethodPut, engineURL+"/v1/admin/data", bytes.NewReader(payload))
		putReq.Header.Set("Content-Type", "application/json")
		putReq.Header.Set("Authorization", "Bearer "+adminToken)
		putReq.Header.Set("X-Audit-Author", "cerberus-redteam")
		putReq.Header.Set("X-Audit-Summary", fmt.Sprintf("kill switch test global=%v", globalKill))
		putResp, err := client.Do(putReq)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(putResp.Body)
		_ = putResp.Body.Close()
		if putResp.StatusCode != http.StatusOK {
			return fmt.Errorf("put data returned %d: %s", putResp.StatusCode, string(b))
		}
		return nil
	}

	// Ensure cleanup restores global=false
	defer func() {
		_ = putDoc(false)
	}()

	// 3. Set kill switch on
	if err := putDoc(true); err != nil {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: "enable kill switch failed: " + err.Error()}
	}

	// 4. Test decide under kill switch -> must deny ops.kill_switch
	reqKs, _ := http.NewRequest(http.MethodPost, engineURL+"/v1/decide", strings.NewReader(decideBody))
	reqKs.Header.Set("Content-Type", "application/json")
	respKs, err := client.Do(reqKs)
	if err != nil {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: "decide under kill switch failed: " + err.Error()}
	}
	defer func() { _ = respKs.Body.Close() }()

	var decKS struct {
		Decision string `json:"decision"`
		RuleID   string `json:"rule_id"`
	}
	_ = json.NewDecoder(respKs.Body).Decode(&decKS)
	if decKS.Decision != "deny" || decKS.RuleID != "ops.kill_switch" {
		return AttackResult{
			Attack: "kill_switch_honor",
			Result: "exposed",
			Detail: fmt.Sprintf("kill switch active but decide was %s/%s (expected deny/ops.kill_switch)", decKS.Decision, decKS.RuleID),
		}
	}

	// 5. Turn kill switch off
	if err := putDoc(false); err != nil {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: "restore kill switch failed: " + err.Error()}
	}

	// 6. Test decide restored -> must allow
	reqRestored, _ := http.NewRequest(http.MethodPost, engineURL+"/v1/decide", strings.NewReader(decideBody))
	reqRestored.Header.Set("Content-Type", "application/json")
	respRestored, err := client.Do(reqRestored)
	if err != nil {
		return AttackResult{Attack: "kill_switch_honor", Result: "exposed", Detail: "restored decide failed: " + err.Error()}
	}
	defer func() { _ = respRestored.Body.Close() }()

	var decRestored struct {
		Decision string `json:"decision"`
	}
	_ = json.NewDecoder(respRestored.Body).Decode(&decRestored)
	if decRestored.Decision != "allow" {
		return AttackResult{
			Attack: "kill_switch_honor",
			Result: "exposed",
			Detail: fmt.Sprintf("restored decide returned %s, want allow", decRestored.Decision),
		}
	}

	return AttackResult{
		Attack: "kill_switch_honor",
		Result: "blocked",
		Detail: "kill switch honored (deny/ops.kill_switch when active, restored to allow on reset)",
	}
}

// 8. Audit tamper: audit db file must be 0640/0600 (not 0644)
func testAuditTamper() AttackResult {
	matches, err := filepath.Glob("/tmp/audit*.db")
	if err != nil || len(matches) == 0 {
		matches, _ = filepath.Glob("/tmp/cerberus*.db")
	}

	if len(matches) == 0 {
		return AttackResult{
			Attack: "audit_tamper_permissions",
			Result: "warn",
			Detail: "no audit db files found in /tmp to inspect",
		}
	}

	var insecureFiles []string
	for _, f := range matches {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&0o007 != 0 {
			insecureFiles = append(insecureFiles, fmt.Sprintf("%s (%04o)", filepath.Base(f), perm))
		}
	}

	if len(insecureFiles) > 0 {
		return AttackResult{
			Attack: "audit_tamper_permissions",
			Result: "warn",
			Detail: "insecure world-readable audit files: " + strings.Join(insecureFiles, ", ") + " (requires deploy/harden-macmini.sh --apply)",
		}
	}

	return AttackResult{
		Attack: "audit_tamper_permissions",
		Result: "blocked",
		Detail: "audit files are 0640/0600; world-read/write restricted",
	}
}

// 9. Auth missing: all admin endpoints without token -> 401; with junk token -> 401
func testAuthMissing(engineURL string) AttackResult {
	client := &http.Client{Timeout: 3 * time.Second}
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/admin/data"},
		{http.MethodPut, "/v1/admin/data"},
		{http.MethodPost, "/v1/admin/reload"},
		{http.MethodPost, "/v1/admin/policy/validate"},
		{http.MethodPost, "/v1/admin/regex/test"},
		{http.MethodGet, "/v1/admin/revisions"},
		{http.MethodPost, "/v1/admin/rollback"},
		{http.MethodPost, "/v1/admin/explain"},
		{http.MethodPost, "/v1/admin/replay"},
		{http.MethodGet, "/v1/admin/coverage"},
		{http.MethodGet, "/v1/audit"},
		{http.MethodGet, "/v1/events"},
		{http.MethodGet, "/v1/admin/status"},
		{http.MethodPost, "/v1/admin/bundle"},
		{http.MethodGet, "/v1/admin/bundle"},
		{http.MethodPost, "/v1/admin/break-glass"},
		{http.MethodGet, "/v1/admin/break-glass"},
		{http.MethodDelete, "/v1/admin/break-glass"},
	}

	var failed []string
	for _, ep := range endpoints {
		// Test 1: no token
		req, _ := http.NewRequest(ep.method, engineURL+ep.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			failed = append(failed, ep.method+" "+ep.path+" (dial err)")
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			failed = append(failed, fmt.Sprintf("%s %s (no auth: %d)", ep.method, ep.path, resp.StatusCode))
		}

		// Test 2: junk token
		reqJunk, _ := http.NewRequest(ep.method, engineURL+ep.path, strings.NewReader("{}"))
		reqJunk.Header.Set("Content-Type", "application/json")
		reqJunk.Header.Set("Authorization", "Bearer invalid-junk-token")
		respJunk, err := client.Do(reqJunk)
		if err != nil {
			failed = append(failed, ep.method+" "+ep.path+" (dial junk err)")
			continue
		}
		_ = respJunk.Body.Close()
		if respJunk.StatusCode != http.StatusUnauthorized {
			failed = append(failed, fmt.Sprintf("%s %s (junk auth: %d)", ep.method, ep.path, respJunk.StatusCode))
		}
	}

	if len(failed) > 0 {
		return AttackResult{
			Attack: "auth_missing_admin_endpoints",
			Result: "exposed",
			Detail: "endpoints failed 401 requirement: " + strings.Join(failed, ", "),
		}
	}

	return AttackResult{
		Attack: "auth_missing_admin_endpoints",
		Result: "blocked",
		Detail: fmt.Sprintf("all %d admin endpoints verified: 401 on missing auth and junk token", len(endpoints)),
	}
}

// 10. Fuzz regress: half-requests: CONNECT without host, request line 2MB, header count 500 -> 4xx/431, NO crash
func testFuzzHalfRequests(engineURL, egressAddr, dockerProxy string) AttackResult {
	// 10A: CONNECT without host on egress proxy
	conn1, err := net.DialTimeout("tcp", egressAddr, 2*time.Second)
	if err == nil {
		_, _ = conn1.Write([]byte("CONNECT  HTTP/1.1\r\n\r\n"))
		_ = conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn1)
		_, _ = reader.ReadString('\n')
		_ = conn1.Close()
	}

	// 10B: 2MB request line to engine
	conn2, err := net.DialTimeout("tcp", strings.TrimPrefix(engineURL, "http://"), 2*time.Second)
	if err == nil {
		huge := "GET /" + strings.Repeat("A", 2*1024*1024) + " HTTP/1.1\r\nHost: localhost\r\n\r\n"
		_, _ = conn2.Write([]byte(huge))
		_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn2)
		_, _ = reader.ReadString('\n')
		_ = conn2.Close()
	}

	// 10C: 500 headers to engine
	conn3, err := net.DialTimeout("tcp", strings.TrimPrefix(engineURL, "http://"), 2*time.Second)
	if err == nil {
		var buf bytes.Buffer
		buf.WriteString("GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
		for i := 0; i < 500; i++ {
			buf.WriteString(fmt.Sprintf("X-Fuzz-Header-%d: %s\r\n", i, strings.Repeat("x", 20)))
		}
		buf.WriteString("\r\n")
		_, _ = conn3.Write(buf.Bytes())
		_ = conn3.SetReadDeadline(time.Now().Add(2 * time.Second))
		reader := bufio.NewReader(conn3)
		_, _ = reader.ReadString('\n')
		_ = conn3.Close()
	}

	// Liveness verification: engine healthz
	client := &http.Client{Timeout: 3 * time.Second}
	hResp, err := client.Get(engineURL + "/healthz")
	if err != nil || hResp.StatusCode != http.StatusOK {
		return AttackResult{
			Attack: "fuzz_regress_half_requests",
			Result: "exposed",
			Detail: "engine did not survive fuzz tests: " + fmt.Sprintf("%v", err),
		}
	}
	_ = hResp.Body.Close()

	// Egress proxy liveness check: connect to egress proxy port
	pConn, err := net.DialTimeout("tcp", egressAddr, 2*time.Second)
	if err != nil {
		return AttackResult{
			Attack: "fuzz_regress_half_requests",
			Result: "exposed",
			Detail: "egress proxy did not survive fuzz tests: " + err.Error(),
		}
	}
	_ = pConn.Close()

	return AttackResult{
		Attack: "fuzz_regress_half_requests",
		Result: "blocked",
		Detail: "fuzz regress test passed: proxy & engine survived half-requests, 2MB lines, 500 headers (remained alive and healthy)",
	}
}
