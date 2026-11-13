package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// SPRINT 2C Tests: REST API & admin parity
func TestREST_PoliciesEndpoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// 1. Unauthorized without token -> 401 with structured error {code, message}
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/v1/policies", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/policies: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	var errResp APIError
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Code != "unauthorized" || errResp.Message != "unauthorized" {
		t.Fatalf("expected structured error {code: unauthorized, message: unauthorized}, got %+v", errResp)
	}

	// 2. Happy path with token -> 200 OK, list of modules + revision + hash
	req, _ = http.NewRequest(http.MethodGet, h.ts.URL+"/v1/policies", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/policies: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var res listPoliciesResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode list policies: %v", err)
	}
	if len(res.Result) == 0 {
		t.Fatal("expected at least 1 policy module in result, got 0")
	}

	foundAuthz := false
	for _, m := range res.Result {
		if m.ID == "" || m.Hash == "" {
			t.Fatalf("module ID or Hash empty: %+v", m)
		}
		if len(m.Hash) != 64 { // sha256 hex length
			t.Fatalf("module hash %q invalid sha256 length", m.Hash)
		}
		if strings.Contains(m.ID, "authz.rego") {
			foundAuthz = true
		}
	}
	if !foundAuthz {
		t.Fatal("expected gateway/authz.rego to be in policies list")
	}
}

func TestREST_DataEndpoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// 1. Unauthorized without token -> 401
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/v1/data", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/data: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// 2. Read full data document
	req, _ = http.NewRequest(http.MethodGet, h.ts.URL+"/v1/data", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/data: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var fullData struct {
		Result map[string]any `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fullData); err != nil {
		t.Fatalf("decode full data: %v", err)
	}
	if fullData.Result["config"] == nil || fullData.Result["agents"] == nil {
		t.Fatalf("full data missing expected keys: %v", fullData.Result)
	}

	// 3. Read specific path via ?path=config
	req, _ = http.NewRequest(http.MethodGet, h.ts.URL+"/v1/data?path=config", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/data?path=config: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var configData struct {
		Result map[string]any `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&configData); err != nil {
		t.Fatalf("decode config data: %v", err)
	}
	if configData.Result["bypass_unknown_keys"] == nil {
		t.Fatalf("config data missing bypass_unknown_keys: %v", configData.Result)
	}

	// 4. Path not found -> 404 with structured error
	req, _ = http.NewRequest(http.MethodGet, h.ts.URL+"/v1/data?path=nonexistent.subpath", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET non-existent data: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	var notFoundErr APIError
	_ = json.NewDecoder(resp.Body).Decode(&notFoundErr)
	if notFoundErr.Code != "not_found" {
		t.Fatalf("expected code not_found, got %q", notFoundErr.Code)
	}

	// 5. Masking in response: put data with secret token & email and verify masked
	putDataWithSecret := []byte(`{
		"config": {"bypass_unknown_keys": true, "bypass_unknown_teams": true},
		"teams": {},
		"agents": {
			"k-open": {
				"name": "open-agent",
				"api_token": "sk-supersecret12345",
				"contact_email": "operator@cerberus.internal"
			}
		},
		"blocked_patterns": ["jailbreak"],
		"domains": {},
		"prod_shield": {
			"dangerous_cmd_patterns": [
				{"id": "rm_rf", "regex": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)"},
				{"id": "grep_wildcard_dump", "regex": "grep\\s+[^|]*(\\*|wildcard)[^|]*(/passwd|/etc|\\.env|id_rsa)"}
			],
			"protected_containers": ["teknikalidnew-db-1"]
		}
	}`)
	putReq, _ := http.NewRequest(http.MethodPut, h.ts.URL+"/v1/admin/data", strings.NewReader(string(putDataWithSecret)))
	putReq.Header.Set("Authorization", "Bearer "+adminToken)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT /v1/admin/data: %v", err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT data status = %d, want 200", putResp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, h.ts.URL+"/v1/data?path=agents", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/data?path=agents: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var agentsResp struct {
		Result map[string]any `json:"result"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&agentsResp)
	rawResp, _ := json.Marshal(agentsResp)
	if strings.Contains(string(rawResp), "sk-supersecret12345") {
		t.Fatalf("raw secret leaked in data response: %s", rawResp)
	}
	if !strings.Contains(string(rawResp), "[REDACTED]") {
		t.Fatalf("secret was not redacted in response: %s", rawResp)
	}
}

func TestREST_QueryEndpointAndRateLimiting(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// 1. Unauthorized without token -> 401
	qBody := `{"q": "data.gateway.authz.decision", "input": {"stage": "tool", "key_id": "k-open", "tool_call": "bash", "args": {"cmd": "echo test"}}}`
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/query", strings.NewReader(qBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/query: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// 2. Happy path ad-hoc query
	req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/v1/query", strings.NewReader(qBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/query: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var qResult struct {
		Result any `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&qResult); err != nil {
		t.Fatalf("decode query result: %v", err)
	}
	if qResult.Result == nil {
		t.Fatal("query result is nil")
	}

	// 3. Query compile error -> 422 with structured error
	badQBody := `{"q": "data.syntax error %%%"}`
	req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/v1/query", strings.NewReader(badQBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST bad query: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad query status = %d, want 422", resp.StatusCode)
	}
	var compileErr APIError
	_ = json.NewDecoder(resp.Body).Decode(&compileErr)
	if compileErr.Code != "compile_error" {
		t.Fatalf("expected code compile_error, got %q", compileErr.Code)
	}

	// 4. Rate limiting: 10/min token bucket. On slow/loaded runners the OPA
	// compile per query can take seconds, and the bucket refills at 10/60
	// tokens/sec — so the exact boundary request is timing-dependent. Keep
	// issuing requests until the limiter engages (consumption always outpaces
	// refill), then assert the 429 + error code.
	successes := 0
	var rateLimitedResp *http.Response
	for i := 0; i < 25; i++ {
		req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/v1/query", strings.NewReader(qBody))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("query req %d: %v", i, err)
		}
		if r.StatusCode == http.StatusTooManyRequests {
			rateLimitedResp = r
			break
		}
		if r.StatusCode != http.StatusOK {
			_ = r.Body.Close()
			t.Fatalf("query req %d got status %d, want 200", i, r.StatusCode)
		}
		_ = r.Body.Close()
		successes++
	}
	if rateLimitedResp == nil {
		t.Fatalf("rate limiter never engaged after 25 requests (successes=%d)", successes)
	}
	if successes < 8 {
		t.Fatalf("engaged too early: only %d successes before 429, want >= 8 (limit 10/min)", successes)
	}
	defer func() { _ = rateLimitedResp.Body.Close() }()
	if rateLimitedResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 rate limit exceeded", rateLimitedResp.StatusCode)
	}
	var rateErr APIError
	_ = json.NewDecoder(rateLimitedResp.Body).Decode(&rateErr)
	if rateErr.Code != "rate_limit_exceeded" {
		t.Fatalf("expected code rate_limit_exceeded, got %q", rateErr.Code)
	}
}
