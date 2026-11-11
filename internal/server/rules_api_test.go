package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRegex_TestEndpoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Case 1: valid regex with matching command
	body1 := `{"regex": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f)", "test_string": "rm -rf /tmp/data"}`
	resp1 := h.do(t, http.MethodPost, "/v1/admin/regex/test", "application/json", body1, true)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("regex test 1 status = %d, want 200", resp1.StatusCode)
	}
	res1 := decodeJSON[regexTestResponse](t, resp1.Body)
	if !res1.Valid || !res1.Matches {
		t.Fatalf("res1 = %+v, want valid:true, matches:true", res1)
	}

	// Case 2: valid regex without match
	body2 := `{"regex": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f)", "test_string": "ls -la /tmp"}`
	resp2 := h.do(t, http.MethodPost, "/v1/admin/regex/test", "application/json", body2, true)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("regex test 2 status = %d, want 200", resp2.StatusCode)
	}
	res2 := decodeJSON[regexTestResponse](t, resp2.Body)
	if !res2.Valid || res2.Matches {
		t.Fatalf("res2 = %+v, want valid:true, matches:false", res2)
	}

	// Case 3: invalid regex
	body3 := `{"regex": "[a-z(invalid"}`
	resp3 := h.do(t, http.MethodPost, "/v1/admin/regex/test", "application/json", body3, true)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("regex test 3 status = %d, want 200", resp3.StatusCode)
	}
	res3 := decodeJSON[regexTestResponse](t, resp3.Body)
	if res3.Valid || res3.Error == "" {
		t.Fatalf("res3 = %+v, want valid:false with error", res3)
	}
}

func TestRules_RevisionsAndRollback(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Step 1: Query initial data
	initialSnap := h.store.Current()
	initialEpoch := initialSnap.Epoch

	// Step 2: PUT updated data (adding an agent)
	dataCopy := make(map[string]any)
	for k, v := range initialSnap.Data {
		dataCopy[k] = v
	}
	agents, _ := dataCopy["agents"].(map[string]any)
	agentsCopy := make(map[string]any)
	for ak, av := range agents {
		agentsCopy[ak] = av
	}
	agentsCopy["k-new-test"] = map[string]any{
		"name": "new-test-agent",
	}
	dataCopy["agents"] = agentsCopy
	updatedBytes, _ := json.Marshal(dataCopy)

	putReq, _ := http.NewRequest(http.MethodPut, h.ts.URL+"/v1/admin/data", bytes.NewReader(updatedBytes))
	putReq.Header.Set("Authorization", "Bearer "+adminToken)
	putReq.Header.Set("X-Admin-User", "operator-sprint5")
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT /v1/admin/data: %v", err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /v1/admin/data status = %d, want 200", putResp.StatusCode)
	}

	if h.store.Current().Epoch != initialEpoch+1 {
		t.Fatalf("epoch after put = %d, want %d", h.store.Current().Epoch, initialEpoch+1)
	}

	// Step 3: GET /v1/admin/revisions -> should have 1 revision
	revResp := h.do(t, http.MethodGet, "/v1/admin/revisions", "", "", true)
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/revisions status = %d, want 200", revResp.StatusCode)
	}
	type revItem struct {
		ID      int64  `json:"id"`
		Author  string `json:"author"`
		Summary string `json:"summary"`
	}
	revs := decodeJSON[[]revItem](t, revResp.Body)
	if len(revs) == 0 {
		t.Fatal("expected at least 1 revision, got 0")
	}
	if revs[0].Author != "operator-sprint5" {
		t.Fatalf("revision author = %q, want operator-sprint5", revs[0].Author)
	}
	if !strings.Contains(revs[0].Summary, "agents") {
		t.Fatalf("revision summary = %q, want mention of agents", revs[0].Summary)
	}

	// Step 4: POST /v1/admin/rollback -> restore previous data
	rollbackReq := `{"revision_id": ` + jsonString(t, revs[0].ID) + `}`
	rbResp := h.do(t, http.MethodPost, "/v1/admin/rollback", "application/json", rollbackReq, true)
	if rbResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/admin/rollback status = %d, want 200", rbResp.StatusCode)
	}
	rbOut := decodeJSON[rollbackResponse](t, rbResp.Body)
	if !rbOut.OK || rbOut.Epoch != initialEpoch+2 {
		t.Fatalf("rbOut = %+v, want ok:true, epoch:%d", rbOut, initialEpoch+2)
	}

	// Confirm agent k-new-test is no longer in current store
	currentSnap := h.store.Current()
	currentAgents, _ := currentSnap.Data["agents"].(map[string]any)
	if _, exists := currentAgents["k-new-test"]; exists {
		t.Fatal("agent k-new-test still present after rollback")
	}
}

func TestRules_DryRunSmokeGateRejectsBrokenPolicy(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Step 1: Prepare data that deletes dangerous_cmd_patterns
	initialSnap := h.store.Current()
	brokenData := make(map[string]any)
	for k, v := range initialSnap.Data {
		brokenData[k] = v
	}
	brokenData["prod_shield"] = map[string]any{
		"dangerous_cmd_patterns": []any{},
	}
	brokenBytes, _ := json.Marshal(brokenData)

	// Step 2: PUT /v1/admin/data -> must be rejected with 422 and mention smoke test
	resp := h.do(t, http.MethodPut, "/v1/admin/data", "application/json", string(brokenBytes), true)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("PUT broken data status = %d, want 422", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, "smoke test failed") {
		t.Fatalf("expected smoke test error message, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "rm -rf") {
		t.Fatalf("expected message to mention rm -rf, got: %s", bodyStr)
	}
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return string(b)
}
