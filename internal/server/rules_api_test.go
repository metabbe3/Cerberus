package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/store"
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

func TestRules_RollbackRestoresRawSecretAndMirrorsPG(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	var pgSaveCalls atomic.Int32
	var lastSavedData atomic.Value
	h.api.deps.PGMirror = store.NewTestPG(func(_ context.Context, data map[string]any) error {
		pgSaveCalls.Add(1)
		lastSavedData.Store(data)
		return nil
	})

	// Step 1: PUT initial data with secret api_key
	initialSnap := h.store.Current()
	data1 := make(map[string]any)
	for k, v := range initialSnap.Data {
		data1[k] = v
	}
	agents1 := make(map[string]any)
	if ag, ok := data1["agents"].(map[string]any); ok {
		for ak, av := range ag {
			agents1[ak] = av
		}
	}
	secretVal := "mock-token-xyz-12345" // #nosec G101 -- test fixture token
	agents1["k-secret-agent"] = map[string]any{
		"name":    "secret-agent",
		"api_key": secretVal,
	}
	data1["agents"] = agents1
	bytes1, _ := json.Marshal(data1)

	resp1 := h.do(t, http.MethodPut, "/v1/admin/data", "application/json", string(bytes1), true)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("PUT /v1/admin/data status = %d, want 200", resp1.StatusCode)
	}

	// Verify revision recorded and PGMirror called
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pgSaveCalls.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if pgSaveCalls.Load() == 0 {
		t.Fatal("expected PGMirror.SaveData call on initial PUT, got 0")
	}

	// Step 2: PUT second data modification
	data2 := make(map[string]any)
	for k, v := range data1 {
		data2[k] = v
	}
	agents2 := make(map[string]any)
	for ak, av := range agents1 {
		agents2[ak] = av
	}
	agents2["k-secret-agent"] = map[string]any{
		"name":    "secret-agent-v2",
		"api_key": "changed-val",
	}
	data2["agents"] = agents2
	bytes2, _ := json.Marshal(data2)

	resp2 := h.do(t, http.MethodPut, "/v1/admin/data", "application/json", string(bytes2), true)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("PUT /v1/admin/data v2 status = %d, want 200", resp2.StatusCode)
	}

	// Step 3: GET /v1/admin/revisions
	// Verify that revision list masks secretVal into "[REDACTED]"
	revResp := h.do(t, http.MethodGet, "/v1/admin/revisions", "", "", true)
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/revisions status = %d, want 200", revResp.StatusCode)
	}
	revBody, _ := io.ReadAll(revResp.Body)
	if strings.Contains(string(revBody), secretVal) {
		t.Fatalf("GET /v1/admin/revisions leaked raw secret: %s", string(revBody))
	}
	if !strings.Contains(string(revBody), "[REDACTED]") {
		t.Fatalf("GET /v1/admin/revisions missing [REDACTED] masking: %s", string(revBody))
	}

	type revItem struct {
		ID int64 `json:"id"`
	}
	var revs []revItem
	if err := json.Unmarshal(revBody, &revs); err != nil {
		t.Fatalf("unmarshal revs: %v", err)
	}
	if len(revs) < 2 {
		t.Fatalf("expected at least 2 revisions, got %d", len(revs))
	}

	// Step 4: Rollback to the revision containing data1 (revs[0].ID)
	pgSaveCalls.Store(0)
	targetRevID := revs[0].ID
	rollbackReq := fmt.Sprintf(`{"revision_id": %d}`, targetRevID)
	rbResp := h.do(t, http.MethodPost, "/v1/admin/rollback", "application/json", rollbackReq, true)
	if rbResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/admin/rollback status = %d, want 200", rbResp.StatusCode)
	}

	// Wait for goroutine PGMirror.SaveData
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pgSaveCalls.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if pgSaveCalls.Load() == 0 {
		t.Fatal("PGMirror.SaveData was NOT called after rollback")
	}

	// Step 5: Verify current active store data has the raw secret, NOT [REDACTED]
	curSnap := h.store.Current()
	curAgents, _ := curSnap.Data["agents"].(map[string]any)
	targetAgent, ok := curAgents["k-secret-agent"].(map[string]any)
	if !ok {
		t.Fatalf("agent k-secret-agent missing after rollback")
	}
	if targetAgent["api_key"] != secretVal {
		t.Fatalf("agent api_key = %v, want raw secret %q", targetAgent["api_key"], secretVal)
	}
	if targetAgent["api_key"] == "[REDACTED]" {
		t.Fatal("agent api_key in active store was restored as [REDACTED]!")
	}
}
