package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/policy"
)

func TestAdmin_ReplayAudit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Emit some audit events
	ev1 := audit.Event{
		Time:     time.Now().Add(-2 * time.Minute),
		Stage:    "docker",
		KeyID:    "k-dev",
		Subject:  "box1",
		Decision: "allow",
		RuleID:   "docker.allow",
		Reason:   "docker action allowed",
		Args:     map[string]any{"action": "stop", "container": "box1"},
	}
	ev2 := audit.Event{
		Time:     time.Now().Add(-1 * time.Minute),
		Stage:    "llm",
		KeyID:    "k-dev",
		Subject:  "gpt-4o",
		Decision: "deny",
		RuleID:   "shield.blocked_pattern",
		Reason:   "blocked pattern matched",
		Args:     map[string]any{"prompt": "eval rm -rf /"},
	}
	h.auditLog.Emit(ev1)
	h.auditLog.Emit(ev2)

	// Poll until both emitted events are visible to replay. On slow CI runners
	// the audit batch flush can lag well past the old fixed 50ms sleep.
	var res1 replayResponse
	ok := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		resp1 := h.do(t, http.MethodPost, "/v1/admin/replay", "application/json", `{"limit":10}`, true)
		if resp1.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp1.StatusCode)
		}
		res1 = decodeJSON[replayResponse](t, resp1.Body)
		if res1.TotalEvaluated >= 2 {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("expected at least 2 evaluated events after 5s, got %d", res1.TotalEvaluated)
	}

	// 2. Replay with draft data that tightens rules
	// Add "box1" to protected_containers so ev1 changes from allow -> deny
	currData := h.store.Current().Data
	draftData := make(map[string]any)
	for k, v := range currData {
		draftData[k] = v
	}
	prodShield := make(map[string]any)
	if ps, ok := currData["prod_shield"].(map[string]any); ok {
		for k, v := range ps {
			prodShield[k] = v
		}
	}
	prodShield["protected_containers"] = []any{"box1", "prod-db"}
	draftData["prod_shield"] = prodShield

	payload, _ := json.Marshal(map[string]any{
		"limit": 10,
		"data":  draftData,
	})
	resp2 := h.do(t, http.MethodPost, "/v1/admin/replay", "application/json", string(payload), true)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for draft replay, got %d", resp2.StatusCode)
	}

	res2 := decodeJSON[replayResponse](t, resp2.Body)
	if res2.DiffCount == 0 {
		t.Fatalf("expected diff count > 0 with stricter draft data, got %d", res2.DiffCount)
	}
	if res2.StricterCount == 0 {
		t.Fatalf("expected stricter count > 0, got %d", res2.StricterCount)
	}

	foundStricter := false
	for _, diff := range res2.Diffs {
		if diff.Subject == "box1" && diff.OldDecision == "allow" && diff.NewDecision == "deny" {
			foundStricter = true
			if diff.Shift != "stricter" {
				t.Fatalf("expected shift 'stricter', got %q", diff.Shift)
			}
		}
	}
	if !foundStricter {
		t.Fatalf("did not find expected stricter diff for box1: %+v", res2.Diffs)
	}

	// 3. Unauthorized request fails with 401
	respUnauth := h.do(t, http.MethodPost, "/v1/admin/replay", "application/json", `{"limit":10}`, false)
	if respUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", respUnauth.StatusCode)
	}
}

func TestAdmin_GetCoverage(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// 1. Unauthorized request fails with 401
	respUnauth := h.do(t, http.MethodGet, "/v1/admin/coverage", "", "", false)
	if respUnauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", respUnauth.StatusCode)
	}

	// 2. Authorized request succeeds
	resp := h.do(t, http.MethodGet, "/v1/admin/coverage", "", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	rep := decodeJSON[policy.CoverageReport](t, resp.Body)
	if rep.Coverage < 80.0 {
		t.Fatalf("expected coverage >= 80%%, got %.2f%%", rep.Coverage)
	}
	if rep.CoveredLines == 0 {
		t.Fatal("expected >0 covered lines")
	}
	if len(rep.Files) == 0 {
		t.Fatal("expected reported files in coverage")
	}
}
