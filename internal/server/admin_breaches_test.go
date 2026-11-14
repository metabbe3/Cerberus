package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
)

func TestBreachesAndAgentsSummary(t *testing.T) {
	h := newHarness(t)

	now := time.Now().UTC()

	// Fixtures:
	// 1. Security Deny (CRITICAL): shield.cmd.dangerous
	// 2. Security Deny (HIGH): db.sensitive_table
	// 3. Security Deny (MEDIUM): tool.restricted_access
	// 4. Rate/Policy Deny (NON-BREACH): ops.rate_limited
	// 5. Policy Deny (NON-BREACH): tool.not_allowed
	// 6. Security Allow (NON-BREACH): shield.cmd.dangerous (allow verdict)
	events := []audit.Event{
		{
			Time:     now.Add(-2 * time.Hour),
			Stage:    "tool",
			KeyID:    "agent-bad",
			Subject:  "shell_exec",
			Decision: "deny",
			RuleID:   "shield.cmd.dangerous",
			Reason:   "dangerous command rm -rf",
			Epoch:    1,
			Args:     map[string]any{"cmd": "rm -rf /"},
		},
		{
			Time:     now.Add(-1 * time.Hour),
			Stage:    "db",
			KeyID:    "agent-bad",
			Subject:  "query",
			Decision: "deny",
			RuleID:   "db.sensitive_table",
			Reason:   "unauthorized access to sensitive table",
			Epoch:    1,
			Args:     map[string]any{"table": "users"},
		},
		{
			Time:     now.Add(-30 * time.Minute),
			Stage:    "tool",
			KeyID:    "agent-restricted",
			Subject:  "restricted_action",
			Decision: "deny",
			RuleID:   "shield.restricted_command",
			Reason:   "tool requires elevated permissions",
			Epoch:    1,
		},
		{
			Time:     now.Add(-15 * time.Minute),
			Stage:    "tool",
			KeyID:    "agent-spammy",
			Subject:  "api_call",
			Decision: "deny",
			RuleID:   "ops.rate_limited",
			Reason:   "rate limit exceeded",
			Epoch:    1,
		},
		{
			Time:     now.Add(-10 * time.Minute),
			Stage:    "tool",
			KeyID:    "agent-spammy",
			Subject:  "unregistered_tool",
			Decision: "deny",
			RuleID:   "tool.not_allowed",
			Reason:   "tool not in allowlist",
			Epoch:    1,
		},
		{
			Time:     now.Add(-5 * time.Minute),
			Stage:    "tool",
			KeyID:    "agent-good",
			Subject:  "safe_command",
			Decision: "allow",
			RuleID:   "shield.cmd.dangerous",
			Reason:   "safe command",
			Epoch:    1,
		},
	}

	for _, ev := range events {
		h.auditLog.Emit(ev)
	}

	// 1. Test GET /v1/audit/breaches — poll hingga audit logger selesai flush
	// (pipeline audit async; sleep tetap di CI lambat — poll dengan deadline).
	var breachRes audit.BreachResult
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/v1/audit/breaches?since=24h", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /v1/audit/breaches: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		breachRes = audit.BreachResult{}
		if err := json.NewDecoder(resp.Body).Decode(&breachRes); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("decode breach result: %v", err)
		}
		_ = resp.Body.Close()
		if breachRes.Summary.Total >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify Summary:
	// Critical: 1 (shield.cmd.dangerous deny)
	// High: 1 (db.sensitive_table deny)
	// Medium: 1 (tool.restricted_access deny)
	// Total: 3 (rate_limited, not_allowed, and allow are excluded!)
	if breachRes.Summary.Critical != 1 {
		t.Errorf("summary.Critical = %d, want 1", breachRes.Summary.Critical)
	}
	if breachRes.Summary.High != 1 {
		t.Errorf("summary.High = %d, want 1", breachRes.Summary.High)
	}
	if breachRes.Summary.Medium != 1 {
		t.Errorf("summary.Medium = %d, want 1", breachRes.Summary.Medium)
	}
	if breachRes.Summary.Total != 3 {
		t.Errorf("summary.Total = %d, want 3 (security denies only)", breachRes.Summary.Total)
	}

	// Verify Events:
	// Only 3 security deny events should be present in events list
	if len(breachRes.Events) != 3 {
		t.Fatalf("len(breachRes.Events) = %d, want 3", len(breachRes.Events))
	}
	for _, ev := range breachRes.Events {
		if ev.Decision != "deny" {
			t.Errorf("breach event decision = %q, want deny", ev.Decision)
		}
		if ev.RuleID == "ops.rate_limited" || ev.RuleID == "tool.not_allowed" {
			t.Errorf("policy event %s should not be in breaches events list", ev.RuleID)
		}
	}

	// Verify Top Offenders:
	// agent-bad had 2 security breaches (1 critical, 1 high)
	// agent-restricted had 1 (medium)
	if len(breachRes.TopOffenders) == 0 {
		t.Fatal("expected top offenders, got none")
	}
	top := breachRes.TopOffenders[0]
	if top.KeyID != "agent-bad" {
		t.Errorf("top offender KeyID = %q, want agent-bad", top.KeyID)
	}
	if top.Count != 2 {
		t.Errorf("top offender Count = %d, want 2", top.Count)
	}
	if top.CriticalCount != 1 {
		t.Errorf("top offender CriticalCount = %d, want 1", top.CriticalCount)
	}

	// 2. Test GET /v1/audit/agents-summary?since=24h
	reqSummary, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/v1/audit/agents-summary?since=24h", nil)
	reqSummary.Header.Set("Authorization", "Bearer "+adminToken)
	respSummary, err := http.DefaultClient.Do(reqSummary)
	if err != nil {
		t.Fatalf("GET /v1/audit/agents-summary: %v", err)
	}
	defer func() { _ = respSummary.Body.Close() }()
	if respSummary.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respSummary.StatusCode)
	}

	var summaries []audit.AgentSummary
	if err := json.NewDecoder(respSummary.Body).Decode(&summaries); err != nil {
		t.Fatalf("decode agents summary: %v", err)
	}

	// Verify agent summaries:
	// agent-bad: total=2, deny=2, breach_count=2 (critical+high)
	// agent-spammy: total=2, deny=2, breach_count=0 (policy only)
	var badSummary, spammySummary *audit.AgentSummary
	for i := range summaries {
		if summaries[i].KeyID == "agent-bad" {
			badSummary = &summaries[i]
		}
		if summaries[i].KeyID == "agent-spammy" {
			spammySummary = &summaries[i]
		}
	}
	if badSummary == nil {
		t.Fatal("expected summary for agent-bad")
	}
	if badSummary.BreachCount != 2 {
		t.Errorf("agent-bad breach_count = %d, want 2", badSummary.BreachCount)
	}
	if spammySummary == nil {
		t.Fatal("expected summary for agent-spammy")
	}
	if spammySummary.BreachCount != 0 {
		t.Errorf("agent-spammy breach_count = %d, want 0 (policy denies are not breaches)", spammySummary.BreachCount)
	}
}

func TestRotateKey(t *testing.T) {
	h := newHarness(t)

	// 1. Rotate key with clone policy (revoke_old=false)
	body := `{"revoke_old": false, "suffix": "-v2"}`
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/keys/k-prod/rotate", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST rotate key: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var rotResp rotateKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&rotResp); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if !rotResp.OK || rotResp.NewKeyID != "k-prod-v2" || rotResp.RevokedOld {
		t.Fatalf("unexpected rotate response: %+v", rotResp)
	}

	// Verify data has both old and new keys
	snap := h.store.Current()
	agents := snap.Data["agents"].(map[string]any)
	if _, ok := agents["k-prod"]; !ok {
		t.Error("expected old key k-prod to still exist")
	}
	if _, ok := agents["k-prod-v2"]; !ok {
		t.Error("expected new key k-prod-v2 to exist")
	}

	// 2. Rotate key with revoke_old=true
	bodyRevoke := `{"revoke_old": true, "suffix": "-v3"}`
	req2, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/keys/k-prod/rotate", strings.NewReader(bodyRevoke))
	req2.Header.Set("Authorization", "Bearer "+adminToken)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("POST rotate key revoke: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}

	snap2 := h.store.Current()
	agents2 := snap2.Data["agents"].(map[string]any)
	if _, ok := agents2["k-prod"]; ok {
		t.Error("expected old key k-prod to be revoked/deleted")
	}
	if _, ok := agents2["k-prod-v3"]; !ok {
		t.Error("expected new key k-prod-v3 to exist")
	}
}

func TestPolicyModulesAndTestRun(t *testing.T) {
	h := newHarness(t)

	// 1. GET /v1/policy/modules
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+"/v1/policy/modules", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/policy/modules: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var mods []PolicyModuleItem
	if err := json.NewDecoder(resp.Body).Decode(&mods); err != nil {
		t.Fatalf("decode modules: %v", err)
	}
	if len(mods) == 0 {
		t.Fatal("expected at least 1 policy module")
	}

	foundShield := false
	for _, m := range mods {
		if strings.Contains(m.File, "shield") {
			foundShield = true
		}
		if m.File == "" || m.SHA256 == "" || m.Size <= 0 {
			t.Errorf("incomplete module metadata: %+v", m)
		}
	}
	if !foundShield {
		t.Errorf("expected shield module in policy modules, got: %+v", mods)
	}

	// 2. POST /v1/policy/test-run
	reqRun, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/policy/test-run", bytes.NewReader(nil))
	reqRun.Header.Set("Authorization", "Bearer "+adminToken)
	respRun, err := http.DefaultClient.Do(reqRun)
	if err != nil {
		t.Fatalf("POST /v1/policy/test-run: %v", err)
	}
	defer func() { _ = respRun.Body.Close() }()
	if respRun.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respRun.StatusCode)
	}

	var testRun TestRunResponse
	if err := json.NewDecoder(respRun.Body).Decode(&testRun); err != nil {
		t.Fatalf("decode test run response: %v", err)
	}
	if testRun.Total == 0 {
		t.Fatal("expected test cases in test-run, got 0")
	}
	if testRun.Failed > 0 {
		t.Fatalf("expected 0 failures in rego test suite, got %d", testRun.Failed)
	}
	if testRun.Passed != testRun.Total {
		t.Fatalf("passed (%d) != total (%d)", testRun.Passed, testRun.Total)
	}
}
