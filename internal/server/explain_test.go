package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/engine"
)

func TestDecide_ExplainQueryParam(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	sub, cancel := h.auditLog.Subscribe()
	defer cancel()

	// 1. POST /v1/decide?explain=true without auth must return 401 Unauthorized
	reqBody := `{"stage": "tool", "key_id": "k-open", "tool_call": "bash", "args": {"cmd": "rm -rf /"}}`
	respNoAuth := h.do(t, http.MethodPost, "/v1/decide?explain=true", "application/json", reqBody, false)
	if respNoAuth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("decide explain without auth status = %d, want 401", respNoAuth.StatusCode)
	}

	// 2. POST /v1/decide?explain=true with auth must return 200 OK
	resp := h.do(t, http.MethodPost, "/v1/decide?explain=true", "application/json", reqBody, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decide explain status = %d, want 200", resp.StatusCode)
	}

	// 3. Verify audit event was emitted with RuleID "admin.explain"
	select {
	case ev := <-sub:
		if ev.RuleID != "admin.explain" {
			t.Fatalf("audit event RuleID = %q, want admin.explain", ev.RuleID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for audit event for admin.explain")
	}

	var d engine.Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode explain response: %v", err)
	}

	if d.Decision != "deny" || d.RuleID != "shield.cmd.dangerous" {
		t.Fatalf("decision = %s/%s, want deny/shield.cmd.dangerous", d.Decision, d.RuleID)
	}
	if len(d.Trace) == 0 {
		t.Fatal("expected non-empty trace in explain response, got 0 entries")
	}
	if d.PrettyTrace == "" {
		t.Fatal("expected non-empty pretty_trace, got empty string")
	}

	// Verify trace entries have valid Op, Rule/Node, Location
	foundDangerousRule := false
	for _, tr := range d.Trace {
		if tr.Op == "" {
			t.Errorf("trace entry with empty Op: %+v", tr)
		}
		if tr.Rule != "" && tr.Rule == "data.shield.prod.dangerous_cmd" || tr.Rule == "dangerous_cmd" {
			foundDangerousRule = true
		}
	}
	t.Logf("Evaluated trace length: %d entries, foundDangerousRule: %v", len(d.Trace), foundDangerousRule)
}

func TestAdmin_ExplainEndpoint(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Admin dry-run explain with safe tool command
	reqBody := `{"stage": "tool", "key_id": "k-open", "tool_call": "bash", "args": {"cmd": "ls -la /tmp"}}`
	resp := h.do(t, http.MethodPost, "/v1/admin/explain", "application/json", reqBody, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin explain status = %d, want 200", resp.StatusCode)
	}

	var d engine.Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode admin explain response: %v", err)
	}

	if d.Decision != "allow" {
		t.Fatalf("decision = %s, want allow", d.Decision)
	}
	if len(d.Trace) == 0 {
		t.Fatal("expected trace entries, got 0")
	}
	if d.PrettyTrace == "" {
		t.Fatal("expected pretty trace, got empty")
	}
}
