package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/metabbe3/cerberus/internal/engine"
)

func TestDecide_ExplainQueryParam(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// POST /v1/decide?explain=true with dangerous command (rm -rf)
	reqBody := `{"stage": "tool", "key_id": "k-open", "tool_call": "bash", "args": {"cmd": "rm -rf /"}}`
	resp := h.do(t, http.MethodPost, "/v1/decide?explain=true", "application/json", reqBody, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decide explain status = %d, want 200", resp.StatusCode)
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
