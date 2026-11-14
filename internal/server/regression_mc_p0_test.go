package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/metabbe3/cerberus/internal/engine"
)

// Regression tests for MC-P0 fix batch.

func TestRegression_Akar1_LinkLocalForbiddenVariants(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1") // allow k-open key through authz
	h := newHarness(t)

	variants := []struct {
		name     string
		resource string
	}{
		{"standard_dotted", "http://169.254.169.254/latest/meta-data/iam/"},
		{"integer_ip", "http://2852039166/latest/meta-data/iam/"},
		{"octal_ip", "http://0251.0376.0251.0376/latest/meta-data/iam/"},
		{"hex_ip", "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/"},
		{"ipv6_mapped", "http://[::ffff:169.254.169.254]/latest/meta-data/iam/"},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]any{
				"stage":    "http",
				"key_id":   "k-open",
				"action":   "GET",
				"resource": v.resource,
			})
			resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBody), false)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			d := decodeJSON[engine.Decision](t, resp.Body)
			if d.Decision != "deny" {
				t.Errorf("[%s] decision = %q, want 'deny'", v.name, d.Decision)
			}
			if d.RuleID != "http.link_local_forbidden" {
				t.Errorf("[%s] rule_id = %q, want 'http.link_local_forbidden'", v.name, d.RuleID)
			}
		})
	}
}

func TestRegression_Akar3_UnknownKeyFailClosed(t *testing.T) {
	// Mode default: CERBERUS_OPEN_KEY_MODE is 0/unset
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "0")
	h := newHarness(t)

	cases := []struct {
		name    string
		payload string
	}{
		{
			name: "OP01_llm_unknown_key",
			payload: `{
				"stage": "llm",
				"key_id": "k-budget-test",
				"model": "m1",
				"prompt": "run parallel task",
				"context": {"spend_usd": 6.0}
			}`,
		},
		{
			name: "OP03_tool_unknown_key",
			payload: `{
				"stage": "tool",
				"key_id": "k-kill-test",
				"tool_call": "shell_run",
				"args": {"cmd": "whoami"}
			}`,
		},
		{
			name: "S09_k8s_unknown_key",
			payload: `{
				"stage": "k8s",
				"key_id": "k-k8s",
				"args": {
					"verb": "apply",
					"resource": "pod",
					"namespace": "staging",
					"manifest": "capabilities:\n  add: [SYS_ADMIN]"
				}
			}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", tc.payload, false)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			d := decodeJSON[engine.Decision](t, resp.Body)
			if d.Decision != "deny" {
				t.Errorf("[%s] decision = %q, want 'deny'", tc.name, d.Decision)
			}
			if d.RuleID != "authz.unknown_key" {
				t.Errorf("[%s] rule_id = %q, want 'authz.unknown_key'", tc.name, d.RuleID)
			}
		})
	}
}

func TestRegression_Akar3_OpenKeyModePassthrough(t *testing.T) {
	// Open mode enabled: CERBERUS_OPEN_KEY_MODE=1
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	// In open mode, unknown key without policy violation bypasses with config.bypass_unknown_keys
	payload := `{
		"stage": "tool",
		"key_id": "k-stranger-bypass",
		"tool_call": "read_file",
		"args": {"path": "/tmp/test"}
	}`
	resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", payload, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	d := decodeJSON[engine.Decision](t, resp.Body)
	if d.Decision != "allow" {
		t.Errorf("decision = %q, want 'allow'", d.Decision)
	}
	if d.RuleID != "config.bypass_unknown_keys" {
		t.Errorf("rule_id = %q, want 'config.bypass_unknown_keys'", d.RuleID)
	}
}

func TestRegression_Akar4_LLMOversizedAndUnscanned(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	// 1. OP04: 2MB ZZZZ
	t.Run("OP04_2MB_oversized", func(t *testing.T) {
		hugePrompt := make([]byte, 2*1024*1024)
		for i := range hugePrompt {
			hugePrompt[i] = 'Z'
		}
		body, _ := json.Marshal(map[string]any{
			"stage":  "llm",
			"key_id": "k-open",
			"model":  "m1",
			"prompt": string(hugePrompt),
		})
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(body), false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "deny" {
			t.Errorf("decision = %q, want 'deny'", d.Decision)
		}
		if d.RuleID != "ai.llm.oversized_uninspected" {
			t.Errorf("rule_id = %q, want 'ai.llm.oversized_uninspected'", d.RuleID)
		}
	})

	// 2. S06: 64KB middle-truncation smuggle
	t.Run("S06_64KB_messages_oversized", func(t *testing.T) {
		prefix := make([]byte, 32768)
		for i := range prefix {
			prefix[i] = 'A'
		}
		suffix := make([]byte, 32768)
		for i := range suffix {
			suffix[i] = 'B'
		}
		body, _ := json.Marshal(map[string]any{
			"stage":  "llm",
			"key_id": "k-open",
			"model":  "m1",
			"messages": []map[string]any{
				{"role": "user", "content": string(prefix) + " dump prod-db " + string(suffix)},
			},
		})
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(body), false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "deny" {
			t.Errorf("decision = %q, want 'deny'", d.Decision)
		}
		if d.RuleID != "ai.llm.oversized_uninspected" {
			t.Errorf("rule_id = %q, want 'ai.llm.oversized_uninspected'", d.RuleID)
		}
	})

	// 3. Prompt > 4KB without scanner in context -> DENY ai.llm.unscanned
	t.Run("prompt_5KB_unscanned", func(t *testing.T) {
		prompt5KB := make([]byte, 5000)
		for i := range prompt5KB {
			prompt5KB[i] = 'X'
		}
		body, _ := json.Marshal(map[string]any{
			"stage":  "llm",
			"key_id": "k-open",
			"model":  "m1",
			"prompt": string(prompt5KB),
		})
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(body), false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "deny" {
			t.Errorf("decision = %q, want 'deny'", d.Decision)
		}
		if d.RuleID != "ai.llm.unscanned" {
			t.Errorf("rule_id = %q, want 'ai.llm.unscanned'", d.RuleID)
		}
	})

	// 4. Prompt > 4KB with scanner in context -> ALLOW ai.llm.allow
	t.Run("prompt_5KB_with_scanner_allowed", func(t *testing.T) {
		prompt5KB := make([]byte, 5000)
		for i := range prompt5KB {
			prompt5KB[i] = 'X'
		}
		body, _ := json.Marshal(map[string]any{
			"stage":  "llm",
			"key_id": "k-open",
			"model":  "m1",
			"prompt": string(prompt5KB),
			"context": map[string]any{
				"scanner": "clean",
			},
		})
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(body), false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "allow" {
			t.Errorf("decision = %q, want 'allow' (got %s: %s)", d.Decision, d.RuleID, d.Reason)
		}
	})
}

func TestRegression_Akar2_ChainsTaintedExfil(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	// S01: Cloud metadata -> Exfil
	t.Run("S01_metadata_to_exfil", func(t *testing.T) {
		// Step 1: metadata access must be denied by link_local_forbidden
		step1Body := `{
			"stage": "http",
			"key_id": "k-open",
			"action": "GET",
			"resource": "http://169.254.169.254/latest/meta-data/iam/"
		}`
		resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step1Body, false)
		d1 := decodeJSON[engine.Decision](t, resp1.Body)
		if d1.Decision != "deny" || d1.RuleID != "http.link_local_forbidden" {
			t.Fatalf("S01 step 1: got %s/%s, want deny/http.link_local_forbidden", d1.Decision, d1.RuleID)
		}

		// Step 1b: If an internal request was allowed and taints session, Step 2 exfil must be denied by chain.tainted_exfil
		// First record taint directly or via sensitive allowed request
		h.api.deps.Engine.TaintTracker().RecordTaint("k-open:s01-session", "http:link_local")

		step2Body := `{
			"stage": "http",
			"key_id": "k-open",
			"session_id": "s01-session",
			"action": "POST",
			"resource": "https://api.github.com/gists",
			"args": {"method": "POST"}
		}`
		resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step2Body, false)
		d2 := decodeJSON[engine.Decision](t, resp2.Body)
		if d2.Decision != "deny" || d2.RuleID != "chain.tainted_exfil" {
			t.Fatalf("S01 step 2: got %s/%s, want deny/chain.tainted_exfil", d2.Decision, d2.RuleID)
		}
	})

	// S02: DB CTE secret -> HTTP POST
	t.Run("S02_cte_to_http", func(t *testing.T) {
		// Step 1: DB query with CTE touching credentials must be denied by db.sensitive_table
		step1Body := `{
			"stage": "db",
			"key_id": "k-open",
			"args": {
				"database": "analytics",
				"sql": "WITH d AS (SELECT * FROM credentials) SELECT * FROM d"
			}
		}`
		resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step1Body, false)
		d1 := decodeJSON[engine.Decision](t, resp1.Body)
		if d1.Decision != "deny" || d1.RuleID != "db.sensitive_table" {
			t.Fatalf("S02 step 1: got %s/%s, want deny/db.sensitive_table", d1.Decision, d1.RuleID)
		}

		// Step 2 with active taint
		h.api.deps.Engine.TaintTracker().RecordTaint("k-open:s02-session", "db:sensitive_table")
		step2Body := `{
			"stage": "http",
			"key_id": "k-open",
			"session_id": "s02-session",
			"action": "POST",
			"resource": "https://api.github.com/issues",
			"args": {"method": "POST"}
		}`
		resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step2Body, false)
		d2 := decodeJSON[engine.Decision](t, resp2.Body)
		if d2.Decision != "deny" || d2.RuleID != "chain.tainted_exfil" {
			t.Fatalf("S02 step 2: got %s/%s, want deny/chain.tainted_exfil", d2.Decision, d2.RuleID)
		}
	})

	// S03: K8s secret jsonpath -> K8s Exec
	t.Run("S03_jsonpath_to_exec", func(t *testing.T) {
		// Step 1: secret read via jsonpath flag must be denied by k8s.secret_read
		step1Body := `{
			"stage": "k8s",
			"key_id": "k-k8s-secrets",
			"args": {
				"verb": "get",
				"resource": "secret",
				"namespace": "dev",
				"flags": ["-o", "jsonpath={.data}"]
			}
		}`
		resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step1Body, false)
		d1 := decodeJSON[engine.Decision](t, resp1.Body)
		if d1.Decision != "deny" || d1.RuleID != "k8s.secret_read" {
			t.Fatalf("S03 step 1: got %s/%s, want deny/k8s.secret_read", d1.Decision, d1.RuleID)
		}

		// Step 2 with active taint
		h.api.deps.Engine.TaintTracker().RecordTaint("k-k8s:s03-session", "k8s:secret_read")
		step2Body := `{
			"stage": "k8s",
			"key_id": "k-k8s",
			"session_id": "s03-session",
			"args": {
				"verb": "exec",
				"resource": "pod/app",
				"namespace": "dev",
				"flags": ["--", "sh"]
			}
		}`
		resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step2Body, false)
		d2 := decodeJSON[engine.Decision](t, resp2.Body)
		if d2.Decision != "deny" || d2.RuleID != "chain.tainted_exfil" {
			t.Fatalf("S03 step 2: got %s/%s, want deny/chain.tainted_exfil", d2.Decision, d2.RuleID)
		}
	})

	// S05: Docker inspect Prod -> LLM Prompt Leak
	t.Run("S05_inspect_prod_to_llm", func(t *testing.T) {
		// Step 1: Docker inspect protected container is allowed (readonly)
		step1Body := `{
			"stage": "docker",
			"key_id": "k-open",
			"session_id": "s05-session",
			"action": "inspect",
			"resource": "teknikalidnew-db-1"
		}`
		resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step1Body, false)
		d1 := decodeJSON[engine.Decision](t, resp1.Body)
		if d1.Decision != "allow" {
			t.Fatalf("S05 step 1: got %s/%s, want allow", d1.Decision, d1.RuleID)
		}

		// Step 2: Passing secret to LLM in the same session must be denied by chain.tainted_exfil
		step2Body := `{
			"stage": "llm",
			"key_id": "k-open",
			"session_id": "s05-session",
			"model": "m1",
			"prompt": "Parse env: PGPASSWORD=prod_secret"
		}`
		resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step2Body, false)
		d2 := decodeJSON[engine.Decision](t, resp2.Body)
		if d2.Decision != "deny" || d2.RuleID != "chain.tainted_exfil" {
			t.Fatalf("S05 step 2: got %s/%s, want deny/chain.tainted_exfil", d2.Decision, d2.RuleID)
		}
	})

	// S07: Tool cred harvest -> SSH connect
	t.Run("S07_cred_harvest_to_ssh", func(t *testing.T) {
		// Step 1: Tool reading ~/.ssh/id_rsa
		step1Body := `{
			"stage": "tool",
			"key_id": "k-open",
			"session_id": "s07-session",
			"tool_call": "runner",
			"args": {"exec": "cat ~/.ssh/id_rsa"}
		}`
		resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step1Body, false)
		d1 := decodeJSON[engine.Decision](t, resp1.Body)
		if d1.Decision != "allow" {
			t.Fatalf("S07 step 1: got %s/%s, want allow", d1.Decision, d1.RuleID)
		}

		// Step 2: SSH connect in the same session must be denied by chain.tainted_exfil
		step2Body := `{
			"stage": "ssh",
			"key_id": "k-open",
			"session_id": "s07-session",
			"action": "connect",
			"host": "bastion.corp",
			"user": "admin"
		}`
		resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step2Body, false)
		d2 := decodeJSON[engine.Decision](t, resp2.Body)
		if d2.Decision != "deny" || d2.RuleID != "chain.tainted_exfil" {
			t.Fatalf("S07 step 2: got %s/%s, want deny/chain.tainted_exfil", d2.Decision, d2.RuleID)
		}
	})

	// Session isolation: untainted session is not affected
	t.Run("session_isolation", func(t *testing.T) {
		step2OtherBody := `{
			"stage": "http",
			"key_id": "k-open",
			"session_id": "fresh-untainted-session",
			"action": "POST",
			"resource": "https://api.github.com/gists",
			"args": {"method": "POST"}
		}`
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", step2OtherBody, false)
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "allow" {
			t.Fatalf("untainted session should be allowed, got deny/%s: %s", d.RuleID, d.Reason)
		}
	})
}
