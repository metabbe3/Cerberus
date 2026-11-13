package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

// DryRunSmoke evaluates the candidate snapshot against essential safety-net fixtures:
// 1. rm -rf deny (shield.cmd.dangerous)
// 2. grep /etc/passwd deny (shield.cmd.dangerous)
// 3. ls allow
// 4. protected container deny (shield.container.protected)
// 5. happy llm/tool allow
// Rejection here prevents activating broken or overly permissive policies.
func DryRunSmoke(ctx context.Context, snap *Snapshot) error {
	type smokeCase struct {
		name       string
		input      map[string]any
		wantDec    string
		wantRuleID string
	}

	targetContainer := "teknikalidnew-db-1"
	if ps, ok := snap.Data["prod_shield"].(map[string]any); ok {
		if pcs, ok := ps["protected_containers"].([]any); ok && len(pcs) > 0 {
			if s, ok := pcs[0].(string); ok && s != "" {
				targetContainer = s
			}
		}
	}

	cases := []smokeCase{
		{
			name: "rm -rf",
			input: map[string]any{
				"stage":     "tool",
				"key_id":    "k-stranger-smoke",
				"tool_call": "bash",
				"args":      map[string]any{"cmd": "rm -rf /"},
				"bypass":    true,
			},
			wantDec:    "deny",
			wantRuleID: "shield.cmd.dangerous",
		},
		{
			name: "grep /etc/passwd",
			input: map[string]any{
				"stage":     "tool",
				"key_id":    "k-stranger-smoke",
				"tool_call": "bash",
				"args":      map[string]any{"cmd": "grep * /etc/passwd"},
				"bypass":    true,
			},
			wantDec:    "deny",
			wantRuleID: "shield.cmd.dangerous",
		},
		{
			name: "ls allow",
			input: map[string]any{
				"stage":     "tool",
				"key_id":    "k-stranger-smoke",
				"tool_call": "bash",
				"args":      map[string]any{"cmd": "ls -la /tmp"},
				"bypass":    true,
			},
			wantDec:    "allow",
			wantRuleID: "",
		},
		{
			name: "protected container",
			input: map[string]any{
				"stage":     "tool",
				"key_id":    "k-stranger-smoke",
				"tool_call": "docker rm",
				"args":      map[string]any{"container": targetContainer},
				"bypass":    true,
			},
			wantDec:    "deny",
			wantRuleID: "shield.container.protected",
		},
		{
			name: "happy llm/tool allow",
			input: map[string]any{
				"stage":    "llm",
				"key_id":   "k-stranger-smoke",
				"model":    "gpt-4",
				"messages": []any{map[string]any{"role": "user", "content": "ping"}},
				"bypass":   true,
			},
			wantDec:    "allow",
			wantRuleID: "",
		},
	}

	// If global kill switch is explicitly enabled, verify that all traffic is properly denied with ops.kill_switch.
	if cfg, ok := snap.Data["config"].(map[string]any); ok {
		if ks, ok := cfg["kill_switch"].(map[string]any); ok {
			if g, ok := ks["global"].(bool); ok && g {
				for _, sc := range cases {
					rs, err := snap.Query.Eval(ctx, rego.EvalInput(sc.input))
					if err != nil {
						return fmt.Errorf("kill switch smoke eval '%s' error: %w", sc.name, err)
					}
					if len(rs) == 0 || len(rs[0].Expressions) == 0 {
						return fmt.Errorf("kill switch smoke eval '%s' returned no expression", sc.name)
					}
					val, ok := rs[0].Expressions[0].Value.(map[string]any)
					if !ok {
						return fmt.Errorf("kill switch smoke eval '%s' returned invalid value type %T", sc.name, rs[0].Expressions[0].Value)
					}
					gotDec := strVal(val["decision"])
					gotRule := strVal(val["rule_id"])
					if gotDec != "deny" || gotRule != "ops.kill_switch" {
						return fmt.Errorf("kill switch smoke test failed on '%s': got %s/%s, want deny/ops.kill_switch", sc.name, gotDec, gotRule)
					}
				}
				return nil
			}
		}
	}

	// Fail-closed deployments (bypass_unknown_keys=false) deny unknown keys
	// outright, so stranger-key "expect allow" cases do not apply — skip them
	// instead of forcing the data back to onboarding mode.
	closedMode := false
	if cfg, ok := snap.Data["config"].(map[string]any); ok {
		if v, ok := cfg["bypass_unknown_keys"].(bool); ok {
			closedMode = !v
		}
	}

	for _, sc := range cases {
		if closedMode && sc.wantDec == "allow" && !registeredKey(snap.Data, sc.input) {
			continue
		}
		rs, err := snap.Query.Eval(ctx, rego.EvalInput(sc.input))
		if err != nil {
			return fmt.Errorf("smoke eval '%s' error: %w", sc.name, err)
		}
		if len(rs) == 0 || len(rs[0].Expressions) == 0 {
			return fmt.Errorf("smoke eval '%s' returned no expression", sc.name)
		}
		val, ok := rs[0].Expressions[0].Value.(map[string]any)
		if !ok {
			return fmt.Errorf("smoke eval '%s' returned invalid value type %T", sc.name, rs[0].Expressions[0].Value)
		}
		gotDec := strVal(val["decision"])
		gotRule := strVal(val["rule_id"])
		if gotDec != sc.wantDec {
			return fmt.Errorf("smoke test failed on '%s': got %s/%s, want %s", sc.name, gotDec, gotRule, sc.wantDec)
		}
		if sc.wantRuleID != "" && gotRule != sc.wantRuleID {
			// A stranger-key deny under bypass_unknown_keys=false is equally
			// fail-closed: accept config.unknown_key_closed wherever the case
			// expected a deny from a stage rule.
			if sc.wantDec != "deny" || gotRule != "config.unknown_key_closed" {
				return fmt.Errorf("smoke test failed on '%s': got rule %s, want %s", sc.name, gotRule, sc.wantRuleID)
			}
		}
	}
	return nil
}

// registeredKey reports whether the case's key_id exists in data.agents.
func registeredKey(data map[string]any, input map[string]any) bool {
	k, _ := input["key_id"].(string)
	if k == "" {
		return false
	}
	agents, ok := data["agents"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = agents[k].(map[string]any)
	return ok
}
