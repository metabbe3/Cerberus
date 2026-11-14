package gateway.tool_test

# Tool stage tests: live decide contract ({key_id, tool_call, args, ...}).
# Tests both the stages.tool stage adapter and gateway integration:
# happy path allow, restricted tools, argument constraints, unknown key bypass,
# and fail-closed path when bypass_unknown_keys=false.

import rego.v1

import data.gateway.authz.decision
import data.stages.tool

decide(inp) := out if {
	out := decision with input as inp
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

no_bypass_config := object.union(data.testdata.config, {"bypass_unknown_keys": false, "bypass_unknown_teams": false})

decide_closed(inp) := out if {
	out := decision with input as inp
		with data.config as no_bypass_config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

# 1. Happy path: allowed tool call for registered agent
test_tool_allow_happy if {
	out := decide({
		"stage": "tool",
		"key_id": "k-glob",
		"tool_call": "kubernetes_get_pods",
		"args": {"namespace": "default"},
	})
	out.decision == "allow"
	out.rule_id == "ai.tool.allow"
}

# 2. Stage adapter direct evaluation
test_tool_stage_adapter_allow if {
	out := tool.decision with input as {
		"stage": "tool",
		"key_id": "k-glob",
		"tool_call": "kubernetes_get_pods",
		"args": {"namespace": "default"},
	}
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
	out.decision == "allow"
	out.rule_id == "ai.tool.allow"
}

# 3. Restricted tool call is denied
test_tool_restricted_denied if {
	out := decide({
		"stage": "tool",
		"key_id": "k-glob",
		"tool_call": "kubernetes_delete_pod",
		"args": {"pod": "test-pod"},
	})
	out.decision == "deny"
	out.rule_id == "ai.tool.restricted"
}

# 4. Tool call not in allow-list is denied
test_tool_not_allowed_denied if {
	out := decide({
		"stage": "tool",
		"key_id": "k-glob",
		"tool_call": "read_file",
		"args": {"path": "/tmp/test"},
	})
	out.decision == "deny"
	out.rule_id == "ai.tool.not_allowed"
}

# 5. Argument constraint violation is denied
test_tool_arg_violation_denied if {
	out := decide({
		"stage": "tool",
		"key_id": "k-exact",
		"tool_call": "bash",
		"args": {"timeout": 999},
	})
	out.decision == "deny"
	out.rule_id == "ai.tool.arg_violation"
}

# 6. Default unknown key with bypass_unknown_keys=true (fail-open onboarding)
test_tool_unknown_key_bypass_allowed if {
	out := decide({
		"stage": "tool",
		"key_id": "stranger-key",
		"tool_call": "unregistered_tool",
		"args": {"info": "harmless"},
	})
	out.decision == "allow"
	out.rule_id == "config.bypass_unknown_keys"
}

# 7. Unknown key executing dangerous command is denied by shield
test_tool_unknown_key_dangerous_cmd_denied if {
	out := decide({
		"stage": "tool",
		"key_id": "stranger-key",
		"tool_call": "bash",
		"args": {"cmd": "rm -rf /"},
	})
	out.decision == "deny"
	out.rule_id == "shield.cmd.dangerous"
}

# 8. Unknown key fails closed when bypass_unknown_keys=false
test_tool_unknown_key_bypass_false_denied if {
	out := decide_closed({
		"stage": "tool",
		"key_id": "stranger-key",
		"tool_call": "any_tool",
		"args": {},
	})
	out.decision == "deny"
	out.rule_id == "authz.unknown_key"
}
