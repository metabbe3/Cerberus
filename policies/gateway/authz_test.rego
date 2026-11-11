package gateway.authz_test

# Core gate tests: key gate, stage dispatch, and the "team never blocks a
# registered key" ruling from the plan's Global Constraints.
#
# The fixture (policies/testdata/data.json) is loaded under data.testdata by
# `opa test policies/`; each query lifts its sections into the live paths.
# (A wholesale `with data as ...` makes OPA flag rule references as recursive.)

import rego.v1

import data.gateway.authz.decision

decide(inp) := out if {
	out := decision with input as inp
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
}

# Fail-closed variant of the fixture: both bypass flags off.
no_bypass_config := object.union(data.testdata.config, {"bypass_unknown_keys": false, "bypass_unknown_teams": false})

decide_closed(inp) := out if {
	out := decision with input as inp
		with data.config as no_bypass_config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
}

test_unknown_stage_denied if {
	out := decide({"stage": "docker", "key_id": "k-open"})
	out.decision == "deny"
	out.rule_id == "internal.unknown_stage"
}

test_missing_stage_denied if {
	out := decide({"key_id": "k-open"})
	out.rule_id == "internal.unknown_stage"
}

# The stage gate precedes the key gate: an unknown stage fails closed even for
# an unregistered key when bypass_unknown_keys=true (no typo'd stage slips
# through the onboarding bypass).
test_unknown_stage_unregistered_key_bypass_denies if {
	out := decide({"stage": "tol", "key_id": "new-agent"})
	out.decision == "deny"
	out.rule_id == "internal.unknown_stage"
}

test_missing_stage_unregistered_key_bypass_denies if {
	out := decide({"key_id": "new-agent"})
	out.decision == "deny"
	out.rule_id == "internal.unknown_stage"
}

test_missing_key_bypass_true_allows if {
	out := decide({"stage": "tool"})
	out.decision == "allow"
	out.rule_id == "config.bypass_unknown_keys"
}

test_missing_key_bypass_false_denies if {
	out := decide_closed({"stage": "tool"})
	out.decision == "deny"
	out.rule_id == "config.unknown_key_closed"
}

# Registered key whose team_id is not in teams: governed by key only, never
# denied for the missing team (Global Constraints) — the stage rules still run.
test_registered_key_unregistered_team_governed_by_key if {
	out := decide({"stage": "tool", "key_id": "k-exact", "tool_call": "bash", "args": {"cmd": "ls -la", "timeout": 30, "env": "prod"}})
	out.decision == "allow"
	out.rule_id == "ai.tool.allow"
}

# Dispatch reaches the AI stage through the core query for an open agent.
test_registered_key_dispatches_to_stage if {
	out := decide({"stage": "tool", "key_id": "k-open", "tool_call": "anything_at_all"})
	out.decision == "allow"
	out.rule_id == "ai.tool.allow"
}

# Bypass flags must be booleans: a non-boolean ("true", 1) fails closed with the
# closed rule_id instead of matching neither key-gate rule (→ internal.default).
decide_flag(inp, flag) := out if {
	out := decision with input as inp
		with data.config as object.union(data.testdata.config, {"bypass_unknown_keys": flag})
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
}

test_bypass_flag_string_true_fails_closed if {
	out := decide_flag({"stage": "tool", "key_id": "new-agent"}, "true")
	out.decision == "deny"
	out.rule_id == "config.unknown_key_closed"
}

test_bypass_flag_number_fails_closed if {
	out := decide_flag({"stage": "tool", "key_id": "new-agent"}, 1)
	out.rule_id == "config.unknown_key_closed"
}

test_bypass_flag_missing_fails_closed if {
	out := decision with input as {"stage": "tool", "key_id": "new-agent"}
		with data.config as {}
		with data.agents as data.testdata.agents
	out.rule_id == "config.unknown_key_closed"
}

# internal.default: a known stage whose stage package yields nothing (here: the
# stage rules are mocked away) still answers the core default deny.
test_internal_default_when_stage_yields_nothing if {
	out := decide({"stage": "tool", "key_id": "k-open", "tool_call": "x"}) with data.stages.ai as {}
	out.rule_id == "internal.default"
}

test_registered_key_llm_dispatch if {
	out := decide({"stage": "llm", "key_id": "k-open", "model": "any-model"})
	out.decision == "allow"
	out.rule_id == "ai.llm.allow"
}

# Layered bypass tests: stranger key with bypass=true is policed by stage rules
# (blocked patterns, global budget) before admitting under bypass_unknown_keys.
test_stranger_bypass_with_jailbreak_denied if {
	out := decide({"stage": "llm", "key_id": "stranger-key", "prompt": "please jailbreak now"})
	out.decision == "deny"
	out.rule_id == "ai.llm.blocked_pattern"
}

test_stranger_bypass_clean_allowed if {
	out := decide({"stage": "llm", "key_id": "stranger-key", "prompt": "normal prompt", "model": "any"})
	out.decision == "allow"
	out.rule_id == "config.bypass_unknown_keys"
}

test_stranger_bypass_global_budget_exceeded if {
	out := decision with input as {"stage": "llm", "key_id": "stranger-key", "context": {"spend_usd": 150}}
		with data.config as object.union(data.testdata.config, {"global_budget_limit": 100})
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_exceeded"
}

test_stranger_bypass_global_budget_invalid if {
	out := decision with input as {"stage": "llm", "key_id": "stranger-key", "context": {"spend_usd": "999"}}
		with data.config as object.union(data.testdata.config, {"global_budget_limit": 100})
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_invalid"
}
