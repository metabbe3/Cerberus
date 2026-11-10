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

test_registered_key_llm_dispatch if {
	out := decide({"stage": "llm", "key_id": "k-open", "model": "any-model"})
	out.decision == "allow"
	out.rule_id == "ai.llm.allow"
}
