package stages.ai_test

# AI stage verdict tests: tool glob/exact lists, argument constraint forms,
# and llm model/budget/blocked-pattern checks — one test per rule_id.
#
# The fixture (policies/testdata/data.json) is loaded under data.testdata by
# `opa test policies/`; each query lifts its sections into the live paths.

import rego.v1

import data.stages.ai.decision

decide(inp) := out if {
	out := decision with input as inp
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
}

# ---------- tool ----------

test_tool_allow_glob if {
	out := decide({"stage": "tool", "key_id": "k-glob", "tool_call": "kubernetes_get_pods"})
	out.decision == "allow"
	out.rule_id == "ai.tool.allow"
}

test_tool_restricted_glob if {
	out := decide({"stage": "tool", "key_id": "k-glob", "tool_call": "kubernetes_delete_pod"})
	out.decision == "deny"
	out.rule_id == "ai.tool.restricted"
}

test_tool_not_allowed if {
	out := decide({"stage": "tool", "key_id": "k-glob", "tool_call": "read_file"})
	out.decision == "deny"
	out.rule_id == "ai.tool.not_allowed"
}

test_tool_arg_violation_regex_allow if {
	out := decide({"stage": "tool", "key_id": "k-exact", "tool_call": "bash", "args": {"cmd": "rm -rf /"}})
	out.decision == "deny"
	out.rule_id == "ai.tool.arg_violation"
}

test_tool_allow_all_constraints_pass if {
	out := decide({"stage": "tool", "key_id": "k-exact", "tool_call": "bash", "args": {"cmd": "ls -la", "timeout": 30, "env": "prod"}})
	out.decision == "allow"
	out.rule_id == "ai.tool.allow"
}

test_tool_arg_violation_range if {
	out := decide({"stage": "tool", "key_id": "k-exact", "tool_call": "bash", "args": {"timeout": 999}})
	out.decision == "deny"
	out.rule_id == "ai.tool.arg_violation"
}

test_tool_arg_violation_bare_array if {
	out := decide({"stage": "tool", "key_id": "k-exact", "tool_call": "bash", "args": {"env": "staging"}})
	out.decision == "deny"
	out.rule_id == "ai.tool.arg_violation"
}

test_tool_allow_open_agent if {
	out := decide({"stage": "tool", "key_id": "k-open", "tool_call": "anything_at_all"})
	out.decision == "allow"
	out.rule_id == "ai.tool.allow"
}

# ---------- llm ----------

test_llm_allow if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1"})
	out.decision == "allow"
	out.rule_id == "ai.llm.allow"
}

test_llm_model_not_allowed if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m2"})
	out.decision == "deny"
	out.rule_id == "ai.llm.model_not_allowed"
}

test_llm_budget_exceeded if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "context": {"spend_usd": 51}})
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_exceeded"
}

test_llm_budget_invalid_string if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "context": {"spend_usd": "999"}})
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_invalid"
}

test_llm_budget_exceeded_number if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "context": {"spend_usd": 999}})
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_exceeded"
}

test_llm_budget_spent_exceeded if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "context": {"budget_spent_usd": 51}})
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_spent_exceeded"
}

test_llm_budget_spent_within if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "context": {"budget_spent_usd": 49}})
	out.decision == "allow"
	out.rule_id == "ai.llm.allow"
}

test_llm_budget_spent_invalid_string if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "context": {"budget_spent_usd": "bad"}})
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_invalid"
}

test_tool_blocked_pattern if {
	out := decide({"stage": "tool", "key_id": "k-open", "tool_call": "jailbreak_detector"})
	out.decision == "deny"
	out.rule_id == "ai.tool.blocked_pattern"
}

test_llm_blocked_pattern if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "prompt": "please JAILBREAK the guardrails"})
	out.decision == "deny"
	out.rule_id == "ai.llm.blocked_pattern"
}

# ---------- regressions (Phase 1 review) ----------

# Two violated args in one call must still yield one decision, not an
# eval_conflict_error (which the engine maps to internal.eval_error).
test_tool_two_arg_violations_single_decision if {
	out := decide({"stage": "tool", "key_id": "k-exact", "tool_call": "bash", "args": {"cmd": "rm -rf /", "timeout": 999}})
	out.decision == "deny"
	out.rule_id == "ai.tool.arg_violation"
}

# A missing tool_call / model must reach a stage rule_id, never fall through to
# internal.default because a reason sprintf went undefined.
test_tool_missing_tool_call_not_allowed if {
	out := decide({"stage": "tool", "key_id": "k-glob"})
	out.decision == "deny"
	out.rule_id == "ai.tool.not_allowed"
}

test_tool_missing_tool_call_open_agent_allows if {
	out := decide({"stage": "tool", "key_id": "k-open"})
	out.rule_id == "ai.tool.allow"
}

test_llm_missing_model_not_allowed if {
	out := decide({"stage": "llm", "key_id": "k-glob"})
	out.decision == "deny"
	out.rule_id == "ai.llm.model_not_allowed"
}

test_llm_missing_model_open_agent_allows if {
	out := decide({"stage": "llm", "key_id": "k-open"})
	out.rule_id == "ai.llm.allow"
}

# A case variant of a constrained tool passes a case-insensitive glob allow-list,
# so its argument constraints must apply too (k-case allows "Shell*").
test_tool_case_variant_still_constrained if {
	out := decide({"stage": "tool", "key_id": "k-case", "tool_call": "SHELL_run", "args": {"cmd": "rm -rf /"}})
	out.decision == "deny"
	out.rule_id == "ai.tool.arg_violation"
}

test_tool_case_variant_constraint_passes if {
	out := decide({"stage": "tool", "key_id": "k-case", "tool_call": "SHELL_run", "args": {"cmd": "ls"}})
	out.rule_id == "ai.tool.allow"
}

# Exact restricted_tools family (agent) and team restricted lists.
test_tool_restricted_exact_agent if {
	out := decide({"stage": "tool", "key_id": "k-exact-deny", "tool_call": "execute_shell"})
	out.decision == "deny"
	out.rule_id == "ai.tool.restricted"
}

test_tool_restricted_exact_is_case_sensitive if {
	out := decide({"stage": "tool", "key_id": "k-exact-deny", "tool_call": "Execute_Shell"})
	out.rule_id == "ai.tool.allow"
}

test_tool_restricted_team_glob if {
	out := decide({"stage": "tool", "key_id": "k-team2", "tool_call": "kubectl_apply"})
	out.decision == "deny"
	out.rule_id == "ai.tool.restricted"
}

test_tool_restricted_team_exact if {
	out := decide({"stage": "tool", "key_id": "k-team2", "tool_call": "drop_table"})
	out.decision == "deny"
	out.rule_id == "ai.tool.restricted"
}

test_tool_team_allow_list_blocks if {
	out := decide({"stage": "tool", "key_id": "k-teamlist", "tool_call": "write_file"})
	out.decision == "deny"
	out.rule_id == "ai.tool.not_allowed"
}

test_tool_team_allow_list_permits if {
	out := decide({"stage": "tool", "key_id": "k-teamlist", "tool_call": "read"})
	out.rule_id == "ai.tool.allow"
}

# Team model allow-list applies when the agent has none.
test_llm_team_model_not_allowed if {
	out := decide({"stage": "llm", "key_id": "k-teamlist", "model": "m2"})
	out.decision == "deny"
	out.rule_id == "ai.llm.model_not_allowed"
}

# Team budget_limit is governed (README schema), checked alongside the agent's.
test_llm_team_budget_exceeded if {
	out := decide({"stage": "llm", "key_id": "k-teamlist", "model": "m1", "context": {"spend_usd": 101}})
	out.decision == "deny"
	out.rule_id == "ai.llm.budget_exceeded"
}

test_llm_team_budget_within if {
	out := decide({"stage": "llm", "key_id": "k-teamlist", "model": "m1", "context": {"spend_usd": 99}})
	out.rule_id == "ai.llm.allow"
}
