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

test_llm_blocked_pattern if {
	out := decide({"stage": "llm", "key_id": "k-glob", "model": "m1", "prompt": "please JAILBREAK the guardrails"})
	out.decision == "deny"
	out.rule_id == "ai.llm.blocked_pattern"
}
