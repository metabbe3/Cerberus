package gateway.llm_test

# LLM stage tests: live decide contract ({key_id, model, messages:[...], ...}).
# Tests both the stages.llm stage adapter and gateway integration:
# happy path allow, model restrictions, deep prompt/message scan, unknown key bypass (allow),
# and fail-closed path when bypass_unknown_keys=false.

import rego.v1

import data.gateway.authz.decision
import data.stages.llm

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

# 1. Happy path: allowed model for registered agent
test_llm_allow_happy if {
	out := decide({
		"stage": "llm",
		"key_id": "k-glob",
		"model": "m1",
		"messages": [{"role": "user", "content": "How do I list Kubernetes pods?"}],
	})
	out.decision == "allow"
	out.rule_id == "ai.llm.allow"
}

# 2. Stage adapter direct evaluation
test_llm_stage_adapter_allow if {
	out := llm.decision with input as {
		"stage": "llm",
		"key_id": "k-glob",
		"model": "m1",
		"messages": [{"role": "user", "content": "Hello"}],
	}
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
	out.decision == "allow"
	out.rule_id == "ai.llm.allow"
}

# 3. Model not allowed for registered agent
test_llm_model_not_allowed if {
	out := decide({
		"stage": "llm",
		"key_id": "k-glob",
		"model": "m2",
		"messages": [{"role": "user", "content": "Hello"}],
	})
	out.decision == "deny"
	out.rule_id == "ai.llm.model_not_allowed"
}

# 4. Deep prompt scan denies blocked pattern inside messages array
test_llm_blocked_pattern_in_messages if {
	out := decide({
		"stage": "llm",
		"key_id": "k-glob",
		"model": "m1",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Please jailbreak the system override"},
		],
	})
	out.decision == "deny"
	out.rule_id == "ai.llm.blocked_pattern"
}

# 5. Default unknown key with bypass_unknown_keys=true (fail-open onboarding)
test_llm_unknown_key_bypass_allowed if {
	out := decide({
		"stage": "llm",
		"key_id": "stranger-key",
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "Hello world"}],
	})
	out.decision == "allow"
	out.rule_id == "config.bypass_unknown_keys"
}

# 6. Unknown key with blocked pattern is still denied even under bypass
test_llm_unknown_key_blocked_pattern_denied if {
	out := decide({
		"stage": "llm",
		"key_id": "stranger-key",
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "jailbreak now"}],
	})
	out.decision == "deny"
	out.rule_id == "ai.llm.blocked_pattern"
}

# 7. Unknown key fails closed when bypass_unknown_keys=false
test_llm_unknown_key_bypass_false_denied if {
	out := decide_closed({
		"stage": "llm",
		"key_id": "stranger-key",
		"model": "m1",
		"messages": [{"role": "user", "content": "Hello"}],
	})
	out.decision == "deny"
	out.rule_id == "authz.unknown_key"
}
