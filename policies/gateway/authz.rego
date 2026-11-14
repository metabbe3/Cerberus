package gateway.authz

# Cerberus core gate. Owns: key gate, dynamic stage dispatch, default deny.
# Per-stage verdicts live in policies/stages/<stage>.rego and are dispatched
# through data.stages[input.stage].decision — the engine evaluates exactly
# data.gateway.authz.decision (see ADR-0002).

import rego.v1

default decision := {"decision": "deny", "rule_id": "internal.default", "reason": "no decision produced"}

# ---------- helpers (consumed by stage packages via data.gateway.authz.*) ----------

agent := data.agents[input.key_id]

team := data.teams[agent.team_id]

# normalize(s): strip zero-width chars and word-joiners (\u200b\u200c\u200d\u2060\u00ad\ufeff),
# map Latin-lookalike Cyrillic homoglyphs (a,e,o,p,c,x,y,г->r), collapse whitespace, lower.
normalize(s) := out if {
	is_string(s)
	s0 := regex.replace(s, "[\u200b\u200c\u200d\u2060\u00ad\ufeff]", "")
	s1 := regex.replace(s0, "[аА]", "a")
	s2 := regex.replace(s1, "[еЕ]", "e")
	s3 := regex.replace(s2, "[оО]", "o")
	s4 := regex.replace(s3, "[рР]", "p")
	s5 := regex.replace(s4, "[сС]", "c")
	s6 := regex.replace(s5, "[хХ]", "x")
	s7 := regex.replace(s6, "[уУ]", "y")
	s8 := regex.replace(s7, "[гГ]", "r")
	s9 := trim_space(regex.replace(s8, `\s+`, " "))
	out := lower(s9)
} else := s
call_matches_pattern(pattern, name) if {
	contains(pattern, "*")
	glob.match(lower(pattern), [], lower(name))
}

call_matches_pattern(pattern, name) if {
	not contains(pattern, "*")
	lower(name) == lower(pattern)
}
# Host matching: exact match OR wildcard suffix (*.domain) without userinfo and host != suffix.
host_matches("*", _) if true

host_matches(pattern, h) if {
	pattern != "*"
	not startswith(pattern, "*.")
	not contains(h, "@")
	lower(h) == lower(pattern)
}

host_matches(pattern, h) if {
	startswith(pattern, "*.")
	not contains(h, "@")
	suffix := substring(pattern, 1, -1)
	lower(h) != lower(suffix)
	endswith(lower(h), lower(suffix))
}

# Common pattern matcher: glob with ":" separator, glob with empty delimiter, or case-insensitive exact.
pattern_matches(pattern, target) if {
	contains(pattern, "*")
	glob.match(lower(pattern), [":"], lower(target))
}

pattern_matches(pattern, target) if {
	contains(pattern, "*")
	glob.match(lower(pattern), [], lower(target))
}

pattern_matches(pattern, target) if {
	endswith(pattern, "*")
	prefix := trim_suffix(pattern, "*")
	startswith(lower(normalize(target)), lower(normalize(prefix)))
}

pattern_matches(pattern, target) if {
	not contains(pattern, "*")
	lower(normalize(target)) == lower(normalize(pattern))
}
# Prod access flag for the resolved agent
agent_has_prod_access if agent.prod_access == true

# ---------- stage dispatch ----------

# A stage is known if a stage package under data.stages exists for it.
# We exclude "ai" since stages.ai is the shared implementation module for llm and tool.
known_stages contains s if {
	some s, _ in data.stages
	s != "ai"
}

# Dynamic alias: stage packages named stages.custom_<name> also register as custom:<name>
known_stages contains sprintf("custom:%s", [trim_prefix(s, "custom_")]) if {
	some s, _ in data.stages
	startswith(s, "custom_")
}

stage_key := replace(input.stage, ":", "_") if {
	startswith(input.stage, "custom:")
} else := input.stage

stage_decision := data.stages[stage_key].decision if {
	stage_is_known
}

stage_decision := {
	"decision": "deny",
	"rule_id": "internal.unknown_stage",
	"reason": sprintf("unknown stage %q", [object.get(input, "stage", "")]),
} if {
	not stage_is_known
}

# Helper form: `not input.stage in known_stages` would not fire when the stage
# key is missing entirely (a `not x in y` expression over an undefined x is
# itself undefined, not true).
stage_is_known if {
	input.stage in known_stages
}

# ---------- kill switch ----------

kill_switch_active if data.config.kill_switch.global == true

kill_switch_active if {
	some k, active in data.config.kill_switch.keys
	k == input.key_id
	active == true
}

kill_switch_verdict := {
	"decision": "deny",
	"rule_id": "ops.kill_switch",
	"reason": "global kill switch active",
} if {
	data.config.kill_switch.global == true
}

kill_switch_verdict := {
	"decision": "deny",
	"rule_id": "ops.kill_switch",
	"reason": sprintf("kill switch active for key %q", [input.key_id]),
} if {
	not data.config.kill_switch.global == true
	some k, active in data.config.kill_switch.keys
	k == input.key_id
	active == true
}

# ---------- core decision ----------
#
# Gate order: kill switch → stage gate → key gate. An active kill switch
# denies immediately. Otherwise an unknown stage fails closed whatever the
# key — a typo'd or not-yet-implemented stage must never ride the key gates
# (in particular config.bypass_unknown_keys). A known stage is then gated by
# the key gate → stage verdict.
#
# For unregistered keys with bypass_unknown_keys=true, requests are policed:
# if the stage policy produces a deny (e.g. blocked patterns, budget limits),
# that deny stands. If the stage policy allows, it is admitted under the
# rule_id config.bypass_unknown_keys.

decision := kill_switch_verdict if {
	kill_switch_active
}

decision := stage_decision if {
	not kill_switch_active
	not stage_is_known
}

# Bypass keys enabled: stage policy checks stand; if allowed, return bypass rule_id.
decision := stage_decision if {
	not kill_switch_active
	stage_is_known
	not agent
	bypass_keys_enabled
	stage_decision.decision == "deny"
}

decision := allow_bypass_keys if {
	not kill_switch_active
	stage_is_known
	not agent
	bypass_keys_enabled
	stage_decision.decision == "allow"
}

# Anything but a literal boolean true fails closed: "true", 1, null or a
# missing flag must never match neither rule (→ internal.default) nor bypass.
decision := deny_unknown_key if {
	not kill_switch_active
	stage_is_known
	not agent
	not bypass_keys_enabled
}

bypass_keys_enabled if data.config.bypass_unknown_keys == true

decision := stage_decision if {
	not kill_switch_active
	stage_is_known
	agent
}

allow_bypass_keys := {
	"decision": "allow",
	"rule_id": "config.bypass_unknown_keys",
	"reason": "key not registered; bypass_unknown_keys=true (fail-open onboarding)",
}

deny_unknown_key := {
	"decision": "deny",
	"rule_id": "authz.unknown_key",
	"reason": "key not registered and bypass_unknown_keys=false (fail-closed)",
}
