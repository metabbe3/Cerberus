package gateway.authz

# Cerberus core gate. Owns: key gate, stage dispatch, default deny.
# Per-stage verdicts live in policies/stages/<stage>.rego and are dispatched
# through data.stages.<stage>.decision — the engine evaluates exactly
# data.gateway.authz.decision (see ADR-0002).

import rego.v1

default decision := {"decision": "deny", "rule_id": "internal.default", "reason": "no decision produced"}

# ---------- helpers (consumed by stage packages via data.gateway.authz.*) ----------

agent := data.agents[input.key_id]

team := data.teams[agent.team_id]

# Glob semantics: trailing "*" = case-insensitive prefix; otherwise
# case-insensitive substring.
call_matches_pattern(pattern, name) if {
	endswith(pattern, "*")
	prefix := trim_suffix(pattern, "*")
	startswith(lower(name), lower(prefix))
}

call_matches_pattern(pattern, name) if {
	not endswith(pattern, "*")
	contains(lower(name), lower(pattern))
}

# ---------- stage dispatch ----------

known_stages := {"llm", "tool"}

stage_decision := data.stages.ai.decision if {
	input.stage in known_stages
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

# ---------- core decision ----------
#
# Gate order: key gate → stage verdict. A registered key is governed by its own
# entry alone (data/prod.json: "policed by key_id alone"): its team never blocks
# the request — team-level lists apply only when the team is registered. The
# config.bypass_unknown_teams / config.unknown_team_closed rule IDs stay
# reserved for a future "require team registration" mode.

decision := allow_bypass_keys if {
	not agent
	data.config.bypass_unknown_keys == true
}

decision := deny_unknown_key if {
	not agent
	not data.config.bypass_unknown_keys
}

decision := stage_decision if {
	agent
}

allow_bypass_keys := {
	"decision": "allow",
	"rule_id": "config.bypass_unknown_keys",
	"reason": "key not registered; bypass_unknown_keys=true (fail-open onboarding)",
}

deny_unknown_key := {
	"decision": "deny",
	"rule_id": "config.unknown_key_closed",
	"reason": "key not registered and bypass_unknown_keys=false (fail-closed)",
}
