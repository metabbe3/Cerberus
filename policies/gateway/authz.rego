package gateway.authz

# GateOwl — authz policy v0.1 (design draft)
# Evaluasi DUA入口: input.stage == "llm" (pre-call) | input.stage == "tool" (pre-exec).
#
# PRINSIP (owner):
# - Governance per-key & per-team INDEPENDEN: key di data.agents dipolisi key_id saja.
# - Polisi yang DIPANGGIL (tool_calls), bukan yang diiklankan (input.tools).
# - bypass_* = fail-open utk yang belum terdaftar (onboarding); setelah false = fail-closed.

import rego.v1

default decision := {"decision": "deny", "reason": "no decision produced", "rule_id": "internal.default"}

# ---------- helper: agent lookup ----------
agent := data.agents[input.key_id] if data.agents[input.key_id]

key_registered := true if { agent }

# ---------- helper: glob matching ----------
# prefix-glob: "kubernetes*" ; substring: "delete" (case-insensitive)
call_matches_pattern(pattern, tool_name) if {
	endswith(pattern, "*")
	prefix := trim_suffix(pattern, "*")
	startswith(lower(tool_name), lower(prefix))
}

call_matches_pattern(pattern, tool_name) if {
	not endswith(pattern, "*")
	contains(lower(tool_name), lower(pattern))
}

tool_call_allowed(tool_name) if {
	pattern := agent.allowed_tool_calls[_]
	call_matches_pattern(pattern, tool_name)
}

tool_call_allowed(tool_name) if {
	not agent.allowed_tool_calls
	not agent.restricted_tool_calls
}

tool_call_denied(tool_name) if {
	pattern := agent.restricted_tool_calls[_]
	call_matches_pattern(pattern, tool_name)
}

# ---------- STAGE: tool (pre-exec) ----------
decision := {
	"decision": "allow",
	"rule_id": "agent.toolcall.allow",
	"reason": sprintf("tool call %s allowed for %s", [input.tool_call, agent.name]),
} if {
	input.stage == "tool"
	key_registered
	not tool_call_denied(input.tool_call)
	# kalau ada allowed_tool_calls → harus match; kalau tidak ada → bebas kecuali denied
	tool_call_allowed(input.tool_call)
}

decision := {
	"decision": "deny",
	"rule_id": "agent.toolcall.restricted",
	"reason": sprintf("tool call %s is restricted for %s", [input.tool_call, agent.name]),
} if {
	input.stage == "tool"
	key_registered
	tool_call_denied(input.tool_call)
}

# key tidak terdaftar
decision := {
	"decision": "allow",
	"rule_id": "config.bypass_unknown_keys",
	"reason": "key not registered; bypass_unknown_keys=true (fail-open onboarding)",
} if {
	input.stage == "tool"
	not key_registered
	data.config.bypass_unknown_keys == true
}

decision := {
	"decision": "deny",
	"rule_id": "config.unknown_key_closed",
	"reason": "key not registered and bypass_unknown_keys=false (fail-closed)",
} if {
	input.stage == "tool"
	not key_registered
	data.config.bypass_unknown_keys != true
}

# ---------- STAGE: llm (pre-call) ----------
decision := {
	"decision": "allow",
	"rule_id": "agent.llm.allow",
	"reason": sprintf("model %s allowed for %s", [input.model, agent.name]),
} if {
	input.stage == "llm"
	key_registered
	input.model in agent.allowed_models
	not blocked_prompt
}

blocked_prompt if {
	some p in data.blocked_patterns
	contains(lower(input.prompt), lower(p))
}

decision := {
	"decision": "deny",
	"rule_id": "agent.llm.blocked_pattern",
	"reason": "prompt contains blocked pattern",
} if {
	input.stage == "llm"
	key_registered
	blocked_prompt
}
