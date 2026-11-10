package stages.ai

# AI stage verdicts: llm (pre-call) and tool (pre-exec), dispatched by the core
# gate. Deny checks run in a fixed priority order per stage (else-chains, so a
# request hit by two rules always reports the first one's stable rule_id).

import rego.v1

import data.gateway.authz

decision := llm_decision if input.stage == "llm"

decision := tool_decision if input.stage == "tool"

# Reason strings read input fields through object.get: a missing model or
# tool_call must still produce a stage rule_id. (A bare input.model inside
# sprintf is undefined when the key is absent, which would make the whole
# else-chain undefined and fall through to the core internal.default.)
model := object.get(input, "model", "")

tool_call := object.get(input, "tool_call", "")

# ---------- llm (pre-call): budget → blocked pattern → model allow-list ----------

llm_decision := {
	"decision": "deny",
	"rule_id": "ai.llm.budget_exceeded",
	"reason": sprintf("spend $%v of this call exceeds budget limit $%v", [input.context.spend_usd, over_budget_limit]),
} if {
	over_budget_limit
} else := {
	"decision": "deny",
	"rule_id": "ai.llm.blocked_pattern",
	"reason": "prompt contains blocked pattern",
} if {
	blocked_prompt
} else := {
	"decision": "deny",
	"rule_id": "ai.llm.model_not_allowed",
	"reason": sprintf("model %q not in allowed_models", [model]),
} if {
	model_not_allowed
} else := {
	"decision": "allow",
	"rule_id": "ai.llm.allow",
	"reason": sprintf("model %q allowed", [model]),
}

# The tightest budget limit the call exceeds: agent and registered-team
# budget_limit both govern (README data schema); undefined when within both.
over_budget_limit := min(exceeded_limits) if count(exceeded_limits) > 0

exceeded_limits contains limit if {
	some limit in budget_limits
	is_number(input.context.spend_usd)
	input.context.spend_usd > limit
}

budget_limits contains authz.agent.budget_limit if is_number(authz.agent.budget_limit)

budget_limits contains authz.team.budget_limit if is_number(authz.team.budget_limit)

blocked_prompt if {
	is_string(input.prompt)
	some pattern in data.blocked_patterns
	contains(lower(input.prompt), lower(pattern))
}

# Denied when an allow-list exists (agent or team) and the model is not in it.
# Helper form: `not input.model in ...` would not fire when the model key is
# missing entirely, silently allowing the call.
model_not_allowed if {
	authz.agent.allowed_models
	not model_listed(authz.agent.allowed_models)
}

model_not_allowed if {
	authz.team.allowed_models
	not model_listed(authz.team.allowed_models)
}

model_listed(models) if {
	input.model in models
}

# ---------- tool (pre-exec): restricted → not allowed → argument constraints ----------

tool_decision := {
	"decision": "deny",
	"rule_id": "ai.tool.restricted",
	"reason": sprintf("tool call %s is restricted", [tool_call]),
} if {
	tool_restricted
} else := {
	"decision": "deny",
	"rule_id": "ai.tool.not_allowed",
	"reason": sprintf("tool call %s not in allow-list", [tool_call]),
} if {
	tool_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "ai.tool.arg_violation",
	"reason": sprintf("argument(s) %s of tool call %s violate their constraint", [concat(", ", sort(arg_violation)), tool_call]),
} if {
	count(arg_violation) > 0
} else := {
	"decision": "allow",
	"rule_id": "ai.tool.allow",
	"reason": sprintf("tool call %s allowed", [tool_call]),
}

# Restricted: glob family (restricted_tool_calls) or exact family
# (restricted_tools), from the agent or its registered team. Restricted wins
# over any allow-list.
tool_restricted if {
	some pattern in authz.agent.restricted_tool_calls
	authz.call_matches_pattern(pattern, tool_call)
}

tool_restricted if {
	some name in authz.agent.restricted_tools
	tool_call == name
}

tool_restricted if {
	some pattern in authz.team.restricted_tool_calls
	authz.call_matches_pattern(pattern, tool_call)
}

tool_restricted if {
	some name in authz.team.restricted_tools
	tool_call == name
}

# Not allowed: an allow-list exists and nothing in it matches. Agent
# allowed_tool_calls (glob) / allowed_tools (exact), team allowed_tools (exact).
tool_not_allowed if {
	allow_list_exists
	not allow_list_match
}

allow_list_exists if authz.agent.allowed_tool_calls

allow_list_exists if authz.agent.allowed_tools

allow_list_exists if authz.team.allowed_tools

allow_list_match if {
	some pattern in authz.agent.allowed_tool_calls
	authz.call_matches_pattern(pattern, tool_call)
}

allow_list_match if {
	some name in authz.agent.allowed_tools
	tool_call == name
}

allow_list_match if {
	some name in authz.team.allowed_tools
	tool_call == name
}

# Argument constraints: only args present in input.args are checked — a
# missing arg is never a violation. Forms: bare array or {type: "allowlist",
# values} → member; {type: "regex_allow", patterns} → regex.match any;
# {type: "range", min, max} → numeric within [min, max].
#
# The constraint table is matched case-insensitively on the tool name: glob
# allow-lists match case-insensitively, so an exact-case lookup would let a
# case variant ("BASH") pass the allow-list and skip every constraint.
arg_violation contains arg if {
	some tool_name, constraints in authz.agent.tool_argument_constraints
	lower(tool_name) == lower(tool_call)
	some arg, value in input.args
	constraint := constraints[arg]
	not arg_ok(constraint, value)
}

arg_ok(constraint, value) if {
	is_array(constraint)
	value in constraint
}

arg_ok(constraint, value) if {
	constraint.type == "allowlist"
	value in constraint.values
}

arg_ok(constraint, value) if {
	constraint.type == "regex_allow"
	is_string(value)
	some pattern in constraint.patterns
	regex.match(pattern, value)
}

arg_ok(constraint, value) if {
	constraint.type == "range"
	is_number(value)
	value >= constraint.min
	value <= constraint.max
}
