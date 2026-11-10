package stages.ai

# AI stage verdicts: llm (pre-call) and tool (pre-exec), dispatched by the core
# gate. Deny checks run in a fixed priority order per stage (else-chains, so a
# request hit by two rules always reports the first one's stable rule_id).

import rego.v1

import data.gateway.authz

decision := llm_decision if input.stage == "llm"

decision := tool_decision if input.stage == "tool"

# ---------- llm (pre-call): budget → blocked pattern → model allow-list ----------

llm_decision := {
	"decision": "deny",
	"rule_id": "ai.llm.budget_exceeded",
	"reason": sprintf("spend $%v of this call exceeds budget limit $%v", [input.context.spend_usd, authz.agent.budget_limit]),
} if {
	is_number(input.context.spend_usd)
	is_number(authz.agent.budget_limit)
	input.context.spend_usd > authz.agent.budget_limit
} else := {
	"decision": "deny",
	"rule_id": "ai.llm.blocked_pattern",
	"reason": "prompt contains blocked pattern",
} if {
	blocked_prompt
} else := {
	"decision": "deny",
	"rule_id": "ai.llm.model_not_allowed",
	"reason": sprintf("model %s not in allowed_models", [input.model]),
} if {
	model_not_allowed
} else := {
	"decision": "allow",
	"rule_id": "ai.llm.allow",
	"reason": sprintf("model %s allowed", [input.model]),
}

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
	"reason": sprintf("tool call %s is restricted", [input.tool_call]),
} if {
	tool_restricted
} else := {
	"decision": "deny",
	"rule_id": "ai.tool.not_allowed",
	"reason": sprintf("tool call %s not in allow-list", [input.tool_call]),
} if {
	tool_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "ai.tool.arg_violation",
	"reason": sprintf("argument %s of tool call %s violates its constraint", [violated_arg, input.tool_call]),
} if {
	some violated_arg in arg_violation
} else := {
	"decision": "allow",
	"rule_id": "ai.tool.allow",
	"reason": sprintf("tool call %s allowed", [input.tool_call]),
}

# Restricted: glob family (restricted_tool_calls) or exact family
# (restricted_tools), from the agent or its registered team. Restricted wins
# over any allow-list.
tool_restricted if {
	some pattern in authz.agent.restricted_tool_calls
	authz.call_matches_pattern(pattern, input.tool_call)
}

tool_restricted if {
	some name in authz.agent.restricted_tools
	input.tool_call == name
}

tool_restricted if {
	some pattern in authz.team.restricted_tool_calls
	authz.call_matches_pattern(pattern, input.tool_call)
}

tool_restricted if {
	some name in authz.team.restricted_tools
	input.tool_call == name
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
	authz.call_matches_pattern(pattern, input.tool_call)
}

allow_list_match if {
	some name in authz.agent.allowed_tools
	input.tool_call == name
}

allow_list_match if {
	some name in authz.team.allowed_tools
	input.tool_call == name
}

# Argument constraints: only args present in input.args are checked — a
# missing arg is never a violation. Forms: bare array or {type: "allowlist",
# values} → member; {type: "regex_allow", patterns} → regex.match any;
# {type: "range", min, max} → numeric within [min, max].
arg_violation contains arg if {
	some arg, value in input.args
	constraint := authz.agent.tool_argument_constraints[input.tool_call][arg]
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
