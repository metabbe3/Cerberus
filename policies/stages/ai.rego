package stages.ai

# AI stage verdicts: llm (pre-call) and tool (pre-exec), dispatched by the core
# gate. Deny checks run in a fixed priority order per stage (else-chains, so a
# request hit by two rules always reports the first one's stable rule_id).

import rego.v1

import data.gateway.authz
import data.shield.prod

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
	"rule_id": "ai.llm.oversized_uninspected",
	"reason": sprintf("prompt size %d bytes exceeds 64KB uninspected limit", [total_prompt_bytes]),
} if {
	llm_oversized
} else := {
	"decision": "deny",
	"rule_id": "ai.llm.unscanned",
	"reason": sprintf("prompt size %d bytes exceeds 4KB without injection scan in context", [total_prompt_bytes]),
} if {
	llm_unscanned
} else := {
	"decision": "deny",
	"rule_id": "ai.llm.budget_invalid",
	"reason": budget_invalid_reason,
} if {
	budget_invalid
} else := {
	"decision": "deny",
	"rule_id": "ai.llm.budget_spent_exceeded",
	"reason": sprintf("cumulative spend $%v exceeds budget limit $%v", [input.context.budget_spent_usd, tightest_budget_limit]),
} if {
	budget_spent_exceeded
} else := {
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
	"decision": "allow",
	"rule_id": "shield.exempt",
	"reason": "shield_exempt",
} if {
	llm_target_prod
	prod.exempt(input.key_id)
} else := {
	"decision": "deny",
	"rule_id": "shield.prod.llm_target",
	"reason": llm_target_reason,
} if {
	llm_target_prod
	not agent_has_prod_access
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

# ---------- prompt size & scanner inspection checks (MC-P0 Akar 4) ----------

prompt_len := count(input.prompt) if {
	is_string(input.prompt)
} else := 0

system_string_len := count(input.system) if {
	is_string(input.system)
} else := 0

system_walk_lens := [count(v) |
	input.system
	not is_string(input.system)
	[_, v] := walk(input.system)
	is_string(v)
]

msg_string_lens := [count(m.content) |
	some m in input.messages
	is_string(m.content)
]

msg_walk_lens := [count(v) |
	some m in input.messages
	not is_string(m.content)
	[_, v] := walk(m.content)
	is_string(v)
]

total_prompt_bytes := (((prompt_len + system_string_len) + sum(system_walk_lens)) + sum(msg_string_lens)) + sum(msg_walk_lens)

llm_oversized if total_prompt_bytes > 65536

injection_scanned if {
	is_object(input.context)
	some k in ["scanner", "scan", "scan_result", "scanner_result", "injection_scan", "injection_scanned", "scanned"]
	v := object.get(input.context, k, null)
	v != null
	v != false
	v != ""
}

llm_unscanned if {
	total_prompt_bytes > 4096
	not injection_scanned
}

# Budget limits: agent, registered team, and optional global budget limit.
budget_limits contains authz.agent.budget_limit if is_number(authz.agent.budget_limit)

budget_limits contains authz.team.budget_limit if is_number(authz.team.budget_limit)

budget_limits contains data.config.global_budget_limit if is_number(data.config.global_budget_limit)

tightest_budget_limit := min(budget_limits) if count(budget_limits) > 0

# The tightest budget limit the call exceeds: undefined when within all limits.
over_budget_limit := min(exceeded_limits) if count(exceeded_limits) > 0

exceeded_limits contains limit if {
	some limit in budget_limits
	is_number(input.context.spend_usd)
	input.context.spend_usd > limit
}

budget_invalid if {
	count(budget_limits) > 0
	_ := input.context.spend_usd
	not is_number(input.context.spend_usd)
}

budget_invalid if {
	count(budget_limits) > 0
	_ := input.context.budget_spent_usd
	not is_number(input.context.budget_spent_usd)
}

budget_invalid if {
	count(budget_limits) > 0
	_ := input.context
	not is_object(input.context)
}

budget_invalid_reason := sprintf("spend_usd %q is not a number", [input.context.spend_usd]) if {
	_ := input.context.spend_usd
	not is_number(input.context.spend_usd)
} else := sprintf("budget_spent_usd %q is not a number", [input.context.budget_spent_usd]) if {
	_ := input.context.budget_spent_usd
	not is_number(input.context.budget_spent_usd)
} else := "budget context is invalid"

budget_spent_exceeded if {
	count(budget_limits) > 0
	is_number(input.context.budget_spent_usd)
	input.context.budget_spent_usd > tightest_budget_limit
}

blocked_prompt if {
	is_string(input.prompt)
	some pattern in data.blocked_patterns
	contains(authz.normalize(input.prompt), authz.normalize(pattern))
}

# Scan input.system (string or array of blocks {type, text})
blocked_prompt if {
	is_string(input.system)
	some pattern in data.blocked_patterns
	contains(authz.normalize(input.system), authz.normalize(pattern))
}

blocked_prompt if {
	not is_string(input.system)
	some pattern in data.blocked_patterns
	[_, val] := walk(input.system)
	is_string(val)
	contains(authz.normalize(val), authz.normalize(pattern))
}

# Deep scan: injection payload can hide in any message content (incl. string,
# array of blocks {type, text}, OCR'd image text, pasted transcript, or tool result) — check
# every string value in input.messages and input.args, not just input.prompt.
blocked_prompt if {
	some pattern in data.blocked_patterns
	some msg in input.messages
	is_string(msg.content)
	contains(authz.normalize(msg.content), authz.normalize(pattern))
}

blocked_prompt if {
	some pattern in data.blocked_patterns
	some msg in input.messages
	not is_string(msg.content)
	[_, val] := walk(msg.content)
	is_string(val)
	contains(authz.normalize(val), authz.normalize(pattern))
}

blocked_prompt if {
	some pattern in data.blocked_patterns
	some str in prod.all_arg_strings(input.args)
	contains(authz.normalize(str), authz.normalize(pattern))
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

# Glob support for allowed_models, mirroring allowed_tool_calls semantics:
# entry "*" allows everything; "glm-*" matches "glm-5.3-flash".
model_listed(models) if {
	some m in models
	not input.model in models
	is_string(m)
	contains(m, "*")
	glob.match(m, null, input.model)
}

# ---------- tool (pre-exec): restricted → not allowed → blocked pattern → argument constraints ----------

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
	"rule_id": "ai.tool.blocked_pattern",
	"reason": "tool call contains blocked pattern",
} if {
	tool_blocked_pattern
} else := {
	"decision": "allow",
	"rule_id": "shield.exempt",
	"reason": "shield_exempt",
} if {
	shield_triggered
	prod.exempt(input.key_id)
} else := {
	"decision": "deny",
	"rule_id": "shield.container.protected",
	"reason": shield_container_reason,
} if {
	shield_container_protected
} else := {
	"decision": "deny",
	"rule_id": "shield.cmd.dangerous",
	"reason": shield_cmd_reason,
} if {
	shield_cmd_dangerous
} else := {
	"decision": "deny",
	"rule_id": "shield.prod.ip_blocked",
	"reason": shield_ip_reason,
} if {
	shield_prod_ip_blocked
} else := {
	"decision": "deny",
	"rule_id": "shield.prod.no_access",
	"reason": shield_no_access_reason,
} if {
	shield_prod_no_access
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

tool_blocked_pattern if {
	some pattern in data.blocked_patterns
	contains(authz.normalize(tool_call), authz.normalize(pattern))
}

tool_blocked_pattern if {
	is_string(input.prompt)
	some pattern in data.blocked_patterns
	contains(authz.normalize(input.prompt), authz.normalize(pattern))
}

tool_blocked_pattern if {
	some str in prod.all_arg_strings(input.args)
	some pattern in data.blocked_patterns
	contains(authz.normalize(str), authz.normalize(pattern))
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

# ---------- prod shield helpers (P0.3, P0.4, P0.5) ----------

agent_has_prod_access if authz.agent_has_prod_access

# LLM prod shield target checks
target_host := object.get(object.get(input, "context", {}), "target_host", "")

llm_target_prod if {
	target_host != ""
	prod.prod_ip(target_host)
}

llm_target_prod if {
	target_host != ""
	prod.touches_prod(target_host)
}

llm_target_prod if {
	is_string(input.prompt)
	prod.touches_prod(input.prompt)
}

llm_target_prod if {
	is_string(input.prompt)
	prod.prod_ip(input.prompt)
}

llm_target_reason := sprintf("target host %q is a protected production resource", [target_host]) if {
	target_host != ""
} else := "prompt targets protected production resource"

# Tool prod shield checks
shield_strings := array.concat([tool_call], prod.all_arg_strings(object.get(input, "args", {})))

# Protected container check
shield_container_protected if {
	is_container_operation
	is_container_protected_target
}

is_container_operation if prod.is_container_delete_call(tool_call)

is_container_operation if {
	some arg_name in ["cmd", "command", "script"]
	cmd_val := object.get(object.get(input, "args", {}), arg_name, "")
	prod.is_container_delete_call(cmd_val)
}

is_container_protected_target if {
	some str in shield_strings
	prod.touches_protected_container(str)
}

first_protected_container_hit := [str |
	some str in shield_strings
	prod.touches_protected_container(str)
][0]

shield_container_reason := sprintf("container %s is protected", [first_protected_container_hit]) if {
	first_protected_container_hit
} else := "container is protected"

# Dangerous command patterns check
shield_cmd_dangerous if {
	count(dangerous_cmd_hits) > 0
}

dangerous_cmd_hits contains id if {
	some arg_name in ["cmd", "command", "script"]
	cmd_val := object.get(object.get(input, "args", {}), arg_name, "")
	some id in prod.dangerous_cmd(cmd_val)
}

dangerous_cmd_hits contains id if {
	some id in prod.dangerous_cmd(tool_call)
}

dangerous_cmd_hits contains id if {
	some str in prod.all_arg_strings(object.get(input, "args", {}))
	some id in prod.dangerous_cmd(str)
}

first_dangerous_pattern_id := sort(dangerous_cmd_hits)[0] if count(dangerous_cmd_hits) > 0

shield_cmd_reason := sprintf("command matches dangerous pattern %q", [first_dangerous_pattern_id]) if {
	first_dangerous_pattern_id
} else := "command matches dangerous pattern"

# Prod IP blocked check
shield_prod_ip_blocked if {
	not agent_has_prod_access
	count(prod_ip_hits) > 0
}

prod_ip_hits contains str if {
	some str in prod.all_arg_strings(object.get(input, "args", {}))
	prod.prod_ip(str)
}

prod_ip_hits contains tool_call if {
	prod.prod_ip(tool_call)
}

first_prod_ip_hit := sort(prod_ip_hits)[0] if count(prod_ip_hits) > 0

shield_ip_reason := sprintf("access to prod IP in %q blocked", [first_prod_ip_hit]) if {
	first_prod_ip_hit
} else := "access to prod IP blocked"

# Touches prod without prod access
shield_prod_no_access if {
	not agent_has_prod_access
	count(prod_touch_hits) > 0
}

prod_touch_hits contains str if {
	some str in prod.all_arg_strings(object.get(input, "args", {}))
	prod.touches_prod(str)
}

prod_touch_hits contains tool_call if {
	prod.touches_prod(tool_call)
}

first_prod_touch_hit := sort(prod_touch_hits)[0] if count(prod_touch_hits) > 0

shield_no_access_reason := sprintf("access to prod resource %q denied without prod_access", [first_prod_touch_hit]) if {
	first_prod_touch_hit
} else := "access to prod resource denied without prod_access"

# Aggregate shield trigger flag for exempt key evaluation
shield_triggered if shield_container_protected

shield_triggered if shield_cmd_dangerous

shield_triggered if shield_prod_ip_blocked

shield_triggered if shield_prod_no_access
