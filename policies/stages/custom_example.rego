package stages.custom_example

# Custom stage template policy (example: terraform / infrastructure lifecycle gate).
# Stage inputs can be dispatched via stage: "custom:example" or stage: "custom_example".
# Demonstrates allowlisting read/plan operations and requiring explicit approval
# for destructive or state-modifying operations (e.g. apply, destroy).

import rego.v1

decision := custom_decision

args := object.get(input, "args", {})

action := lower(object.get(args, "action", object.get(input, "action", "")))

resource := object.get(args, "resource", object.get(input, "resource", ""))

agent := object.get(data.agents, input.key_id, {})

# Valid known actions for this custom stage
valid_actions := ["plan", "apply", "refresh", "show", "output"]

# Approved check: either via args.approved == true, non-empty args.approval_id, or agent privilege
is_approved if object.get(args, "approved", false) == true

is_approved if {
	approval_id := object.get(args, "approval_id", "")
	is_string(approval_id)
	approval_id != ""
}

is_approved if agent.allow_terraform_apply == true

is_approved if agent.prod_access == true

# ---------- custom decision else-chain ----------

custom_decision := {
	"decision": "deny",
	"rule_id": "custom.example.action_invalid",
	"reason": sprintf("action %q is invalid for custom stage (allowed: plan, apply, refresh, show, output)", [action]),
} if {
	not action in valid_actions
} else := {
	"decision": "deny",
	"rule_id": "custom.example.apply_without_approval",
	"reason": sprintf("custom action %q on %q requires prior approval or elevated privilege", [action, resource]),
} if {
	action == "apply"
	not is_approved
} else := {
	"decision": "allow",
	"rule_id": "custom.example.allow_apply",
	"reason": sprintf("custom action %q on %q approved", [action, resource]),
} if {
	action == "apply"
	is_approved
} else := {
	"decision": "allow",
	"rule_id": "custom.example.allow_plan",
	"reason": sprintf("custom action %q on %q permitted", [action, resource]),
} if {
	action == "plan"
} else := {
	"decision": "allow",
	"rule_id": "custom.example.allow_read",
	"reason": sprintf("custom read-only action %q permitted", [action]),
}
