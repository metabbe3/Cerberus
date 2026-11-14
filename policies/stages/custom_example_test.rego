package gateway.custom_example_test

# Custom stage tests: verifies dispatch via stage: "custom:example",
# allowlist of plan, denial of unapproved apply, approval bypass checks, and invalid actions.

import rego.v1

import data.gateway.authz.decision

fixture_agents := {
	"k-custom-operator": {
		"name": "custom-operator-agent",
		"allow_terraform_apply": false,
		"prod_access": false,
	},
	"k-custom-admin": {
		"name": "custom-admin-agent",
		"allow_terraform_apply": true,
		"prod_access": false,
	},
	"k-custom-prod": {
		"name": "custom-prod-agent",
		"prod_access": true,
	},
}

decide(inp) := out if {
	out := decision with input as inp
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as fixture_agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

test_custom_plan_allowed if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-operator",
		"action": "plan",
		"resource": "infra/prod",
	})
	out.decision == "allow"
	out.rule_id == "custom.example.allow_plan"
}

test_custom_apply_denied_without_approval if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-operator",
		"action": "apply",
		"resource": "infra/prod",
	})
	out.decision == "deny"
	out.rule_id == "custom.example.apply_without_approval"
}

test_custom_apply_allowed_with_flag if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-operator",
		"action": "apply",
		"resource": "infra/prod",
		"args": {"approved": true},
	})
	out.decision == "allow"
	out.rule_id == "custom.example.allow_apply"
}

test_custom_apply_allowed_with_approval_id if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-operator",
		"action": "apply",
		"resource": "infra/prod",
		"args": {"approval_id": "appr-9872"},
	})
	out.decision == "allow"
	out.rule_id == "custom.example.allow_apply"
}

test_custom_apply_allowed_elevated_agent if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-admin",
		"action": "apply",
		"resource": "infra/prod",
	})
	out.decision == "allow"
	out.rule_id == "custom.example.allow_apply"
}

test_custom_apply_allowed_prod_access if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-prod",
		"action": "apply",
		"resource": "infra/prod",
	})
	out.decision == "allow"
	out.rule_id == "custom.example.allow_apply"
}

test_custom_invalid_action_denied if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-operator",
		"action": "destroy_all",
		"resource": "infra/prod",
	})
	out.decision == "deny"
	out.rule_id == "custom.example.action_invalid"
}

test_custom_read_only_allowed if {
	out := decide({
		"stage": "custom:example",
		"key_id": "k-custom-operator",
		"action": "output",
		"resource": "infra/prod",
	})
	out.decision == "allow"
	out.rule_id == "custom.example.allow_read"
}
