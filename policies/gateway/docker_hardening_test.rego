package gateway.docker_hardening_test

# Regression tests for the Argon security review (13 Nov 2026):
# exec/pause/update on a protected container must DENY; host-root bind and
# --net=host on create must DENY; read-only logs stay ALLOWED.

import rego.v1

import data.gateway.authz.decision as gateway_decision

evald(inp) := out if {
	out := gateway_decision with input as inp
		with data.config as data.testdata.config
		with data.teams as {}
		with data.agents as {}
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

test_exec_into_protected_container_denies if {
	out := evald({
		"stage": "docker",
		"key_id": "k-agent",
		"action": "exec_create",
		"resource": "teknikalidnew-db-1",
		"args": {"cmd": ["psql", "-c", "DROP TABLE users"]},
	})
	out.decision == "deny"
	out.rule_id == "shield.container.protected"
}

test_pause_protected_container_denies if {
	out := evald({
		"stage": "docker",
		"key_id": "k-agent",
		"action": "pause",
		"resource": "teknikalidnew-db-1",
		"args": {},
	})
	out.decision == "deny"
}

test_update_protected_container_denies if {
	out := evald({
		"stage": "docker",
		"key_id": "k-agent",
		"action": "update",
		"resource": "teknikalidnew-db-1",
		"args": {"memory": 1},
	})
	out.decision == "deny"
}

test_create_with_host_root_bind_denies if {
	out := evald({
		"stage": "docker",
		"key_id": "k-agent",
		"action": "create",
		"resource": "alpine:latest",
		"args": {"binds": ["/:/host"]},
	})
	out.decision == "deny"
	out.rule_id == "docker.host_root_forbidden"
}

test_create_with_host_network_denies if {
	out := evald({
		"stage": "docker",
		"key_id": "k-agent",
		"action": "create",
		"resource": "alpine:latest",
		"args": {"network_mode": "host"},
	})
	out.decision == "deny"
	out.rule_id == "docker.host_namespace_forbidden"
}

test_logs_on_protected_container_allowed if {
	out := evald({
		"stage": "docker",
		"key_id": "k-agent",
		"action": "logs",
		"resource": "teknikalidnew-db-1",
		"args": {},
	})
	out.decision == "allow"
}
