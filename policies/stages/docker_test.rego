package gateway.docker_test

# Docker stage tests: 3-layer verification (happy path, deny rules, bypass key behavior).

import rego.v1

import data.gateway.authz.decision

decide(inp) := out if {
	out := decision with input as inp
		with data.config as data.testdata.config
		with data.teams as fixture_teams
		with data.agents as fixture_agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

no_bypass_config := object.union(data.testdata.config, {"bypass_unknown_keys": false, "bypass_unknown_teams": false})

decide_closed(inp) := out if {
	out := decision with input as inp
		with data.config as no_bypass_config
		with data.teams as fixture_teams
		with data.agents as fixture_agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

fixture_teams := {
	"t-docker": {
		"allowed_images": ["python:3.*", "alpine:latest", "registry.internal/*"],
	},
}

fixture_agents := {
	"k-docker": {
		"name": "docker-agent",
		"team_id": "t-docker",
		"allowed_images": ["python:3.*", "alpine:latest", "registry.internal/*"],
	},
	"k-docker-open": {
		"name": "docker-open-agent",
	},
}

# Layer 1: Happy path
test_docker_allow_happy if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker",
		"action": "start",
		"resource": "alpine:latest",
		"args": {"mounts": ["/tmp:/data"]},
	})
	out.decision == "allow"
	out.rule_id == "docker.allow"
}

test_docker_allow_glob_image if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker",
		"action": "exec",
		"resource": "registry.internal/app/worker:v1",
	})
	out.decision == "allow"
	out.rule_id == "docker.allow"
}

# Layer 2: Deny rules
test_docker_image_not_allowed if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker",
		"action": "start",
		"resource": "untrusted/malicious:latest",
	})
	out.decision == "deny"
	out.rule_id == "docker.image_not_allowed"
}

test_docker_privileged_forbidden if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker",
		"action": "start",
		"resource": "alpine:latest",
		"args": {"privileged": true},
	})
	out.decision == "deny"
	out.rule_id == "docker.privileged_forbidden"
}

test_docker_capability_forbidden if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker",
		"action": "start",
		"resource": "alpine:latest",
		"args": {"cap_add": ["NET_ADMIN", "ALL"]},
	})
	out.decision == "deny"
	out.rule_id == "docker.capability_forbidden"
}

test_docker_mount_forbidden if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker",
		"action": "start",
		"resource": "alpine:latest",
		"args": {"mounts": ["/var/run/docker.sock:/var/run/docker.sock"]},
	})
	out.decision == "deny"
	out.rule_id == "docker.mount_forbidden"
}

test_docker_stop_normal_allowed if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker-open",
		"action": "stop",
		"resource": "my-worker-container",
	})
	out.decision == "allow"
	out.rule_id == "docker.allow"
}

test_docker_stop_protected_denied if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker-open",
		"action": "stop",
		"resource": "teknikalidnew-db-1",
	})
	out.decision == "deny"
	out.rule_id == "shield.container.protected"
}

test_docker_rm_protected_denied if {
	out := decide({
		"stage": "docker",
		"key_id": "k-docker-open",
		"action": "rm",
		"resource": "teknikalidnew-db-1",
	})
	out.decision == "deny"
	out.rule_id == "shield.container.protected"
}

# Layer 3: Bypass
test_docker_stranger_bypass_allowed if {
	out := decide({
		"stage": "docker",
		"key_id": "stranger-key",
		"action": "start",
		"resource": "any-image:latest",
	})
	out.decision == "allow"
	out.rule_id == "config.bypass_unknown_keys"
}

test_docker_stranger_bypass_closed if {
	out := decide_closed({
		"stage": "docker",
		"key_id": "stranger-key",
		"action": "start",
		"resource": "any-image:latest",
	})
	out.decision == "deny"
	out.rule_id == "config.unknown_key_closed"
}
