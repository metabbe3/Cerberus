package gateway.http_test

# HTTP stage tests: 3-layer verification (happy path, deny rules, bypass key behavior).

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
	"t-http": {
		"allowed_hosts": ["*.internal.corp", "api.github.com"],
		"denied_hosts": ["evil.com", "*.malicious.net"],
		"allowed_methods": ["GET", "POST"],
	},
}

fixture_agents := {
	"k-http": {
		"name": "http-agent",
		"team_id": "t-http",
		"allowed_hosts": ["*.internal.corp", "api.github.com"],
		"denied_hosts": ["evil.com", "*.malicious.net"],
		"allowed_methods": ["GET", "POST"],
	},
	"k-http-open": {
		"name": "http-open-agent",
	},
}

# Layer 1: Happy path
test_http_allow_happy if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://api.github.com/repos",
		"args": {"method": "GET"},
	})
	out.decision == "allow"
	out.rule_id == "http.allow"
}

test_http_allow_glob_host if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "http://service.internal.corp:8080/health",
		"args": {"method": "POST"},
	})
	out.decision == "allow"
	out.rule_id == "http.allow"
}

# Layer 2: Deny rules
test_http_host_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://evil.com/leak",
		"args": {"method": "POST"},
	})
	out.decision == "deny"
	out.rule_id == "http.host_denied"
}

test_http_host_not_allowed if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://untrusted.org/data",
		"args": {"method": "GET"},
	})
	out.decision == "deny"
	out.rule_id == "http.host_not_allowed"
}

test_http_method_not_allowed if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://api.github.com/repos",
		"args": {"method": "DELETE"},
	})
	out.decision == "deny"
	out.rule_id == "http.method_not_allowed"
}

# Layer 3: Bypass
test_http_stranger_bypass_allowed if {
	out := decide({
		"stage": "http",
		"key_id": "stranger-key",
		"resource": "https://anywhere.org",
		"args": {"method": "GET"},
	})
	out.decision == "allow"
	out.rule_id == "config.bypass_unknown_keys"
}

test_http_stranger_bypass_closed if {
	out := decide_closed({
		"stage": "http",
		"key_id": "stranger-key",
		"resource": "https://anywhere.org",
		"args": {"method": "GET"},
	})
	out.decision == "deny"
	out.rule_id == "config.unknown_key_closed"
}
