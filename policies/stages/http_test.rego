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
		"allowed_hosts": ["*.internal.corp", "api.github.com", "apple.com"],
		"denied_hosts": ["evil.com", "*.malicious.net"],
		"allowed_methods": ["GET", "POST"],
		"allowed_ports": [80, 443, 8080],
	},
	"t-http-custom-port": {
		"allowed_hosts": ["api.github.com"],
		"allowed_methods": ["GET", "POST"],
		"allowed_ports": [80, 443, 3128],
	},
}

fixture_agents := {
	"k-http": {
		"name": "http-agent",
		"team_id": "t-http",
		"allowed_hosts": ["*.internal.corp", "api.github.com", "apple.com"],
		"denied_hosts": ["evil.com", "*.malicious.net"],
		"allowed_methods": ["GET", "POST"],
		"allowed_ports": [80, 443, 8080],
	},
	"k-http-open": {
		"name": "http-open-agent",
	},
	"k-http-default-ports": {
		"name": "http-default-ports-agent",
		"allowed_hosts": ["api.github.com", "example.com"],
	},
	"k-http-custom-port": {
		"name": "http-custom-port-agent",
		"team_id": "t-http-custom-port",
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

# Port tests: port 25, 53, 3128 default deny; 443/80 allow; explicitly allowed port allow
test_http_port_25_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http-default-ports",
		"resource": "http://api.github.com:25/mail",
		"args": {"method": "POST", "port": 25},
	})
	out.decision == "deny"
	out.rule_id == "http.port_not_allowed"
}

test_http_port_53_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http-default-ports",
		"resource": "http://api.github.com:53/dns",
		"args": {"method": "GET", "port": 53},
	})
	out.decision == "deny"
	out.rule_id == "http.port_not_allowed"
}

test_http_port_3128_default_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http-default-ports",
		"resource": "http://api.github.com:3128/proxy",
		"args": {"method": "GET", "port": 3128},
	})
	out.decision == "deny"
	out.rule_id == "http.port_not_allowed"
}

test_http_port_3128_explicit_allowed if {
	out := decide({
		"stage": "http",
		"key_id": "k-http-custom-port",
		"resource": "http://api.github.com:3128/proxy",
		"args": {"method": "GET", "port": 3128},
	})
	out.decision == "allow"
	out.rule_id == "http.allow"
}

test_http_port_80_default_allowed if {
	out := decide({
		"stage": "http",
		"key_id": "k-http-default-ports",
		"resource": "http://example.com/test",
		"args": {"method": "GET", "port": 80},
	})
	out.decision == "allow"
	out.rule_id == "http.allow"
}

test_http_port_443_default_allowed if {
	out := decide({
		"stage": "http",
		"key_id": "k-http-default-ports",
		"resource": "https://example.com/test",
		"args": {"method": "GET", "port": 443},
	})
	out.decision == "allow"
	out.rule_id == "http.allow"
}

# Punycode / Homoglyph fail-closed test: xn--pple-4td.com not in allowed_hosts -> deny
test_http_punycode_homoglyph_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://xn--pple-4td.com/login",
		"args": {"method": "GET"},
	})
	out.decision == "deny"
	out.rule_id == "http.host_not_allowed"
}

# R2: Host allowlist exact & wildcard matching — evil.com suffix / substring attacks denied
test_http_evil_com_suffix_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://api.github.com.evil.com/leak",
		"args": {"method": "GET"},
	})
	out.decision == "deny"
	out.rule_id == "http.host_not_allowed"
}

test_http_wildcard_suffix_evil_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://service.internal.corp.evil.com/leak",
		"args": {"method": "GET"},
	})
	out.decision == "deny"
	out.rule_id == "http.host_not_allowed"
}

test_http_userinfo_bypass_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"resource": "https://api.github.com@evil.com/leak",
		"args": {"method": "GET"},
	})
	out.decision == "deny"
	out.rule_id == "http.host_not_allowed"
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
	out.rule_id == "authz.unknown_key"
}

# --- Link-local & Metadata SSRF Guard (MC-P0 Akar 1) ---

test_http_link_local_metadata_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"action": "GET",
		"resource": "http://169.254.169.254/latest/meta-data/iam/",
	})
	out.decision == "deny"
	out.rule_id == "http.link_local_forbidden"
}

test_http_link_local_ipv6_mapped_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"action": "GET",
		"resource": "http://[::ffff:169.254.169.254]/latest/meta-data/iam/",
	})
	out.decision == "deny"
	out.rule_id == "http.link_local_forbidden"
}

test_http_link_local_loopback_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"action": "GET",
		"resource": "http://127.0.0.1:8080/admin",
	})
	out.decision == "deny"
	out.rule_id == "http.link_local_forbidden"
}

test_http_link_local_ipv6_loopback_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"action": "GET",
		"resource": "http://[::1]:8080/admin",
	})
	out.decision == "deny"
	out.rule_id == "http.link_local_forbidden"
}

test_http_link_local_integer_ip_denied if {
	out := decide({
		"stage": "http",
		"key_id": "k-http",
		"action": "GET",
		"resource": "http://2852039166/latest/meta-data/iam/",
	})
	out.decision == "deny"
	out.rule_id == "http.link_local_forbidden"
}

test_http_link_local_no_override_exempt_key if {
	out := decide({
		"stage": "http",
		"key_id": "k-owner",
		"action": "GET",
		"resource": "http://169.254.169.254/latest/meta-data/iam/",
	})
	out.decision == "deny"
	out.rule_id == "http.link_local_forbidden"
}
