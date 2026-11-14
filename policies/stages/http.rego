package stages.http

# HTTP stage policy: gates outgoing/incoming HTTP requests by host, method, and headers.

import rego.v1

import data.gateway.authz
import data.shield.prod

decision := http_decision

resource := object.get(input, "resource", "")

args := object.get(input, "args", {})

# Extract host from URL or host string.
extract_host(raw) := h if {
	contains(raw, "://")
	after_proto := split(raw, "://")[1]
	host_port := split(after_proto, "/")[0]
	contains(host_port, "[")
	contains(host_port, "]")
	h = split(split(host_port, "]")[0], "[")[1]
} else := h if {
	contains(raw, "://")
	after_proto := split(raw, "://")[1]
	host_port := split(after_proto, "/")[0]
	h = split(host_port, ":")[0]
} else := h if {
	contains(raw, "[")
	contains(raw, "]")
	host_port := split(raw, "/")[0]
	h = split(split(host_port, "]")[0], "[")[1]
} else := h if {
	host_port := split(raw, "/")[0]
	h = split(host_port, ":")[0]
}

req_host := extract_host(resource)

# Extract port from URL or host:port string.
extract_port(raw) := p if {
	contains(raw, "://")
	after_proto := split(raw, "://")[1]
	host_port := split(after_proto, "/")[0]
	contains(host_port, ":")
	p = split(host_port, ":")[1]
} else := p if {
	not contains(raw, "://")
	host_port := split(raw, "/")[0]
	contains(host_port, ":")
	p = split(host_port, ":")[1]
} else := "443" if {
	startswith(raw, "https://")
} else := "80" if {
	startswith(raw, "http://")
} else := "443"

raw_port := object.get(args, "port", extract_port(resource))
req_port := sprintf("%v", [raw_port])

method := upper(object.get(args, "method", object.get(input, "action", "GET")))

# ---------- http decision else-chain ----------

http_decision := {
	"decision": "deny",
	"rule_id": "http.link_local_forbidden",
	"reason": sprintf("http request to link-local / loopback address %q is forbidden", [req_host]),
} if {
	http_link_local_forbidden
} else := {
	"decision": "allow",
	"rule_id": "shield.exempt",
	"reason": "shield_exempt",
} if {
	http_shield_target
	prod.exempt(input.key_id)
} else := {
	"decision": "deny",
	"rule_id": "shield.prod.ip_blocked",
	"reason": sprintf("http request to prod IP %q blocked", [req_host]),
} if {
	http_prod_ip_blocked
} else := {
	"decision": "deny",
	"rule_id": "shield.prod.no_access",
	"reason": sprintf("http request to prod resource %q denied without prod_access", [req_host]),
} if {
	http_prod_no_access
} else := {
	"decision": "deny",
	"rule_id": "http.host_denied",
	"reason": sprintf("host %q is denied", [req_host]),
} if {
	host_denied
} else := {
	"decision": "deny",
	"rule_id": "http.host_not_allowed",
	"reason": sprintf("host %q not in allowed_hosts", [req_host]),
} if {
	host_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "http.port_not_allowed",
	"reason": sprintf("port %v not in allowed_ports", [req_port]),
} if {
	port_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "http.method_not_allowed",
	"reason": sprintf("method %q not in allowed_methods", [method]),
} if {
	method_not_allowed
} else := {
	"decision": "allow",
	"rule_id": "http.allow",
	"reason": sprintf("http request to %q (%s) allowed", [req_host, method]),
}

# Host denylist: agent or team denied_hosts (glob or pattern match)
host_denied if {
	some pattern in authz.agent.denied_hosts
	host_matches(pattern, req_host)
}

host_denied if {
	some pattern in authz.team.denied_hosts
	host_matches(pattern, req_host)
}

# Host allowlist: when defined on agent or team, host must match
host_not_allowed if {
	allow_hosts_configured
	not host_allowed
}

allow_hosts_configured if authz.agent.allowed_hosts

allow_hosts_configured if authz.team.allowed_hosts

host_allowed if {
	some pattern in authz.agent.allowed_hosts
	host_matches(pattern, req_host)
}

host_allowed if {
	some pattern in authz.team.allowed_hosts
	host_matches(pattern, req_host)
}

host_matches(pattern, h) if authz.host_matches(pattern, h)

# Method allowlist: when defined on agent or team, method must be listed
method_not_allowed if {
	allow_methods_configured
	not method_allowed
}

allow_methods_configured if authz.agent.allowed_methods

allow_methods_configured if authz.team.allowed_methods

method_allowed if {
	some m in authz.agent.allowed_methods
	upper(m) == method
}

method_allowed if {
	some m in authz.team.allowed_methods
	upper(m) == method
}

# Port allowlist: default to [80, 443] for allowlisted hosts unless configured on agent or team
default_allowed_ports := ["80", "443", 80, 443]

port_restriction_active if allow_hosts_configured
port_restriction_active if allow_ports_configured

port_allowed if {
	not allow_ports_configured
	some p in default_allowed_ports
	sprintf("%v", [p]) == req_port
}

port_allowed if {
	some p in authz.agent.allowed_ports
	sprintf("%v", [p]) == req_port
}

port_allowed if {
	some p in authz.team.allowed_ports
	sprintf("%v", [p]) == req_port
}

allow_ports_configured if authz.agent.allowed_ports
allow_ports_configured if authz.team.allowed_ports

port_not_allowed if {
	port_restriction_active
	not port_allowed
}

# ---------- shield prod checks (P0.3) ----------

agent_has_prod_access if authz.agent_has_prod_access

http_prod_ip_blocked if {
	not agent_has_prod_access
	prod.prod_ip(req_host)
}

http_prod_no_access if {
	not agent_has_prod_access
	prod.touches_prod(req_host)
}

http_prod_no_access if {
	not agent_has_prod_access
	prod.touches_prod(resource)
}

http_shield_target if prod.prod_ip(req_host)

http_shield_target if prod.touches_prod(req_host)

http_shield_target if prod.touches_prod(resource)

# ---------- link-local & loopback SSRF guard (MC-P0 Akar 1) ----------

link_local_cidrs := [
	"169.254.0.0/16",
	"fe80::/10",
]

loopback_cidrs := [
	"127.0.0.0/8",
	"::1/128",
]

clean_host(h) := ch if {
	h1 := trim(h, "[]")
	startswith(lower(h1), "::ffff:")
	ch := substring(h1, 7, -1)
} else := trim(h, "[]")

# Guard to avoid eval_builtin_error under rego.StrictBuiltinErrors.
# Only valid IPv4 addresses and link-local/loopback IPv6 addresses relevant to link_local_cidrs.
is_valid_ip(s) if regex.match(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`, s)
is_valid_ip(s) if lower(s) == "::1"
is_valid_ip(s) if {
	lower_s := lower(s)
	regex.match(`^fe[89ab][0-9a-f]:[0-9a-f:]*$`, lower_s)
	not contains(lower_s, ":::")
}

http_link_local_forbidden if {
	ch := clean_host(req_host)
	ch != ""
	is_valid_ip(ch)
	some cidr in link_local_cidrs
	net.cidr_contains(cidr, ch)
}

http_link_local_forbidden if {
	not object.get(args, "allow_loopback", false) == true
	ch := clean_host(req_host)
	ch != ""
	is_valid_ip(ch)
	some cidr in loopback_cidrs
	net.cidr_contains(cidr, ch)
}

http_link_local_forbidden if {
	regex.match(`^[0-9]+$`, req_host)
	n := to_number(req_host)
	n >= 2851995648 # 169.254.0.0
	n <= 2852061183 # 169.254.255.255
}

http_link_local_forbidden if {
	not object.get(args, "allow_loopback", false) == true
	regex.match(`^[0-9]+$`, req_host)
	n := to_number(req_host)
	n >= 2130706432 # 127.0.0.0
	n <= 2147483647 # 127.255.255.255
}

