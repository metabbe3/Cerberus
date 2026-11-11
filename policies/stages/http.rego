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
	h = split(host_port, ":")[0]
} else := h if {
	host_port := split(raw, "/")[0]
	h = split(host_port, ":")[0]
}

req_host := extract_host(resource)

method := upper(object.get(args, "method", object.get(input, "action", "GET")))

# ---------- http decision else-chain ----------

http_decision := {
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

host_matches(pattern, h) if glob.match(pattern, [":"], h)

host_matches(pattern, h) if authz.call_matches_pattern(pattern, h)

host_matches(pattern, h) if lower(pattern) == lower(h)

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

# ---------- shield prod checks (P0.3) ----------

agent_has_prod_access if authz.agent.prod_access == true

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
