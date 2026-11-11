package stages.ssh

# SSH stage policy: gates remote SSH access (connect and exec) by host, user, port, and command pattern.

import rego.v1

import data.gateway.authz
import data.shield.prod

decision := ssh_decision

action := lower(object.get(input, "action", ""))

host := object.get(input, "host", object.get(input, "resource", ""))

user := object.get(input, "user", "")

port := object.get(input, "port", 22)

req_port := sprintf("%v", [port])

command := object.get(input, "command", "")

# ---------- configuration resolution ----------
# Rules from data.ssh

allow_hosts := object.get(data.ssh, "allow_hosts", [])

deny_hosts := object.get(data.ssh, "deny_hosts", [])

allow_ports := object.get(data.ssh, "allow_ports", [22, "22"])

deny_commands := object.get(data.ssh, "deny_commands", [])

allowed_users := object.get(data.ssh, "allowed_users", [])

denied_users := object.get(data.ssh, "denied_users", [])

# ---------- ssh decision else-chain ----------

ssh_decision := {
	"decision": "allow",
	"rule_id": "shield.exempt",
	"reason": "shield_exempt",
} if {
	ssh_shield_target
	prod.exempt(input.key_id)
} else := {
	"decision": "deny",
	"rule_id": "shield.prod.ip_blocked",
	"reason": sprintf("ssh request to prod IP %q blocked", [host]),
} if {
	ssh_prod_ip_blocked
} else := {
	"decision": "deny",
	"rule_id": "shield.prod.no_access",
	"reason": sprintf("ssh request to prod resource %q denied without prod_access", [host]),
} if {
	ssh_prod_no_access
} else := {
	"decision": "deny",
	"rule_id": "ssh.action_invalid",
	"reason": sprintf("action %q is invalid (must be connect or exec)", [action]),
} if {
	action_invalid
} else := {
	"decision": "deny",
	"rule_id": "ssh.host_denied",
	"reason": sprintf("host %q is denied by policy", [host]),
} if {
	host_denied
} else := {
	"decision": "deny",
	"rule_id": "ssh.host_not_allowed",
	"reason": sprintf("host %q not in allow_hosts", [host]),
} if {
	host_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "ssh.port_not_allowed",
	"reason": sprintf("port %v not in allow_ports", [req_port]),
} if {
	port_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "ssh.user_denied",
	"reason": sprintf("user %q is denied", [user]),
} if {
	user_denied
} else := {
	"decision": "deny",
	"rule_id": "ssh.user_not_allowed",
	"reason": sprintf("user %q not in allowed_users", [user]),
} if {
	user_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "ssh.command_denied",
	"reason": sprintf("command matches dangerous pattern", []),
} if {
	command_denied
} else := {
	"decision": "allow",
	"rule_id": "ssh.allow",
	"reason": sprintf("ssh %s to %s@%s:%v allowed", [action, user, host, req_port]),
}

# Action validation
action_invalid if {
	action != "connect"
	action != "exec"
}

# Host pattern matching: supports wildcard subdomain (*.teknikal.id), glob, prefix, exact
host_matches(pattern, h) if {
	startswith(pattern, "*.")
	suffix := substring(pattern, 1, -1)
	endswith(lower(h), lower(suffix))
}

host_matches("*", _) if true

host_matches(pattern, h) if {
	pattern != "*"
	not startswith(pattern, "*.")
	authz.pattern_matches(pattern, h)
}

host_matches(pattern, h) if {
	pattern != "*"
	not startswith(pattern, "*.")
	lower(pattern) == lower(h)
}

# Host deny rule (checked first)
host_denied if {
	some pattern in deny_hosts
	host_matches(pattern, host)
}

# Host allow rule (fail-closed if host not in allow_hosts)
host_allowed if {
	some pattern in allow_hosts
	host_matches(pattern, host)
}

host_not_allowed if not host_allowed

# Port rule: must match allow_ports (default [22])
port_allowed if {
	some p in allow_ports
	sprintf("%v", [p]) == req_port
}

port_not_allowed if not port_allowed

# User rules
user_denied if {
	some u in denied_users
	lower(u) == lower(user)
}

user_allowed if {
	count(allowed_users) == 0
}

user_allowed if {
	some u in allowed_users
	lower(u) == lower(user)
}

user_not_allowed if {
	count(allowed_users) > 0
	not user_allowed
}

# Command rule for exec action: checked against deny_commands regexes
command_denied if {
	action == "exec"
	some pat in deny_commands
	regex.match(pat, command)
}

# ---------- shield prod checks ----------

agent_has_prod_access if authz.agent_has_prod_access

ssh_prod_ip_blocked if {
	not agent_has_prod_access
	prod.prod_ip(host)
}

ssh_prod_no_access if {
	not agent_has_prod_access
	prod.touches_prod(host)
}

ssh_shield_target if prod.prod_ip(host)

ssh_shield_target if prod.touches_prod(host)
