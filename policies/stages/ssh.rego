package stages.ssh

# SSH stage policy: gates remote SSH access (connect and exec) by host, user, port, and command pattern.

import rego.v1

import data.gateway.authz
import data.shield.prod

decision := ssh_decision

args := object.get(input, "args", {})

agent := object.get(data.agents, input.key_id, {})

action := lower(object.get(input, "action", ""))

# Host field: strip an embedded ":port" suffix before pattern matching —
# "bastion.teknikal.id:22" must match allow_hosts wildcard (MC-05, 14 Nov MC
# sweep; raw host:port broke both allowlist and denylist matching).
host_raw := object.get(input, "host", object.get(input, "resource", ""))

host := h if {
	contains(host_raw, ":")
	not contains(split(host_raw, ":")[0], "[")
	h := split(host_raw, ":")[0]
} else := host_raw

user := object.get(input, "user", "")

# Port: top-level first, then args.port — a port smuggled inside args must
# not silently default to 22 (MC-06, 14 Nov MC sweep).
port := object.get(input, "port", object.get(args, "port", 22))

req_port := sprintf("%v", [port])

command := object.get(input, "command", object.get(args, "command", object.get(args, "cmd", "")))

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
	"rule_id": "ssh.auth_pubkey_mismatch",
	"reason": "ssh public key unauthenticated or fingerprint mismatch",
} if {
	auth_pubkey_mismatch
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
	"rule_id": "ssh.staged_script_forbidden",
	"reason": sprintf("executing staged scripts from world-writable paths (/tmp, /var/tmp, /dev/shm) is forbidden: %q", [command]),
} if {
	staged_script_forbidden
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
# "ssh_exec" is the bastion binary's action constant (cmd/cerberus-ssh main.go);
# treat it as an alias of "exec" (MC-02, 14 Nov MC sweep — mismatch caused
# 100% of bastion command executions to be rejected).
action_invalid if {
	action != "connect"
	action != "exec"
	action != "ssh_exec"
}

# Host pattern matching: delegates to secure host_matches in authz
host_matches(pattern, h) if authz.host_matches(pattern, h)

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

# Command rule for exec action: checked against deny_commands regexes.
# lower(command): deny patterns are authored lowercase — "sudo SU -" must not
# slip past "sudo\s+su\b.*" (case bypass, found 14 Nov MC sweep).
is_exec_action if action == "exec"
is_exec_action if action == "ssh_exec"

command_denied if {
	is_exec_action
	some pat in deny_commands
	regex.match(pat, lower(command))
}

# Staged script execution guard: forbids executing scripts located in world-writable directories
staged_script_forbidden if {
	is_exec_action
	command != ""
	regex.match("(?i)(?:^|[\\s;|&`$()<>]|source|\\.)(?:\\s*(?:\\b(?:ba|z|da)?sh\\b|\\bpython[0-9.]*\\b|\\bperl\\b|\\bruby\\b))?\\s*/(?:tmp|var/tmp|dev/shm)/", command)
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

# ---------- public key auth mismatch checks ----------

auth_pubkey_mismatch if {
	input.key_id == "unauthenticated"
}

auth_pubkey_mismatch if {
	fp := object.get(input, "fingerprint", object.get(args, "fingerprint", ""))
	fp != ""
	expected_fp := object.get(agent, "ssh_pubkey_fingerprint", "")
	expected_fp != ""
	lower(trim(fp, " \t\r\n")) != lower(trim(expected_fp, " \t\r\n"))
}

ssh_shield_target if prod.touches_prod(host)
