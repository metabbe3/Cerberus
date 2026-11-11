package gateway.ssh_test

# SSH stage tests: 8+ required quality cases for remote managed access.

import rego.v1

import data.gateway.authz.decision

decide(inp) := out if {
	out := decision with input as inp
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as data.testdata.agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
		with data.ssh as data.testdata.ssh
}

# 1. Wildcard match allowed (*.teknikal.id)
test_ssh_wildcard_match if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "allow"
	out.rule_id == "ssh.allow"
}

# 2. Subdomain non-match denied
test_ssh_subdomain_nonmatch_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "attacker.com",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.host_not_allowed"
}

# 3. Deny_hosts wins over wildcard allow
test_ssh_deny_hosts_wins if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "node1.blocked.teknikal.id",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.host_denied"
}

# 4. Port non-allowlist denied (port 2222)
test_ssh_port_not_allowed if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 2222,
	})
	out.decision == "deny"
	out.rule_id == "ssh.port_not_allowed"
}

# 5. Exec dangerous commands denied (rm -rf, mkfs, shutdown, dd if=)
test_ssh_exec_dangerous_command_rm_rf if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "rm -rf /var/data",
	})
	out.decision == "deny"
	out.rule_id == "ssh.command_denied"
}

test_ssh_exec_dangerous_command_mkfs if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "mkfs.ext4 /dev/sdb1",
	})
	out.decision == "deny"
	out.rule_id == "ssh.command_denied"
}

test_ssh_exec_dangerous_command_shutdown if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "shutdown -h now",
	})
	out.decision == "deny"
	out.rule_id == "ssh.command_denied"
}

test_ssh_exec_dangerous_command_dd if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "dd if=/dev/zero of=/dev/sda",
	})
	out.decision == "deny"
	out.rule_id == "ssh.command_denied"
}

# 6. Exec safe command allowed (uptime, ls)
test_ssh_exec_safe_command_allowed if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "uptime",
	})
	out.decision == "allow"
	out.rule_id == "ssh.allow"
}

# 7. Fail-closed on unknown host
test_ssh_fail_closed_unknown_host if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "internal-db.unauthorized.net",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.host_not_allowed"
}

# 8. User separated: unauthorized user denied (root not in allowed_users [deploy, ubuntu, admin])
test_ssh_user_separated if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "dev.teknikal.id",
		"user": "root",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.user_not_allowed"
}

# 9. Prod shield integration: SSH to prod IP blocked without prod access
test_ssh_prod_shield_blocked if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "10.0.0.9",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "shield.prod.ip_blocked"
}
