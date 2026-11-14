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

# 6b. Staged script from world-writable paths is forbidden
test_ssh_exec_staged_script_tmp_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "sh /tmp/p.sh",
	})
	out.decision == "deny"
	out.rule_id == "ssh.staged_script_forbidden"
}

test_ssh_exec_staged_script_var_tmp_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "bash /var/tmp/x.sh",
	})
	out.decision == "deny"
	out.rule_id == "ssh.staged_script_forbidden"
}

test_ssh_exec_proper_path_allowed if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"command": "/opt/deploy/run.sh",
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

# R2: Host allowlist exact & wildcard matching verification
test_ssh_exact_match_allowed if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "bastion.corp",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "allow"
	out.rule_id == "ssh.allow"
}

test_ssh_wildcard_api_teknikal_allowed if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "api.teknikal.id",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "allow"
	out.rule_id == "ssh.allow"
}

test_ssh_evil_subdomain_suffix_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "evil.teknikal.id.evil.com",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.host_not_allowed"
}

test_ssh_teknikal_id_evil_com_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "teknikal.id.evil.com",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.host_not_allowed"
}

test_ssh_userinfo_spoof_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "api.teknikal.id@evil.com",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.host_not_allowed"
}

test_ssh_unauthenticated_pubkey_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "unauthenticated",
		"action": "connect",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
	})
	out.decision == "deny"
	out.rule_id == "ssh.auth_pubkey_mismatch"
}

test_ssh_fingerprint_mismatch_denied if {
	out := decision with input as {
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"fingerprint": "SHA256:wrongfingerprint",
	}
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as {"k-open": {"name": "open-agent", "ssh_pubkey_fingerprint": "SHA256:correctfingerprint"}}
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
		with data.ssh as data.testdata.ssh
	out.decision == "deny"
	out.rule_id == "ssh.auth_pubkey_mismatch"
}

# --- Regression: case bypass in deny_commands (14 Nov MC sweep) ---
test_exec_dangerous_case_bypass_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "exec",
		"resource": "bastion.teknikal.id",
		"user": "deploy",
		"port": 22,
		"args": {"cmd": "RM -RF /"},
	})
	out.decision == "deny"
	out.rule_id == "ssh.command_denied"
}

# --- Regression MC-02: bastion action "ssh_exec" must be valid (alias of exec) ---
test_ssh_exec_action_valid_now if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "ssh_exec",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"port": 22,
		"args": {"cmd": "uptime"},
	})
	out.decision == "allow"
}

# --- Regression MC-05: host with embedded :port must still match allowlist ---
test_ssh_host_with_port_allowed if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "bastion.teknikal.id:22",
		"user": "deploy",
		"port": 22,
	})
	out.decision == "allow"
}

# --- Regression MC-06: port smuggled in args must be enforced ---
test_ssh_args_port_denied if {
	out := decide({
		"stage": "ssh",
		"key_id": "k-open",
		"action": "connect",
		"host": "dev.teknikal.id",
		"user": "ubuntu",
		"args": {"port": 2222},
	})
	out.decision == "deny"
	out.rule_id == "ssh.port_not_allowed"
}
