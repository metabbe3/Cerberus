package gateway.k8s_test

# K8s stage tests: covers destructive verbs, pod execs, secret reads,
# privilege escalation, namespace allowlists, and happy paths.

import rego.v1

import data.gateway.authz.decision

fixture_agents := {
	"k-k8s-readonly": {
		"name": "k8s-readonly-agent",
		"allowed_k8s_namespaces": ["staging", "dev"],
		"allow_k8s_write": false,
		"allow_k8s_exec": false,
		"allow_k8s_secrets": false,
	},
	"k-k8s-writer": {
		"name": "k8s-writer-agent",
		"allowed_k8s_namespaces": ["prod", "staging", "dev"],
		"allow_k8s_write": true,
		"allow_k8s_exec": false,
		"allow_k8s_secrets": false,
	},
	"k-k8s-exec": {
		"name": "k8s-exec-agent",
		"allowed_k8s_namespaces": ["prod", "staging", "dev"],
		"allow_k8s_write": false,
		"allow_k8s_exec": true,
		"allow_k8s_secrets": false,
	},
	"k-k8s-secrets": {
		"name": "k8s-secrets-agent",
		"allowed_k8s_namespaces": ["staging", "dev"],
		"allow_k8s_write": false,
		"allow_k8s_exec": false,
		"allow_k8s_secrets": true,
	},
	"k-k8s-wildcard": {
		"name": "k8s-wildcard-agent",
		"allowed_k8s_namespaces": ["*"],
		"allow_k8s_write": true,
		"allow_k8s_exec": true,
		"allow_k8s_secrets": true,
	},
}

decide(inp) := out if {
	out := decision with input as inp
		with data.config as data.testdata.config
		with data.teams as data.testdata.teams
		with data.agents as fixture_agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

# 1. Destructive verb on protected namespace denied without write approval
test_k8s_destructive_delete_protected_ns if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "delete",
			"resource": "pods",
			"namespace": "prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.destructive_verb"
}

# 2. Destructive verb with all_namespaces true denied without write approval
test_k8s_destructive_delete_all_namespaces if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "delete",
			"resource": "pods",
			"namespace": "staging",
			"all_namespaces": true,
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.destructive_verb"
}

# 3. Patch verb on protected namespace denied without write approval
test_k8s_destructive_patch_protected_ns if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "patch",
			"resource": "deployments",
			"namespace": "default",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.destructive_verb"
}

# 4. Delete ns always denied even with write approval
test_k8s_destructive_delete_namespace_resource if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "delete",
			"resource": "ns",
			"namespace": "staging",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.destructive_verb"
}

# 5. Delete secret always denied even with write approval
test_k8s_destructive_delete_secret_resource if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "delete",
			"resource": "secrets",
			"namespace": "staging",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.destructive_verb"
}

# 6. Delete pv always denied even with write approval
test_k8s_destructive_delete_pv_resource if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "delete",
			"resource": "pv",
			"namespace": "staging",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.destructive_verb"
}

# 7. Delete pvc always denied even with write approval
test_k8s_destructive_delete_pvc_resource if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "delete",
			"resource": "pvc",
			"namespace": "staging",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.destructive_verb"
}

# 8. Apply on protected namespace allowed with write approval
test_k8s_destructive_apply_protected_ns_with_write_allowed if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "apply",
			"resource": "deployments",
			"namespace": "prod",
			"manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  replicas: 1",
		},
	})
	out.decision == "allow"
	out.rule_id == "k8s.allow"
}

# 9. Exec into protected namespace always denied
test_k8s_exec_protected_ns_denied if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-exec",
		"tool_call": "kubectl",
		"args": {
			"verb": "exec",
			"resource": "pods",
			"namespace": "prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.exec_into_pod"
}

# 10. Exec into non-protected namespace denied without exec approval
test_k8s_exec_other_ns_denied_without_flag if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "exec",
			"resource": "pods",
			"namespace": "staging",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.exec_into_pod"
}

# 11. Exec into non-protected namespace allowed with exec approval
test_k8s_exec_other_ns_allowed_with_flag if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-exec",
		"tool_call": "kubectl",
		"args": {
			"verb": "exec",
			"resource": "pods",
			"namespace": "staging",
		},
	})
	out.decision == "allow"
	out.rule_id == "k8s.allow"
}

# 12. Secret read denied without secret approval
test_k8s_secret_read_denied_without_flag if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "secrets",
			"namespace": "staging",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.secret_read"
}

# 13. Secret read allowed with secret approval
test_k8s_secret_read_allowed_with_flag if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-secrets",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "secrets",
			"namespace": "staging",
		},
	})
	out.decision == "allow"
	out.rule_id == "k8s.allow"
}

# 14. Secret read blocked with --output yaml even with secret approval
test_k8s_secret_read_blocked_yaml_output if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-secrets",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "secrets",
			"namespace": "staging",
			"flags": ["--output", "yaml"],
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.secret_read"
}

# 15. Secret read blocked with -o=json even with secret approval
test_k8s_secret_read_blocked_json_output if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-secrets",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "secrets",
			"namespace": "staging",
			"flags": ["-o=json"],
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.secret_read"
}

# 16. Privilege escalation: hostPath in manifest denied
test_k8s_privilege_escalation_manifest_hostpath if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "apply",
			"resource": "pods",
			"namespace": "staging",
			"manifest": "spec:\n  volumes:\n  - name: host-root\n    hostPath:\n      path: /",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.privilege_escalation"
}

# 17. Privilege escalation: privileged container denied
test_k8s_privilege_escalation_manifest_privileged if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "apply",
			"resource": "pods",
			"namespace": "staging",
			"manifest": "spec:\n  containers:\n  - name: root\n    securityContext:\n      privileged: true",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.privilege_escalation"
}

# 18. Privilege escalation: default service account denied
test_k8s_privilege_escalation_manifest_serviceaccount_default if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "apply",
			"resource": "pods",
			"namespace": "staging",
			"manifest": "spec:\n  serviceAccountName: default",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.privilege_escalation"
}

# 19. Privilege escalation: ClusterRoleBinding denied
test_k8s_privilege_escalation_manifest_clusterrolebinding if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "create",
			"resource": "clusterrolebinding",
			"namespace": "staging",
			"manifest": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: admin-binding",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.privilege_escalation"
}

# 20. Privilege escalation: --privileged flag denied
test_k8s_privilege_escalation_flags if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-writer",
		"tool_call": "kubectl",
		"args": {
			"verb": "create",
			"resource": "deployment",
			"namespace": "staging",
			"flags": ["--privileged"],
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.privilege_escalation"
}

# 21. Namespace allowlist: unlisted namespace denied
test_k8s_namespace_not_allowed if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "pods",
			"namespace": "finance",
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.namespace_not_allowed"
}

# 22. Namespace allowlist: wildcard allowed
test_k8s_namespace_wildcard_allowed if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-wildcard",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "pods",
			"namespace": "finance",
		},
	})
	out.decision == "allow"
	out.rule_id == "k8s.allow"
}

# 23. Happy path: get pods in allowed namespace
test_k8s_happy_path_get_pods if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "pods",
			"namespace": "staging",
		},
	})
	out.decision == "allow"
	out.rule_id == "k8s.allow"
}

# 24. Happy path: get deployments in allowed namespace
test_k8s_happy_path_get_deployments if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-readonly",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "deployments",
			"namespace": "dev",
		},
	})
	out.decision == "allow"
	out.rule_id == "k8s.allow"
}

# 25. Secret output blocked: -o jsonpath={.data}
test_k8s_secret_output_blocked_jsonpath if {
	out := decide({
		"stage": "k8s",
		"key_id": "k-k8s-secrets",
		"tool_call": "kubectl",
		"args": {
			"verb": "get",
			"resource": "secret",
			"namespace": "dev",
			"flags": ["-o", "jsonpath={.data}"],
		},
	})
	out.decision == "deny"
	out.rule_id == "k8s.secret_read"
}
