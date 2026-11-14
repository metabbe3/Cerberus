package stages.k8s

# K8s stage policy: gates kubectl operations executed via SDK/CLI wrappers.
# Evaluates destructive verbs on protected namespaces/resources, pod execs,
# secret reads, privilege escalation manifests/flags, and namespace allowlists.

import rego.v1

decision := k8s_decision

args := object.get(input, "args", {})

verb := lower(object.get(args, "verb", object.get(input, "action", "")))

resource := lower(object.get(args, "resource", object.get(input, "resource", "")))

namespace := object.get(args, "namespace", object.get(input, "namespace", "default"))

all_namespaces := object.get(args, "all_namespaces", false)

flags := object.get(args, "flags", [])

manifest := object.get(args, "manifest", "")

tool_call := object.get(input, "tool_call", object.get(input, "action", "kubectl"))

agent := object.get(data.agents, input.key_id, {})

# ---------- k8s decision else-chain ----------

k8s_decision := {
	"decision": "deny",
	"rule_id": "k8s.privilege_escalation",
	"reason": "manifest or flags contain privilege escalation pattern",
} if {
	privilege_escalation
} else := {
	"decision": "deny",
	"rule_id": "k8s.secret_read",
	"reason": "reading secrets is restricted or yaml/json output forbidden",
} if {
	secret_read
} else := {
	"decision": "deny",
	"rule_id": "k8s.exec_into_pod",
	"reason": "exec/attach/port-forward into pod is restricted",
} if {
	exec_into_pod
} else := {
	"decision": "deny",
	"rule_id": "k8s.destructive_verb",
	"reason": "destructive kubectl verb is forbidden on protected resource or namespace",
} if {
	destructive_verb
} else := {
	"decision": "deny",
	"rule_id": "k8s.namespace_not_allowed",
	"reason": sprintf("namespace %q not in allowed_k8s_namespaces", [namespace]),
} if {
	namespace_not_allowed
} else := {
	"decision": "allow",
	"rule_id": "k8s.allow",
	"reason": sprintf("kubectl %s on %s in %s allowed", [verb, resource, namespace]),
}

# ---------- Protected namespaces ----------

protected_namespaces := ns if {
	ns := data.shield.prod.k8s_protected_namespaces
	is_array(ns)
} else := ns if {
	ns := data.prod_shield.k8s_protected_namespaces
	is_array(ns)
} else := ["prod", "production", "default", "kube-system"]

is_protected_ns if {
	lower(namespace) in protected_namespaces
}

is_protected_ns if {
	all_namespaces == true
}

# ---------- Destructive verbs ----------

unconditionally_protected_delete_resources := [
	"ns", "namespace", "namespaces",
	"secret", "secrets",
	"pv", "persistentvolume", "persistentvolumes",
	"pvc", "persistentvolumeclaim", "persistentvolumeclaims",
]

destructive_verbs := ["delete", "patch", "replace", "scale", "scale-down", "apply", "applied"]

destructive_verb if {
	verb == "delete"
	resource in unconditionally_protected_delete_resources
}

destructive_verb if {
	verb in destructive_verbs
	is_protected_ns
	not agent.allow_k8s_write == true
}

# ---------- Pod exec / attach / port-forward ----------

exec_verbs := ["exec", "attach", "port-forward", "portforward"]

exec_into_pod if {
	verb in exec_verbs
	is_protected_ns
}

exec_into_pod if {
	verb in exec_verbs
	not is_protected_ns
	not agent.allow_k8s_exec == true
}

# ---------- Secret read & output restrictions ----------

is_secret_resource if {
	resource in ["secret", "secrets"]
}

secret_output_blocked if {
	is_secret_resource
	some f in flags
	regex.match(`(?i)^(-o|--output)(=|\s+)?(yaml|json|jsonpath.*|go-template.*)$`, f)
}

secret_output_blocked if {
	is_secret_resource
	some i, f in flags
	f in ["-o", "--output"]
	regex.match(`(?i)^(yaml|json|jsonpath|go-template)`, flags[i + 1])
}

secret_read if {
	is_secret_resource
	verb in ["get", "describe", "list", "watch"]
	not agent.allow_k8s_secrets == true
}

secret_read if {
	secret_output_blocked
}

# ---------- Privilege escalation ----------

escalation_patterns := [
	`(?i)privileged`,
	`(?i)hostNetwork`,
	`(?i)hostPID`,
	`(?i)hostIPC`,
	`(?i)hostPath`,
	`(?i)serviceAccount(Name)?:\s*default`,
	`(?i)cluster-?role-?binding`,
]

escalation_in_manifest if {
	manifest != ""
	some p in escalation_patterns
	regex.match(p, manifest)
}

escalation_in_flags if {
	some f in flags
	some p in escalation_patterns
	regex.match(p, f)
}

privilege_escalation if {
	verb in ["apply", "create", "replace", "patch"]
	escalation_in_manifest
}

privilege_escalation if {
	verb in ["apply", "create", "replace", "patch"]
	escalation_in_flags
}

# ---------- Namespace allowlist ----------

ns_allowlist_configured if {
	agent.allowed_k8s_namespaces != null
	is_array(agent.allowed_k8s_namespaces)
}

namespace_matches(pattern, _) if pattern == "*"

namespace_matches(pattern, ns) if {
	startswith(pattern, "*.")
	suffix := trim_prefix(pattern, "*")
	endswith(lower(ns), lower(suffix))
}

namespace_matches(pattern, ns) if {
	not startswith(pattern, "*.")
	pattern != "*"
	lower(pattern) == lower(ns)
}

namespace_allowed if {
	some p in agent.allowed_k8s_namespaces
	namespace_matches(p, namespace)
}

namespace_not_allowed if {
	ns_allowlist_configured
	not namespace_allowed
}
