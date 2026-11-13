package stages.docker

# Docker stage policy: gates container operations by image allowlist, forbid privileged,
# forbid cap-add=ALL, and forbid mounting docker.sock.

import rego.v1

import data.gateway.authz
import data.shield.prod

decision := docker_decision

image := object.get(input, "resource", "")

action := lower(object.get(input, "action", ""))

args := object.get(input, "args", {})

# ---------- docker decision else-chain ----------

docker_decision := {
	"decision": "allow",
	"rule_id": "shield.exempt",
	"reason": "shield_exempt",
} if {
	docker_container_protected
	prod.exempt(input.key_id)
} else := {
	"decision": "deny",
	"rule_id": "shield.container.protected",
	"reason": sprintf("container %s is protected", [image]),
} if {
	docker_container_protected
} else := {
	"decision": "deny",
	"rule_id": "docker.host_root_forbidden",
	"reason": "mounting host filesystem root into a container is forbidden",
} if {
	mount_host_root
} else := {
	"decision": "deny",
	"rule_id": "docker.host_namespace_forbidden",
	"reason": "host network/IPC/PID namespace is forbidden",
} if {
	host_namespace
} else := {
	"decision": "deny",
	"rule_id": "docker.mount_forbidden",
	"reason": "mounting docker.sock is forbidden",
} if {
	mount_docker_sock
} else := {
	"decision": "deny",
	"rule_id": "docker.privileged_forbidden",
	"reason": "privileged mode is forbidden",
} if {
	privileged_mode
} else := {
	"decision": "deny",
	"rule_id": "docker.capability_forbidden",
	"reason": "cap-add=ALL is forbidden",
} if {
	cap_add_all
} else := {
	"decision": "deny",
	"rule_id": "docker.image_not_allowed",
	"reason": sprintf("image %q not in allowed_images", [image]),
} if {
	image_not_allowed
} else := {
	"decision": "deny",
	"rule_id": "docker.write_not_allowlisted",
	"reason": sprintf("mutating docker action %q is not allowlisted for this key", [action]),
} if {
	docker_write_action
} else := {
	"decision": "allow",
	"rule_id": "docker.allow",
	"reason": sprintf("docker %s on %q allowed", [action, image]),
}

# Host-escape mounts: binding / or /Users or /private into a container is
# a full host takeover — forbid regardless of image allowlist.
mount_host_root if {
	some mount in args.binds
	is_string(mount)
	regex.match(`(?i)^(/|/Users|/private|/var|/etc|/bin|/sbin|/usr)(:|$)`, mount)
}

mount_host_root if {
	some mount in args.volumes
	is_string(mount)
	regex.match(`(?i)^(/|/Users|/private|/var|/etc|/bin|/sbin|/usr)(:|$)`, mount)
}

mount_host_root if {
	some mount in args.mounts
	is_object(mount)
	regex.match(`(?i)^(/|/Users|/private|/var|/etc|/bin|/sbin|/usr)$`, object.get(mount, "source", ""))
}

# --net=host / host IPC / host PID namespace sharing
host_namespace if args.network_mode == "host"
host_namespace if args.net == "host"
host_namespace if args.ipc_mode == "host"
host_namespace if args.pid_mode == "host"

# Mount check: forbid docker.sock in mounts, volumes, or binds
mount_docker_sock if {
	some mount in args.mounts
	is_string(mount)
	contains(lower(mount), "docker.sock")
}

mount_docker_sock if {
	some mount in args.volumes
	is_string(mount)
	contains(lower(mount), "docker.sock")
}

mount_docker_sock if {
	some mount in args.binds
	is_string(mount)
	contains(lower(mount), "docker.sock")
}

mount_docker_sock if {
	some mount in args.mounts
	is_object(mount)
	contains(lower(object.get(mount, "source", "")), "docker.sock")
}

# Privileged mode check: boolean true or string "true" or number 1
privileged_mode if args.privileged == true

privileged_mode if args.privileged == "true"

privileged_mode if args.privileged == 1

# Cap-add=ALL check: array or string containing ALL
cap_add_all if {
	some cap in args.cap_add
	is_string(cap)
	upper(cap) == "ALL"
}

cap_add_all if {
	some cap in args["cap-add"]
	is_string(cap)
	upper(cap) == "ALL"
}

cap_add_all if {
	is_string(args.cap_add)
	upper(args.cap_add) == "ALL"
}

# Image allowlist: when defined on agent or team, image must match glob pattern
image_not_allowed if {
	image != ""
	not action in ["rm", "rmi", "delete", "down", "stop", "kill"]
	image_allowlist_configured
	not image_allowed
}

image_allowlist_configured if authz.agent.allowed_images

image_allowlist_configured if authz.team.allowed_images

image_allowed if {
	some pattern in authz.agent.allowed_images
	image_matches(pattern, image)
}

image_allowed if {
	some pattern in authz.team.allowed_images
	image_matches(pattern, image)
}

image_matches(pattern, img) if authz.pattern_matches(pattern, img)

# ---------- shield container checks (P0.4) ----------

# Read-only actions that never mutate container state (observability stays open).
docker_readonly_action if action in ["get", "list", "inspect", "logs", "stats", "top", "events", "version", "info", "ping", "diff", "changes", "history", "search"]

# Default-deny writes (Argon round 2): POST/PUT/DELETE on the Docker API are
# denied UNLESS the agent's key is explicitly allowlisted for that action.
# docker_write_allowlist on the agent: e.g. {"create": true, "start": ["alpine:*"]}
docker_write_allowed if {
	some act, perms in authz.agent.docker_write_allowlist
	lower(act) == action
	perms != false
}

docker_write_action if {
	not docker_readonly_action
	not docker_write_allowed
}

# Hardened 13 Nov: a protected container is untouchable for ANY mutating
# action — not just rm/stop/kill. exec into it, pause, update, attach,
# archive, rename, resize, wait: all deny.
docker_container_protected if {
	not docker_readonly_action
	docker_protected_target
}

# Legacy helper kept for is_container_delete_call semantics (plan/compose destroy).
docker_delete_action if action in ["rm", "rmi", "delete", "down", "stop", "kill"]

docker_delete_action if prod.is_container_delete_call(action)

docker_protected_target if {
	image != ""
	prod.touches_protected_container(image)
}

docker_protected_target if {
	some arg_val in prod.all_arg_strings(args)
	prod.touches_protected_container(arg_val)
}
