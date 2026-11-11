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
	"decision": "allow",
	"rule_id": "docker.allow",
	"reason": sprintf("docker %s on %q allowed", [action, image]),
}

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

image_matches(pattern, img) if glob.match(pattern, [":"], img)

image_matches(pattern, img) if authz.call_matches_pattern(pattern, img)

image_matches(pattern, img) if lower(pattern) == lower(img)

# ---------- shield container checks (P0.4) ----------

docker_container_protected if {
	docker_delete_action
	docker_protected_target
}

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
