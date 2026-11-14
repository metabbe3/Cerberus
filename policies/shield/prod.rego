package shield.prod

# Production Shield helper: reusable pure functions for detecting dangerous
# command patterns, protected containers, prod network IPs/CIDRs, and prod keywords.
# Imported by stages (ai, http, docker) and gateway authz.

import rego.v1

# ---------- Reusable pure helper functions (P0.2) ----------

# exempt(key_id): true if key_id is in data.prod_shield.exempt_keys
exempt(key_id) if {
	is_string(key_id)
	key_id in data.prod_shield.exempt_keys
}

# prod_ip(ip): true if net.cidr_contains(cidr, ip) for some cidr in data.prod_shield.cidrs
# Safe under rego.StrictBuiltinErrors: only valid IP representations are handed to net.cidr_contains.
ipv4_pattern := `\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`

prod_ip(ip) if {
	is_string(ip)
	some candidate in regex.find_n(ipv4_pattern, ip, -1)
	some cidr in data.prod_shield.cidrs
	net.cidr_contains(cidr, candidate)
}

# normalize(s): NFKC unicode, strip zero-width (\u200b\u200c\u200d\ufeff), collapse whitespace, lower.
normalize(s) := out if {
	is_string(s)
	s1 := regex.replace(s, "[\u200b\u200c\u200d\ufeff]", "")
	s2 := trim_space(regex.replace(s1, `\s+`, " "))
	out := lower(s2)
} else := s

# touches_prod(text): true if some host_keyword or db_keyword (lower contains) is in text
touches_prod(text) if {
	is_string(text)
	norm_text := normalize(text)
	some kw in data.prod_shield.host_keywords
	contains(norm_text, normalize(kw))
}

touches_prod(text) if {
	is_string(text)
	norm_text := normalize(text)
	some kw in data.prod_shield.db_keywords
	contains(norm_text, normalize(kw))
}

# dangerous_cmd(cmd): set of pattern ids that match regex.match
dangerous_cmd(cmd) := ids if {
	is_string(cmd)
	norm_cmd := normalize(cmd)
	ids := {p.id |
		some p in data.prod_shield.dangerous_cmd_patterns
		object.get(p, "enabled", true) == true
		regex.match(p.regex, norm_cmd)
	}
}

# all_arg_strings(args): recursively extract all string values from an object or array
all_arg_strings(args) := [val |
	[_, val] := walk(args)
	is_string(val)
] if {
	is_object(args)
} else := [val |
	[_, val] := walk(args)
	is_string(val)
] if {
	is_array(args)
} else := []

# is_container_delete_call(call): true if call or action matches container deletion
is_container_delete_call(call) if {
	is_string(call)
	regex.match(`(?i)(docker.*rm|container.*delete|container.*rm|docker.*rmi|kubectl.*delete|compose.*down)`, call)
}

# touches_protected_container(text): true if text names a protected container or touches prod
touches_protected_container(text) if {
	is_string(text)
	norm_text := normalize(text)
	some c in data.prod_shield.protected_containers
	contains(norm_text, normalize(c))
}

touches_protected_container(text) if {
	touches_prod(text)
}
