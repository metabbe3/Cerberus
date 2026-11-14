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

# prod_ip(ip): true if net.cidr_contains(cidr, ip) for some cidr in data.prod_shield.cidrs,
# link-local cidrs (169.254.0.0/16, fe80::/10), or loopback cidrs (127.0.0.0/8, ::1/128).
# Safe under rego.StrictBuiltinErrors: only valid IP representations are handed to net.cidr_contains.
ipv4_pattern := `\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`

loopback_allowed if {
	object.get(object.get(input, "args", {}), "allow_loopback", false) == true
}

shield_cidrs := array.concat(
	object.get(data.prod_shield, "cidrs", []),
	["169.254.0.0/16", "fe80::/10"],
)

prod_ip(ip) if {
	is_string(ip)
	some candidate in regex.find_n(ipv4_pattern, ip, -1)
	some cidr in shield_cidrs
	net.cidr_contains(cidr, candidate)
}

prod_ip(ip) if {
	not loopback_allowed
	is_string(ip)
	some candidate in regex.find_n(ipv4_pattern, ip, -1)
	some cidr in ["127.0.0.0/8", "::1/128"]
	net.cidr_contains(cidr, candidate)
}

# normalize(s): NFKC unicode, strip zero-width and word-joiners (\u200b\u200c\u200d\u2060\u00ad\ufeff),
# map Latin-lookalike Cyrillic homoglyphs (a,e,o,p,c,x,y,г->r), collapse whitespace, lower.
normalize(s) := out if {
	is_string(s)
	s0 := regex.replace(s, "[\u200b\u200c\u200d\u2060\u00ad\ufeff]", "")
	s1 := regex.replace(s0, "[аА]", "a")
	s2 := regex.replace(s1, "[еЕ]", "e")
	s3 := regex.replace(s2, "[оО]", "o")
	s4 := regex.replace(s3, "[рР]", "p")
	s5 := regex.replace(s4, "[сС]", "c")
	s6 := regex.replace(s5, "[хХ]", "x")
	s7 := regex.replace(s6, "[уУ]", "y")
	s8 := regex.replace(s7, "[гГ]", "r")
	s9 := trim_space(regex.replace(s8, `\s+`, " "))
	out := lower(s9)
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
