package stages.db

# DB stage policy: gates SQL database queries executed via SDK/CLI wrappers.
# Evaluates destructive statements, limit requirements, sensitive tables/columns,
# write permissions, and database allowlists.

import rego.v1

decision := db_decision

args := object.get(input, "args", {})

raw_sql := object.get(args, "sql", object.get(input, "sql", object.get(input, "query", "")))

database := object.get(args, "database", object.get(input, "resource", object.get(input, "database", "")))

dialect := lower(object.get(args, "dialect", object.get(input, "dialect", "postgres")))

tool_call := object.get(input, "tool_call", object.get(input, "action", "sql_exec"))

agent := object.get(data.agents, input.key_id, {})

# Strip block comments /* ... */ and line comments -- ...
clean_sql := regex.replace(regex.replace(raw_sql, `(?s)/\*.*?\*/`, " "), `--[^\r\n]*`, " ")

# Split into individual statements by semicolon
statements := [trim(s, " \t\r\n") | s := split(clean_sql, ";")[_]; trim(s, " \t\r\n") != ""]

# ---------- db decision else-chain ----------

db_decision := {
	"decision": "deny",
	"rule_id": "db.destructive_statement",
	"reason": "destructive SQL statement is forbidden",
} if {
	destructive_statement
} else := {
	"decision": "deny",
	"rule_id": "db.select_requires_limit",
	"reason": "SELECT statement requires a LIMIT clause",
} if {
	select_requires_limit
} else := {
	"decision": "deny",
	"rule_id": "db.sensitive_table",
	"reason": "access to sensitive table or column is restricted",
} if {
	sensitive_table_violation
} else := {
	"decision": "deny",
	"rule_id": "db.write_without_approval",
	"reason": "database write requires allow_db_write permission",
} if {
	write_without_approval
} else := {
	"decision": "deny",
	"rule_id": "db.database_not_allowed",
	"reason": sprintf("database %q not in allowed_databases", [database]),
} if {
	database_not_allowed
} else := {
	"decision": "allow",
	"rule_id": "db.allow",
	"reason": sprintf("db query on %q allowed", [database]),
}

# ---------- Destructive statements ----------

destructive_statement if {
	some stmt in statements
	statement_is_destructive(stmt)
}

destructive_statement if {
	clean_sql != ""
	statement_is_destructive(clean_sql)
}

statement_is_destructive(s) if regex.match(`(?i)\bdrop\s+(database|table|index|schema)\b`, s)

statement_is_destructive(s) if regex.match(`(?i)\btruncate\b`, s)

statement_is_destructive(s) if regex.match(`(?i)\balter\s+table\b.*\bdrop\b`, s)

statement_is_destructive(s) if delete_without_where(s)

statement_is_destructive(s) if update_without_where(s)

statement_is_destructive(s) if regex.match(`(?i)\b(grant|revoke)\b`, s)

statement_is_destructive(s) if regex.match(`(?i)\bcreate\s+extension\b`, s)

statement_is_destructive(s) if regex.match(`(?i)\bcopy\b.*\bto\s+program\b`, s)

statement_is_destructive(s) if regex.match(`(?i)\bpg_read_file\b`, s)

statement_is_destructive(s) if regex.match(`(?i)\bload\s+data\s+(local\s+)?infile\b`, s)

statement_is_destructive(s) if regex.match(`(?i)\balter\s+system\b`, s)

statement_is_destructive(s) if pg_sleep_too_long(s)

statement_is_destructive(s) if regex.match(`(?i)\bshutdown\b`, s)

delete_without_where(s) if {
	regex.match(`(?i)\bdelete\s+(from\s+)?['"]?[a-z0-9_.]+['"]?`, s)
	not regex.match(`(?i)\bwhere\b`, s)
}

update_without_where(s) if {
	regex.match(`(?i)\bupdate\s+['"]?[a-z0-9_.]+['"]?\s+set\b`, s)
	not regex.match(`(?i)\bwhere\b`, s)
}

pg_sleep_too_long(s) if {
	some m in regex.find_all_string_submatch_n(`(?i)\bpg_sleep\s*\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)`, s, -1)
	to_number(m[1]) > 5
}

# ---------- Select requires limit ----------

db_require_limit if data.config.db_require_limit == true

select_requires_limit if {
	db_require_limit
	some stmt in statements
	is_select_statement(stmt)
	not has_limit_clause(stmt)
}

is_select_statement(s) if {
	regex.match(`(?i)^\s*select\b`, s)
}

has_limit_clause(s) if {
	regex.match(`(?i)\blimit\s+[0-9]+`, s)
}

# ---------- Sensitive table & column ----------

protected_tables := pt if {
	pt := data.shield.prod.db_protected_tables
	is_array(pt)
} else := pt if {
	pt := data.prod_shield.db_protected_tables
	is_array(pt)
} else := ["users", "credentials", "api_keys", "secrets", "payment_methods", "personal_data"]

is_aggregate_select(s) if {
	regex.match(`(?i)^\s*select\s+(count|avg|min|max|sum)\s*\(`, s)
}

touches_protected_table(s) if {
	some tbl in protected_tables
	regex.match(sprintf(`(?i)\b(from|join)\s+([a-zA-Z0-9_]+\.)?['"]?%s['"]?\b`, [tbl]), s)
}

has_sensitive_column(s) if {
	regex.match(`(?i)\b(password|token|secret|private_key)\b`, s)
}

sensitive_table_violation if {
	some stmt in statements
	is_select_statement(stmt)
	touches_protected_table(stmt)
	not is_aggregate_select(stmt)
}

sensitive_table_violation if {
	some stmt in statements
	has_sensitive_column(stmt)
}

# ---------- Write without approval ----------

allow_db_write if agent.allow_db_write == true

is_write_statement(s) if {
	regex.match(`(?i)^\s*(insert|update|delete|create|replace|alter|drop|truncate|upsert|merge)\b`, s)
}

is_write_query if {
	object.get(args, "write", false) == true
}

is_write_query if {
	some stmt in statements
	is_write_statement(stmt)
}

write_without_approval if {
	is_write_query
	not allow_db_write
}

# ---------- Allowed databases ----------

database_allowlist_configured if {
	agent.allowed_databases != null
	is_array(agent.allowed_databases)
}

database_matches(pattern, _) if pattern == "*"

database_matches(pattern, db) if {
	startswith(pattern, "*.")
	suffix := trim_prefix(pattern, "*")
	endswith(lower(db), lower(suffix))
}

database_matches(pattern, db) if {
	not startswith(pattern, "*.")
	pattern != "*"
	lower(pattern) == lower(db)
}

database_allowed if {
	some p in agent.allowed_databases
	database_matches(p, database)
}

database_not_allowed if {
	database_allowlist_configured
	not database_allowed
}
