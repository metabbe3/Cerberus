package gateway.db_test

# DB stage tests: covers destructive statements, limits, sensitive tables/columns,
# write approvals, database allowlists, and bypass attempts.

import rego.v1

import data.gateway.authz.decision

fixture_agents := {
	"k-db-readonly": {
		"name": "db-readonly-agent",
		"allowed_databases": ["customers-prod", "*.internal"],
		"allow_db_write": false,
	},
	"k-db-writer": {
		"name": "db-writer-agent",
		"allowed_databases": ["customers-prod", "*.internal"],
		"allow_db_write": true,
	},
	"k-db-wildcard": {
		"name": "db-wildcard-agent",
		"allowed_databases": ["*"],
		"allow_db_write": false,
	},
	"k-db-open": {
		"name": "db-open-agent",
		"allow_db_write": true,
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

decide_with_limit_req(inp) := out if {
	cfg := object.union(data.testdata.config, {"db_require_limit": true})
	out := decision with input as inp
		with data.config as cfg
		with data.teams as data.testdata.teams
		with data.agents as fixture_agents
		with data.blocked_patterns as data.testdata.blocked_patterns
		with data.domains as data.testdata.domains
		with data.prod_shield as data.testdata.prod_shield
}

# 1. Destructive: DROP TABLE
test_db_destructive_drop_table if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "DROP TABLE accounts",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 2. Destructive: DROP DATABASE
test_db_destructive_drop_database if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "DROP DATABASE customers",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 3. Destructive: TRUNCATE
test_db_destructive_truncate if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "TRUNCATE logs",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 4. Destructive: ALTER TABLE ... DROP
test_db_destructive_alter_table_drop if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "ALTER TABLE orders DROP COLUMN notes",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 5. Destructive: DELETE without WHERE
test_db_destructive_delete_without_where if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "DELETE FROM audit_logs",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 6. Destructive: UPDATE without WHERE
test_db_destructive_update_without_where if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "UPDATE settings SET active = false",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 7. Destructive: GRANT / REVOKE
test_db_destructive_grant_revoke if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "GRANT ALL ON db.* TO 'hacker'@'%'",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 8. Destructive: CREATE EXTENSION
test_db_destructive_create_extension if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "CREATE EXTENSION pg_trgm",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 9. Destructive: COPY ... TO PROGRAM
test_db_destructive_copy_program if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "COPY data TO PROGRAM 'id'",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 10. Destructive: pg_read_file
test_db_destructive_pg_read_file if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT pg_read_file('/etc/passwd')",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 11. Destructive: LOAD DATA INFILE
test_db_destructive_load_data_infile if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "mysql",
			"sql": "LOAD DATA INFILE '/tmp/dump.txt' INTO TABLE dump",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 12. Destructive: ALTER SYSTEM
test_db_destructive_alter_system if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "ALTER SYSTEM SET max_connections = 1000",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 13. Destructive: pg_sleep > 5
test_db_destructive_pg_sleep_over_5 if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT pg_sleep(10)",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 14. Safe pg_sleep <= 5 allowed
test_db_destructive_pg_sleep_safe_allowed if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT pg_sleep(2)",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 15. Destructive: SHUTDOWN
test_db_destructive_shutdown if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SHUTDOWN",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 16. Bypass attempt: multi-statement split with semicolon
test_db_destructive_multistatement_bypass if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT 1; DROP TABLE x",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 17. Bypass attempt: line comment prefix
test_db_destructive_comment_bypass if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "--x\nDROP TABLE x",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 18. Bypass attempt: block comment wrapping
test_db_destructive_block_comment_bypass if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "/* innocent */ DROP TABLE x",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 19. Bypass attempt: lowercase case bypass
test_db_destructive_case_bypass if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "drop table x",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.destructive_statement"
}

# 20. Limit required: SELECT without LIMIT denied when configured
test_db_select_requires_limit_denied if {
	out := decide_with_limit_req({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT * FROM items",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.select_requires_limit"
}

# 21. Limit satisfied: SELECT with LIMIT allowed when configured
test_db_select_requires_limit_satisfied if {
	out := decide_with_limit_req({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT * FROM items LIMIT 10",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 22. Sensitive table: non-aggregate SELECT on protected table denied
test_db_sensitive_table_non_aggregate if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT id, email FROM users LIMIT 10",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.sensitive_table"
}

# 23. Sensitive table: aggregate SELECT on protected table allowed
test_db_sensitive_table_aggregate_allowed if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT count(*) FROM users",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 24. Sensitive column: password column access denied
test_db_sensitive_column_password if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT password FROM accounts LIMIT 10",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.sensitive_table"
}

# 25. Sensitive column: token column access denied
test_db_sensitive_column_token if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT id, token FROM sessions LIMIT 10",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.sensitive_table"
}

# 26. Write without approval: INSERT denied for read-only agent
test_db_write_without_approval_insert if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "INSERT INTO items (name) VALUES ('book')",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.write_without_approval"
}

# 27. Write with approval: INSERT allowed for writer agent
test_db_write_with_approval_allowed if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-writer",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "INSERT INTO items (name) VALUES ('book')",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 28. Write flag true without approval denied
test_db_write_flag_without_approval if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT 1",
			"database": "customers-prod",
			"write": true,
		},
	})
	out.decision == "deny"
	out.rule_id == "db.write_without_approval"
}

# 29. Database allowlist: unlisted database denied
test_db_database_not_allowed if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT * FROM items LIMIT 10",
			"database": "unauthorized-db",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.database_not_allowed"
}

# 30. Database allowlist: suffix wildcard *.internal allowed
test_db_database_suffix_allowed if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT * FROM items LIMIT 10",
			"database": "analytics.internal",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 31. Database allowlist: suffix wildcard *.internal non-match denied
test_db_database_suffix_denied if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT * FROM items LIMIT 10",
			"database": "analytics.external",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.database_not_allowed"
}

# 32. Database allowlist: full wildcard * allowed
test_db_database_wildcard_all_allowed if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-wildcard",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT * FROM items LIMIT 10",
			"database": "any-random-db",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 33. Happy path: clean SELECT with LIMIT on allowed database
test_db_happy_path_clean_select if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT id, title FROM articles LIMIT 10",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 34. Happy path: clean SELECT with WHERE clause and LIMIT
test_db_happy_path_where_limit if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT id, name FROM items WHERE price < 100 LIMIT 25",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 35. Happy path: clean aggregate query
test_db_happy_path_aggregate if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "SELECT count(*), max(price) FROM products",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}

# 36. CTE WITH query accessing sensitive table (credentials) denied
test_db_cte_sensitive_table_violation if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "WITH d AS (SELECT * FROM credentials) SELECT * FROM d",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.sensitive_table"
}

# 37. COPY ... TO 'file' is forbidden file-drop
test_db_copy_to_file_drop_denied if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "COPY (SELECT * FROM orders LIMIT 9) TO '/tmp/f'",
			"database": "customers-prod",
		},
	})
	out.decision == "deny"
	out.rule_id == "db.file_drop_forbidden"
}

# 38. COPY ... TO STDOUT is allowed
test_db_copy_to_stdout_allowed if {
	out := decide({
		"stage": "db",
		"key_id": "k-db-readonly",
		"tool_call": "sql_exec",
		"args": {
			"dialect": "postgres",
			"sql": "COPY (SELECT 1) TO STDOUT",
			"database": "customers-prod",
		},
	})
	out.decision == "allow"
	out.rule_id == "db.allow"
}
