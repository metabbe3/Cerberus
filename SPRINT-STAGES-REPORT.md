# SPRINT-STAGES REPORT: Database & Kubernetes Stage Adapters

## Executive Summary
This sprint delivers two stage adapters for Cerberus:
1. **`db` stage (`policies/stages/db.rego`)**: gates SQL database operations (PostgreSQL / MySQL) executed via SDK / CLI wrappers with strict safety controls against destructive operations, sensitive table/column exfiltration, unapproved mutations, and unauthorized database access.
2. **`k8s` stage (`policies/stages/k8s.rego`)**: gates `kubectl` operations via SDK wrappers, enforcing protections on critical namespaces, unconditional protection on sensitive resources (`ns`, `secrets`, `pv`, `pvc`), pod exec restrictions, secret output dumping blocks (`--output yaml|json`), and host-escape / privilege escalation prevention.
3. **Stage Registration & Engine Integration**: dynamically registered stages `db` and `k8s` in `internal/policy/loader.go`, validated snapshot stages in `loader_test.go`, and added 4 end-to-end integration tests in `internal/engine/engine_test.go`.

All strict worktree boundaries were respected (no modifications to `cmd/`, `internal/server/`, or `internal/audit/`).

---

## S1: Database Stage Adapter (`db.rego` & `db_test.rego`)

### 1. Contract & Input Format
- **Stage identifier**: `db`
- **Tool call**: `sql_exec`
- **Input schema**:
  ```json
  {
    "stage": "db",
    "key_id": "<agent_key>",
    "tool_call": "sql_exec",
    "args": {
      "dialect": "postgres" | "mysql",
      "sql": "SELECT ...",
      "database": "customers-prod",
      "write": true | false
    }
  }
  ```

### 2. Normalization & Pre-Processing
- **Comment Stripping**: SQL comments are stripped before pattern evaluation:
  - Block comments: `/* ... */` using `regex.replace(..., "(?s)/\\*.*?\\*/", " ")`
  - Line comments: `-- ...\n` using `regex.replace(..., "--[^\\r\\n]*", " ")`
- **Multi-statement Splitting**: Semicolon-delimited queries (`SELECT 1; DROP TABLE x`) are split and evaluated individually as well as collectively, defeating multi-statement injection bypasses.
- **Case-Insensitive Matching**: All pattern checks are case-insensitive (`(?i)`).

### 3. Rules Implemented
| Rule ID | Decision | Trigger Condition |
| :--- | :--- | :--- |
| `db.destructive_statement` | DENY | Keywords matched in any statement: `DROP (DATABASE\|TABLE\|INDEX\|SCHEMA)`, `TRUNCATE`, `ALTER TABLE ... DROP`, `DELETE [FROM] <tbl>` without literal `WHERE`, `UPDATE <tbl> SET` without literal `WHERE`, `GRANT`/`REVOKE`, `CREATE EXTENSION`, `COPY ... TO PROGRAM`, `pg_read_file`, `LOAD DATA INFILE`, `ALTER SYSTEM`, `pg_sleep(>5)`, `SHUTDOWN`. |
| `db.select_requires_limit` | DENY | Activated only if `data.config.db_require_limit == true` (default `false`); denies `SELECT` queries lacking a `LIMIT <n>` clause. |
| `db.sensitive_table` | DENY | Matches non-aggregate queries accessing protected tables (`users`, `credentials`, `api_keys`, `secrets`, `payment_methods`, `personal_data`, configurable via `data.shield.prod.db_protected_tables`), or queries referencing sensitive columns (`password`, `token`, `secret`, `private_key`). Aggregate queries (`count`, `avg`, `min`, `max`, `sum`) on protected tables without sensitive columns are permitted. |
| `db.write_without_approval` | DENY | Denies mutating queries (`INSERT`, `UPDATE`, `DELETE`, `CREATE`, `REPLACE`, `ALTER`, `DROP`, `TRUNCATE`, `UPSERT`, `MERGE`) or explicit `write: true` flags unless the agent configuration has `allow_db_write: true`. |
| `db.database_not_allowed` | DENY | Denies requests where target database is not permitted by `data.agents[key_id].allowed_databases`. Supports exact match, full wildcard (`*`), and domain suffix wildcards (`*.internal`). |
| `db.allow` | ALLOW | Clean queries satisfying all constraints. |

### 4. Test Coverage (`policies/stages/db_test.rego`)
- Total test cases: **35 cases** (exceeding minimum requirement of 14 cases).
- Verification includes:
  - Positive tests for every destructive keyword (DROP TABLE/DATABASE, TRUNCATE, ALTER TABLE DROP, DELETE without WHERE, UPDATE without WHERE, GRANT, CREATE EXTENSION, COPY TO PROGRAM, pg_read_file, LOAD DATA INFILE, ALTER SYSTEM, pg_sleep > 5, SHUTDOWN).
  - Safe `pg_sleep(2)` allowed.
  - Multi-statement bypass attempt (`SELECT 1; DROP TABLE x`) denied.
  - Line comment bypass attempt (`--x\nDROP TABLE x`) denied.
  - Block comment bypass attempt (`/* bypass */ DROP TABLE x`) denied.
  - Case variations (`drop table x`) denied.
  - Limit requirement enforcement with toggle on/off.
  - Sensitive table non-aggregate denied vs aggregate allowed.
  - Sensitive columns (`password`, `token`) denied.
  - Write approvals: write denied for read-only agent, allowed for writer agent, write flag auto-detection.
  - Database allowlist: exact match, suffix match (`*.internal`), wildcard (`*`), and unauthorized database denial.
  - Clean happy paths.

---

## S2: Kubernetes Stage Adapter (`k8s.rego` & `k8s_test.rego`)

### 1. Contract & Input Format
- **Stage identifier**: `k8s`
- **Tool call**: `kubectl`
- **Input schema**:
  ```json
  {
    "stage": "k8s",
    "key_id": "<agent_key>",
    "tool_call": "kubectl",
    "args": {
      "verb": "get" | "delete" | "apply" | "exec" | "patch" | "create" | "...",
      "resource": "pods" | "deployments" | "secrets" | "ns" | "...",
      "namespace": "prod",
      "all_namespaces": false,
      "flags": ["--force", "--privileged"],
      "manifest": "..."
    }
  }
  ```

### 2. Rules Implemented
| Rule ID | Decision | Trigger Condition |
| :--- | :--- | :--- |
| `k8s.privilege_escalation` | DENY | Scanning `flags` and `args.manifest` on mutating verbs (`apply`, `create`, `replace`, `patch`) for container escape vectors: `privileged`, `hostNetwork`, `hostPID`, `hostIPC`, `hostPath`, `serviceAccount: default`, `serviceAccountName: default`, `ClusterRoleBinding`. |
| `k8s.secret_read` | DENY | Denies reading `secrets` resource (`get`, `describe`, `list`, `watch`) unless agent has `allow_k8s_secrets: true`. Unconditionally blocks `--output yaml|json` or `-o=yaml|json` flag combinations when targeting secrets. |
| `k8s.exec_into_pod` | DENY | Interactive verbs (`exec`, `attach`, `port-forward`, `portforward`) into protected namespaces (`prod`, `production`, `default`, `kube-system`, or `all_namespaces: true`) are unconditionally denied. In non-protected namespaces, requires `allow_k8s_exec: true`. |
| `k8s.destructive_verb` | DENY | Destructive verbs (`delete`, `patch`, `replace`, `scale`, `scale-down`, `apply`, `applied`) targeted at protected namespaces denied unless agent has `allow_k8s_write: true`. `delete` is unconditionally denied for critical infrastructure resources: `ns`/`namespace`, `secret`/`secrets`, `pv`/`persistentvolume`, `pvc`/`persistentvolumeclaim`. |
| `k8s.namespace_not_allowed` | DENY | Enforces namespace allowlist from `data.agents[key_id].allowed_k8s_namespaces` (supports exact match and `*` wildcard). |
| `k8s.allow` | ALLOW | Clean `kubectl` operations on allowed resources and namespaces. |

### 3. Test Coverage (`policies/stages/k8s_test.rego`)
- Total test cases: **24 cases** (exceeding minimum requirement of 12 cases).
- Verification includes:
  - Destructive verb in protected namespaces denied without `allow_k8s_write`.
  - `all_namespaces: true` treated as protected namespace.
  - Delete unconditionally denied for `ns`, `secret`, `pv`, `pvc`.
  - Mutating apply in protected namespace allowed with `allow_k8s_write: true`.
  - Exec in protected namespace denied regardless of permissions.
  - Exec in non-protected namespace denied without `allow_k8s_exec`, allowed with `allow_k8s_exec`.
  - Secret read denied without `allow_k8s_secrets`, allowed with flag.
  - Secret read with `--output yaml` or `-o=json` strictly blocked even with secret permission.
  - Privilege escalation in manifests: `hostPath`, `privileged: true`, `serviceAccountName: default`, `ClusterRoleBinding` denied.
  - Privilege escalation via flags: `--privileged` denied.
  - Namespace allowlist: unlisted namespace denied, wildcard allowed.
  - Happy paths: get pods and deployments in allowed namespaces.

---

## S3: Loader & Engine Integration

### 1. `internal/policy/loader.go`
- Added `"k8s": true` to `extractStages` default stage map (alongside existing `"db": true`, `"ssh": true`, `"docker": true`, etc.).
- Automatically indexes rule IDs declared in `db.rego` and `k8s.rego`.
- Updated `internal/policy/loader_test.go` to assert `"db"` and `"k8s"` present in `snap.Stages`.

### 2. `internal/engine/engine_test.go`
- Added 4 end-to-end integration tests:
  - `TestDecide_StageDB_DestructiveDeny`: validates `DROP TABLE accounts;` returns `deny` with `db.destructive_statement`.
  - `TestDecide_StageDB_SelectAllow`: validates `SELECT id, name FROM items LIMIT 10;` returns `allow` with `db.allow`.
  - `TestDecide_StageK8s_ExecDeny`: validates `exec` on pod in `prod` returns `deny` with `k8s.exec_into_pod`.
  - `TestDecide_StageK8s_GetAllow`: validates `get pods` in `staging` returns `allow` with `k8s.allow`.
- Extended `TestEngine_MetricStage_Dynamic` to verify bounded Prometheus label resolution for `"k8s"` and `"db"`.

---

## Gate Verification Results

| Check | Command | Result | Details |
| :--- | :--- | :--- | :--- |
| **Go Build** | `go build ./...` | **PASS** | 0 build errors across all packages. |
| **OPA Unit Tests** | `make opa-test` | **PASS** | **233/233 PASS** (174 existing + 35 db + 24 k8s). |
| **OPA Strict Check** | `make opa-check` | **PASS** | `opa check --strict policies/` clean with 0 warnings/errors. |
| **Go Linter** | `golangci-lint run` | **PASS** | 0 issues reported across entire codebase. |
| **Formatters** | `gofmt -l .` / `opa fmt` | **PASS** | 0 formatting discrepancies. |
| **Race & Integration Tests** | `go test -race -count=1 ./internal/policy/ ./internal/engine/` | **PASS** | All policy, concurrency, reload, and engine tests pass without data races. |
