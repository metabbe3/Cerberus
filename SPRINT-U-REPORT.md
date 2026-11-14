# SPRINT U REPORT: Owl Per-Agent Detail & Breach Center

**Worktree**: `main` (starting HEAD `7715a92`)  
**Sprint Mandate**: BRIEF U (U1 - U7)  
**Execution Status**: ALL TASKS COMPLETED (Gates Passed: `make test`, `npm run build`, `vitest`, `opa test`, `golangci-lint`)  
**Commit State**: Uncommitted working tree (per instruction: *"JANGAN commit — Hermes verify dulu"*).

---

## 1. Executive Summary

Sprint U delivers the per-agent operational observability view and security breach management center for Cerberus Owl, addressing critical gaps in breach evidence retention, severity categorization, aggregate auditing, key rotation workflows, and bundle policy test exploration.

Following the design arbitrations in `owl-agentux-argon.md` and `owl-agentux-opus.md`, all additions strictly adhere to Cerberus **Mode B** UI design philosophy: dark, dense, data-first, keyboard-navigable (`j`/`k`, `Enter`, `t`, `x`, `/`), monospace tabular numerals for identifiers and latencies, semantically crisp colors (`destructive`, `amber`, `emerald`), respecting `prefers-reduced-motion`, with zero client-side engine token exposure (all traffic flows through Next.js `/api` proxy routes).

---

## 2. Deliverables by Ticket

### U1 (P0): Fix Audit Args NULL in Engine
- **Root Cause**: `auditArgsFor` in `internal/engine/engine.go` previously emitted `d.MaskedArgs`. When an input had no masking rules triggered, `d.MaskedArgs` was `nil`. Because SQLite stores `event.Args`, unmasked tool calls resulted in NULL `args` columns in the audit ledger, losing vital forensic evidence for denied operations (e.g. ShellGuard commands).
- **Resolution**:
  - Updated `auditArgsFor(in Input, d Decision) map[string]any`:
    - Checks `d.MaskedArgs` first; if non-empty, uses it.
    - Otherwise, emits `in.Args` for tool calls, or masked messages/prompts for LLM stages.
    - Guarantees `event.Args` is never nil when arguments exist in the input.
    - At-rest storage-level masking in `internal/audit/sqlite.go:335` (`insertBatch`) remains intact as defense-in-depth before writing to SQLite.
- **Verification**:
  - Added `TestAuditArgs_DenyShellguardWithoutMasking` in `internal/engine/engine_test.go`: verified that a blocked shellguard command (`rm -rf /`) on a key with no masking rules preserves `args.cmd` in the emitted audit event (`PASS` in 0.13s).

---

### U2 (P0): Severity Map & Incident Deduplication
- **Implementation**:
  - `owl/lib/severity.ts`: Full TypeScript severity categorization with rule prefix/suffix matching:
    - **CRITICAL**: `shield.cmd.dangerous`, `shield.container.protected`, `shield.prod.ip_blocked`, `k8s.privilege_escalation`, `k8s.exec_into_pod`, `db.destructive_statement`, `docker.privileged_forbidden`, `docker.host_root_forbidden`, `shellguard.unparseable`.
    - **HIGH**: `shield.prod.*`, `db.sensitive_table`, `db.write_without_approval`, `k8s.secret_read`, `k8s.destructive_verb`, `ssh.command_denied`, `ai.*.blocked_pattern(s)`.
    - **MEDIUM**: `*.restricted*`, `*.arg_violation*`, `*.host_denied*`, `ops.kill_switch`.
    - **POLICY**: `*.not_allowed`, `ops.rate_limited`, `ai.llm.budget_*` (not breaches).
  - Go severity mirror in `internal/audit/severity.go` (`GetSeverity`, `IsSecurityRule`, `IsBreach`).
  - **Breach Definition (Opus)**: Strictly `decision == "deny"` on CRITICAL or HIGH security rules. Rate limits, budget overages, and tool allowlist denials are classified as warnings/policy events and excluded from the Breach Center.
  - **Deduplication**: `deduplicateBreaches()` groups events by `(key_id, rule_id, day)` and computes `incidentCount` with first/last timestamps, avoiding raw row flooding.
- **Verification**:
  - `owl/lib/severity.test.ts`: 5 unit tests verifying classification, breach filtering, and deduplication (`vitest run` passed 5/5).

---

### U3 (P0): Server-Side Aggregate Endpoints
- **Endpoints Implemented in `internal/server/admin.go` & `internal/audit/sqlite.go`**:
  - `GET /v1/audit/breaches?since=&until=&severity=&stage=&rule_prefix=&key_id=&limit=200`:
    - Scans SQLite daily partitions (like Timeseries).
    - Aggregates by security prefix list (`shield.`, `k8s.`, `db.`, `docker.`, `ssh.`, `shellguard.`, `ai.*blocked_pattern*`).
    - Returns structured `{summary: {critical, high, medium, total}, buckets: [{bucket_ns, critical, high, medium}], top_offenders: [{key_id, count, critical_count, last_time, top_rule_id}], events: [...]}`.
  - `GET /v1/audit/agents-summary?since=24h`:
    - Groups events by `key_id`, returning `[{key_id, total, deny, breach_count, last_active, daily_tool_calls}]`.
- **Database Optimization**:
  - Added idempotent SQLite index `idx_events_decision_rule_time ON events(decision, rule_id, time)` to `internal/audit/sqlite.go`.
- **Verification**:
  - Added `internal/server/admin_breaches_test.go` with `TestBreachesAndAgentsSummary`: verifies that rate-limited events are omitted from breaches while security denies are counted and bucketed accurately (`PASS` with `-race`).

---

### U4 (P0): Detail Page `/agents/[keyId]` (Observability View)
- **Design Transformation**:
  - Transformed `/agents/[keyId]` into a high-density operational view based on `owl-agentux-argon.md §1`.
  - **Header**: Agent display name, team association, Kill Switch badge, Breaches 24h count, and 4 primary actions: Kill/Restore Agent, Rotate Key dialog, Edit Policy (navigates to `/agents/[keyId]/edit`), and Refresh.
  - **Effective Policy Card**: Merged view showing combined agent ∪ team permissions (tightest daily budget, union allowlists, restricted rules taking precedence).
  - **Sparkline Activity**: 24-hour and 7-day sparkline charts via `/api/timeseries?key_id=`.
  - **Security Breaches Panel**: Dedicated card listing CRITICAL and HIGH breaches with severity badges, formatted timestamp, expandable masked args, and an OPA Trace launcher via `TraceDialog`.
  - **Dense Audit Timeline**: Chronological log with time, stage, verdict, subject, rule ID, reason, latency (in µs with `font-mono tabular-nums`), cache hit flag, and expandable JSON payload viewer.
  - **Empty States**: Dual-mode empty states:
    - Clean state: Emerald checkmark indicator for active agents with zero breaches.
    - Inactive state: Amber guidance card with one-click copyable `curl` example snippet.
  - **Keyboard Navigation**:
    - `j` / `k`: Navigate rows up/down.
    - `Enter`: Expand / collapse selected audit row payload.
    - `t`: Open OPA Trace dialog for the selected breach/decision.
    - `x`: Toggle kill switch (kill/restore agent).
    - `/`: Focus search/filter input.
  - **Legacy Editor**: Relocated without modification to `/agents/[keyId]/edit` (`owl/app/(dash)/agents/[keyId]/edit/page.tsx`), preserving full policy and team assignment configuration.
  - **Agents Index**: Updated `/agents` table with KILL badge and Breaches 24h count column populated via `useAgentsSummary("24h")`.

---

### U5 (P1): Breach Center `/breaches`
- **New Dashboard Page (`owl/app/(dash)/breaches/page.tsx`)**:
  - **KPI Cards (Top 3 Columns)**:
    1. *Severity Summary*: Total breaches, CRITICAL count with percentage badge, HIGH count, and 24h delta comparison.
    2. *Incident Trend*: Time-series trend bucket sparkline showing hourly security incidents.
    3. *Top Offenders*: Ranked agent list with critical count, top offending rule ID, and a 1-click **Kill Agent** button.
  - **Incident Table**: Deduplicated incident list grouped by `(key_id, rule_id, day)` showing severity badge, agent key, rule family, incident count, and direct link to `/agents/[keyId]`.
  - **Multi-Factor Filters**: Filter by severity (ALL, CRITICAL, HIGH), stage (`tool`, `llm`, `http`, `docker`, `ssh`, `db`, `k8s`), rule family, and agent key ID.
  - **SSE Live Mode**: Defaults to frozen snapshot (Opus anti-fatigue principle) with an explicit toggle switch for live SSE streaming updates.

---

### U6 (P1): Key Rotation & Expanded Stage Filtering
- **Key Rotation**:
  - Backend: `POST /v1/admin/keys/{keyId}/rotate` in `internal/server/admin.go`. Clones the existing agent configuration, issues a new key ID with `-v2` suffix (or generates an auto-incremented revision suffix), optionally revokes or disables the prior key in data store, and returns `{new_key_id, new_api_key, revoked_old}`.
  - Frontend: `RotateKeyDialog` modal in Owl allowing one-click key rotation with key copying and toast alerts.
- **Stage Dropdowns**:
  - Expanded stage filters across `owl/app/(dash)/decisions/page.tsx`, `owl/components/agents/agent-decisions-tab.tsx`, and `owl/app/(dash)/breaches/page.tsx` to support all Cerberus stages: `tool`, `llm`, `http`, `docker`, `ssh`, `db`, `k8s`.

---

### U7 (P1): Policy Explorer `/policy` (Read-Only)
- **Engine Endpoints**:
  - `GET /v1/policy/modules`: Scans the policy directory, returning all Rego modules with file path, package name, SHA256 hash, byte size, and modification timestamp.
  - `POST /v1/policy/test-run`: Runs `tester.Runner` over all `*_test.rego` files with a 120-second timeout, concurrency guard (returns HTTP 423 Locked if another run is in progress via `Server.testRunMu`), and emits an audit event with `rule_id="policy.test_run"`.
- **Owl UI (`owl/app/(dash)/policy/page.tsx`)**:
  - Searchable Rego module table showing package, filename, SHA256 short hash, file size, and mtime.
  - "Run tests" button with spinner state, summary chip (e.g. `282/282 passed`), and expandable test results with pass/fail badges and individual execution durations.
  - Read-only banner with "Edit via bundle" linking to `docs/INTEGRATION.md` for cryptographic bundle workflow.

---

## 3. Test & Verification Matrix

| Verification Step | Command | Result | Notes |
| :--- | :--- | :---: | :--- |
| **Go Full Suite** | `make test` | **PASS** | `CERBERUS_SKIP_POLICY_SUITE=1 go test -race ./...` (All 19 packages passed) |
| **Server Tests** | `go test -race ./internal/server` | **PASS** | All server routes, admin aggregate handlers, and rotation passed (28.6s) |
| **Engine Tests** | `go test -race ./internal/engine` | **PASS** | Audit args test passed (14.6s) |
| **OPA Policy Tests** | `opa test policies/ -v` | **PASS** | 282 / 282 tests passed |
| **OPA Strict Check** | `opa check --strict policies/` | **PASS** | Strict syntax and schema checks passed |
| **Go Linter** | `golangci-lint run` | **PASS** | 0 issues across all packages |
| **Go Formatting** | `go fmt ./...` | **PASS** | Clean format |
| **Owl Unit Tests** | `npm test` (vitest) | **PASS** | 55 / 55 tests passed (7 test suites) |
| **Owl Build** | `npm run build` (Next.js Turbopack) | **PASS** | 21/21 static pages generated with 0 errors |

---

## 4. Modified & Created Files

### Backend (`cerberus` Go Engine & Server)
- `internal/engine/engine.go` (modified): `auditArgsFor` fix to emit `in.Args` on unmasked requests.
- `internal/engine/engine_test.go` (modified): Added `TestAuditArgs_DenyShellguardWithoutMasking`.
- `internal/audit/severity.go` (new): Go security rule and severity categorization helper.
- `internal/audit/sqlite.go` (modified): `Breaches()` and `AgentsSummary()` queries + index `idx_events_decision_rule_time`.
- `internal/server/server.go` (modified): Added `testRunMu sync.Mutex` and registered new endpoints.
- `internal/server/admin.go` (modified): Handlers for `breaches`, `agents-summary`, `rotate`, `modules`, `test-run`.
- `internal/server/admin_breaches_test.go` (new): Unit tests for breaches, agents summary, key rotation, and test runner.
- `internal/server/server_test.go` (modified): Removed `t.Parallel()` from `TestMetrics` to prevent global metric reset race.

### Frontend (`owl` Next.js Dashboard)
- `owl/lib/severity.ts` (new): Severity classification and incident deduplication engine.
- `owl/lib/severity.test.ts` (new): Unit tests for severity classification and deduplication.
- `owl/lib/schema.ts` (modified): Types for breaches, agent summary, key rotation, policy test run.
- `owl/lib/engine.ts` (modified): Engine API client methods for breaches, summary, rotation, modules, test-run.
- `owl/lib/queries.ts` (modified): React Query hooks for new endpoints.
- `owl/components/nav.tsx` (modified): Added Breaches and Policy Explorer navigation entries.
- `owl/components/agents/agents-table.tsx` (modified): Updated table with KILL badge and Breaches 24h count.
- `owl/components/agents/agent-decisions-tab.tsx` (modified): Added all stages to stage filter dropdown.
- `owl/app/(dash)/agents/page.tsx` (modified): Connected to `useAgentsSummary("24h")`.
- `owl/app/(dash)/agents/[keyId]/page.tsx` (modified): Rebuilt as Observability View with Mode B design, keyboard shortcuts, sparkline, effective policy card, and breach panel.
- `owl/app/(dash)/agents/[keyId]/edit/page.tsx` (new): Relocated existing policy/team editor form.
- `owl/app/(dash)/breaches/page.tsx` (new): Breach Center dashboard with KPI cards, incident table, filters, and SSE toggle.
- `owl/app/(dash)/policy/page.tsx` (modified): Read-only Policy Explorer with test execution and module inventory.
- `owl/app/(dash)/decisions/page.tsx` (modified): Expanded stage filter dropdown.
- `owl/app/api/audit/breaches/route.ts` (new): Next.js proxy route for `/v1/audit/breaches`.
- `owl/app/api/audit/agents-summary/route.ts` (new): Next.js proxy route for `/v1/audit/agents-summary`.
- `owl/app/api/admin/keys/[keyId]/rotate/route.ts` (new): Next.js proxy route for key rotation.
- `owl/app/api/policy/modules/route.ts` (new): Next.js proxy route for `/v1/policy/modules`.
- `owl/app/api/policy/test-run/route.ts` (new): Next.js proxy route for `/v1/policy/test-run`.

---

## 5. Verification Instructions for Hermes

1. **Verify Git Working Tree State**:
   ```bash
   git status -s
   ```
   *Expectation*: Working copy clean of temporary artifacts, untracked and modified files match section 4 above. No commits made.

2. **Run Full Repository Test Suite**:
   ```bash
   make test
   ```
   *Expectation*: All packages pass with `-race` enabled.

3. **Run Policy Tests**:
   ```bash
   opa test policies/ -v
   ```
   *Expectation*: `PASS: 282/282`.

4. **Run Owl Tests & Production Build**:
   ```bash
   cd owl
   npm test
   npm run build
   ```
   *Expectation*: 55 Vitest tests pass; Turbopack builds all 21 static pages successfully.

5. **Run Linter**:
   ```bash
   golangci-lint run
   ```
   *Expectation*: 0 issues reported.
