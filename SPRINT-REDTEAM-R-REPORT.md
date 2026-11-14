# SPRINT REPORT: Cerberus RED-TEAM FIX Batch R — 7 P0 Vulnerabilities

## Executive Summary
Batch R resolves all 7 critical (P0) security vulnerabilities identified by the Opus and Argon red-team audits (verified by Hermes) for Cerberus. The fixes eliminate agent identity impersonation, lock down substring allowlist bypasses in Rego policies, guard against core package declaration hijacking and path-traversal in policy bundles, enforce fail-closed size and JSON integrity gates on LLM responses in `cerberus-tap`, eliminate dangerous Unix domain socket auto-admin privileges, fix vacuum smoke gates in closed mode, and guarantee data fidelity during rollback and PostgreSQL mirroring.

All changes strictly adhere to the project constraints: no commits or pushes, zero new external dependencies, no modifications to `cluster.go`, preserved constant-time comparisons, and 100% compliance across all quality gates (`go build ./...`, `go test -race -count=1 ./...`, `make opa-check`, `make opa-test` 182/182, `golangci-lint run` 0 issues, and `gofmt -s` clean).

---

## Detailed Vulnerability Analysis & Fixes

### R1 (P0 AUTH): Agent Key Impersonation — Secret Binding
- **Files & Lines**:
  - `internal/server/decide.go:42-83`
  - `sdk/go/client.go:27, 43-46`
  - `docs/SETUP.md:64, 66-96`
  - `internal/server/server_test.go:1385-1456`
- **Vulnerability**: `POST /v1/decide` accepted unauthenticated `key_id` values from the request body without credentials, allowing any network caller to impersonate arbitrary agents and inherit their permissions.
- **Fix**:
  - `internal/server/decide.go`: Added extraction and verification of the `X-Agent-Key` HTTP header. If the agent configuration in `data.agents.<key_id>` contains `api_key_sha256` (hex-encoded SHA-256), the server verifies `subtle.ConstantTimeCompare(sha256(header), hash) == 1`. Requests with missing or incorrect keys are rejected with HTTP 401 (`agent_key_required` / `agent_key_invalid`) immediately without evaluating Rego policies.
  - Added support for `CERBERUS_REQUIRE_AGENT_KEYS=true`: in this mode, all non-admin decide requests must supply a valid key matching an agent with a configured `api_key_sha256`; unkeyed agents are rejected with HTTP 401.
  - Requests carrying a valid admin bearer token (`Authorization: Bearer <CERBERUS_ADMIN_TOKEN>`) bypass agent secret checks.
  - `sdk/go/client.go`: Added `AgentKey` to `ClientOptions`, automatically sending `X-Agent-Key` on requests.
  - `docs/SETUP.md`: Added configuration and usage guide for `CERBERUS_REQUIRE_AGENT_KEYS`, `api_key_sha256`, and the `X-Agent-Key` header.
- **Tests**:
  - `internal/server/server_test.go:TestDecide_AgentKeyAuthentication`:
    - Agent with hash: no header -> 401 `agent_key_required`
    - Agent with hash: invalid key -> 401 `agent_key_invalid`
    - Agent with hash: valid key -> 200 OK
    - Agent without hash + `CERBERUS_REQUIRE_AGENT_KEYS=false` -> 200 OK (legacy backward-compatible)
    - Agent without hash + `CERBERUS_REQUIRE_AGENT_KEYS=true` -> 401 `agent_key_required`
    - Admin bearer token bypass -> 200 OK

---

### R2 (P0 REGO): Allowlist Substring Match Bypass → Exact / Suffix Matching
- **Files & Lines**:
  - `policies/gateway/authz.rego:157-196`
  - `policies/stages/http.rego:111-118`
  - `policies/stages/ssh.rego:59-65`
  - `policies/testdata/data.json:20`
  - `policies/stages/http_test.rego:261-295`
  - `policies/stages/ssh_test.rego:108-175`
- **Vulnerability**: `policies/gateway/authz.rego`, `policies/stages/http.rego`, and `policies/stages/ssh.rego` used `contains(lower(target), lower(pattern))` for host and tool matching. An attacker could register domains such as `api.teknikal.id.evil.com` to bypass `api.teknikal.id` allowlists.
- **Fix**:
  - `policies/gateway/authz.rego`:
    - `host_matches(pattern, host)`: Enforces exact match `lower(host) == lower(pattern)` OR suffix matching when `startswith(pattern, "*.")` where `endswith(lower(host), lower(pattern[1:]))`, host does not contain userinfo (`not contains(host, "@")`), and host != pattern.
    - `call_matches_pattern(pattern, tool_call)`: Enforces exact equality `lower(tool_call) == lower(pattern)` OR glob matching `glob.match(lower(pattern), [], lower(tool_call))` only if `contains(pattern, "*")`.
    - `pattern_matches`: Replaced substring `contains` with `call_matches_pattern`.
  - `policies/stages/http.rego` & `policies/stages/ssh.rego`: Delegated all host checking to `authz.host_matches`.
  - `policies/testdata/data.json`: Updated `k-glob` `restricted_tool_calls` from `["delete"]` to `["*delete*"]` to explicitly match glob semantics.
- **Tests**:
  - `policies/stages/http_test.rego`: Added tests verifying `evil.com` suffix and `api.teknikal.id.evil.com` are blocked, while exact matches pass.
  - `policies/stages/ssh_test.rego`: Added tests verifying wildcard `*.teknikal.id` allows `api.teknikal.id` and `bastion.teknikal.id` but denies `evil.teknikal.id.evil.com`.
  - Quality gate: `opa check --strict policies/` (0 warnings/errors) and `opa test policies/ -v` (182/182 PASS).

---

### R3 (P0 BUNDLE): Package-Decl Guard + Prefix Strip Bypass
- **Files & Lines**:
  - `internal/policy/bundle.go:132-156, 193-219`
  - `internal/policy/bundle_test.go:420-466`
- **Vulnerability**: Bundles containing files such as `stages/helper.rego` with `package gateway.authz` merged arbitrary rules directly into core evaluation packages; `safeRel` only stripped a single `policies/` prefix, allowing nested paths like `policies/policies/gateway/authz.rego` to evade path restrictions.
- **Fix**:
  - `internal/policy/bundle.go`:
    - Updated `safeRel` to repeatedly strip `policies/` or `policies\` in a loop until none remain.
    - In `ReadBundle`, parsed every `.rego` file using `ast.ParseModule`. Added package declaration enforcement: rejected any file declaring package `gateway`, `shield`, or subpackages (`gateway.*`, `shield.*`) unless the file path is explicitly within permitted core paths (`gateway/` or `shield/`).
- **Tests**:
  - `internal/policy/bundle_test.go`:
    - `TestSafeRel`: Verifies single, repeated (`policies/policies/gateway/...`), and root paths are properly stripped and normalized.
    - `TestStore_BundleCorePackageDeclRefused`: Verifies that a bundle containing `stages/helper.rego` declaring `package gateway.authz` is cleanly rejected with `core package declaration not permitted`.

---

### R4 (P0 TAP): Fail-Closed Non-SSE Large / Invalid Payload Gate
- **Files & Lines**:
  - `cmd/cerberus-tap/main.go:452-474`
  - `cmd/cerberus-tap/main_test.go:825-866`
- **Vulnerability**: When an upstream non-SSE response exceeded `maxBody` (2MB), `json.Unmarshal` failed silently on the truncated buffer, bypassing tool call inspection while forwarding the full response body to the client.
- **Fix**:
  - `cmd/cerberus-tap/main.go`: In the non-SSE response inspection path, if `len(respBody) > maxBody` OR non-SSE `application/json` fails `json.Unmarshal`, the tap now fails closed immediately: denies transmission and returns HTTP 502 with error `response_exceeds_inspection_limit`.
- **Tests**:
  - `cmd/cerberus-tap/main_test.go:TestNonSSEResponseLargePayload`: Emits a 3MB payload containing `tool_use` blocks; verifies the client receives HTTP 502 with `response_exceeds_inspection_limit` and zero forwarded body bytes.

---

### R5 (P0 ADMIN): Unix Socket & RemoteAddr Auto-Admin Trust Elimination
- **Files & Lines**:
  - `internal/server/break_glass.go:96-118`
  - `docs/SETUP.md:65`
  - `internal/server/break_glass_test.go:110-151`
- **Vulnerability**: `isPrivilegedAdmin` returned `true` whenever `RemoteAddr == "@"`, started with `"/"`, or was empty `""`. Behind Unix domain socket reverse proxies, all incoming requests had `RemoteAddr` set to the proxy socket, granting unauthenticated admin access to any caller.
- **Fix**:
  - `internal/server/break_glass.go`: Eliminated auto-trust for empty `RemoteAddr`. Gated Unix domain socket privilege (`@` or `/`) behind an explicit environment variable `CERBERUS_TRUST_UNIX_SOCKET=true` (default: `false`).
- **Tests**:
  - `internal/server/break_glass_test.go:TestPrivilegedAdmin_UnixSocketTrust`:
    - `RemoteAddr == ""` without token -> HTTP 401 Unauthorized
    - `RemoteAddr == "@"` with `CERBERUS_TRUST_UNIX_SOCKET=false` -> HTTP 401 Unauthorized
    - `RemoteAddr == "@"` with `CERBERUS_TRUST_UNIX_SOCKET=true` -> Privileged Admin Granted (200 OK)

---

### R6 (P0 SMOKE): Vacuum Gate in Closed-Mode Elimination
- **Files & Lines**:
  - `internal/policy/smoke.go:40-100`
  - `internal/policy/loader.go:118-135`
  - `policies/testdata/data.json:34-40`
  - `internal/policy/store_test.go:340-383`
- **Vulnerability**: In closed mode (`default_action: deny`), `DryRunSmoke` used `k-stranger-smoke` across all 5 smoke cases. Closed mode returned `config.unknown_key_closed`, which `smoke.go` accepted as a valid deny. Consequently, policy corruption (e.g. deletion of dangerous command restriction rules) still passed smoke testing because unknown keys were denied at the entry gate.
- **Fix**:
  - `internal/policy/smoke.go`: Replaced `k-stranger-smoke` with a dedicated registered fixture `k-smoke-fixture`. Explicitly rejected `gotRule == "config.unknown_key_closed"` during smoke tests.
  - `internal/policy/loader.go`: Added `ensureSmokeFixture` ensuring `k-smoke-fixture` is present with minimal permissions (`allowed_tools: ["bash", "docker rm"]`, `allowed_models: ["gpt-4"]`) in policy snapshot data.
  - `policies/testdata/data.json`: Added `k-smoke-fixture` definition.
- **Tests**:
  - `internal/policy/store_test.go:TestDryRunSmoke_ClosedModeBrokenPolicyFails`: Stripping dangerous command patterns from policy under closed mode causes `DryRunSmoke` to fail fast, preventing broken policies from being loaded.

---

### R7 (P0 DATA): Rollback Masking Fix & PostgreSQL Mirror Synchronization
- **Files & Lines**:
  - `internal/audit/sqlite.go:835-845`
  - `internal/server/admin.go:1115-1145, 1150-1165`
  - `internal/store/pg.go:23, 27-32, 178-182`
  - `internal/audit/logger_test.go:610-630`
  - `internal/server/rules_api_test.go:175-300`
- **Vulnerability**: Revisions recorded in SQLite were masked (`[REDACTED]`) before insertion, resulting in `[REDACTED]` overwriting active secrets when rolled back. Additionally, rollback and data update endpoints omitted calls to `PGMirror.SaveData`, allowing outdated PostgreSQL state to overwrite rolled-back data upon engine restart.
- **Fix**:
  - `internal/audit/sqlite.go`: `recordRevision` now saves raw `data_json` directly into SQLite `data_revisions` table.
  - `internal/server/admin.go`: Sensitive masking is now performed dynamically in `listRevisions` when serving GET `/v1/admin/revisions`.
  - `internal/server/admin.go`: Added `mirrorSaveData` fire-and-forget helper, invoking `s.deps.PGMirror.SaveData` on `putData`, `rollbackData`, `uploadBundle`, and `rollbackBundle`.
  - `internal/store/pg.go`: Added `SaveDataFn` and `NewTestPG` mock constructor for unit verification.
- **Tests**:
  - `internal/server/rules_api_test.go:TestRules_RollbackRestoresRawSecretAndMirrorsPG`:
    - PUT data with secret `mock-token-xyz-12345` -> Revision created, `PGMirror.SaveData` called.
    - PUT updated data -> Second revision created.
    - GET `/v1/admin/revisions` -> Response contains `[REDACTED]` and leaks no raw secret.
    - POST `/v1/admin/rollback` -> Snapshot restored with raw `mock-token-xyz-12345` (NOT `[REDACTED]`).
    - Verifies `PGMirror.SaveData` was invoked asynchronously post-rollback.

---

## Quality Gate Verification Summary

| Quality Gate | Command | Result |
|---|---|---|
| **Build** | `go build ./...` | **PASS** (Exit Code 0, 0 errors) |
| **OPA Policy Syntax** | `opa check --strict policies/` | **PASS** (Exit Code 0, 0 warnings) |
| **OPA Unit Tests** | `opa test policies/ -v` | **PASS** (182/182 passed) |
| **Linter** | `golangci-lint run` | **PASS** (0 issues) |
| **Code Formatting** | `gofmt -s -d .` | **PASS** (Clean, 0 diffs) |
| **Go Race Unit Tests** | `go test -race -count=1 ./...` | **PASS** (All packages passing) |
