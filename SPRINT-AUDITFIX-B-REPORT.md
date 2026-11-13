# SPRINT-AUDITFIX-B-REPORT: P2 Reliability & Policy-Correctness Audit Fixes

## Executive Summary
Batch B audit fixes successfully executed across the Cerberus codebase targeting 9 verified P2 reliability and policy-correctness findings identified from the 5-way function-by-function audit review. All fixes are verified with unit and regression tests, adhering to the codebase's conventions and rules. All quality gates (`go build ./...`, `go test -race -count=1 ./...`, `golangci-lint run`, `gofmt -l`, and `opa test policies/`) pass cleanly.

---

## Detailed Item Reports

### B1 (P2) Rollback bundle tidak lengkap (union bukan restore) + tanpa smoke
- **Location**:
  - `internal/policy/store.go:27` (field `prevAddedFiles []string`)
  - `internal/policy/bundle.go:439-465` (`LoadBundle`: tracks files added by new bundle not previously existing on disk in `addedFiles` slice, saved into `s.prevAddedFiles`)
  - `internal/policy/bundle.go:512-575` (`Rollback`: removes `s.prevAddedFiles` in `tmpDir`, overlays previous bundle files, runs `DryRunSmoke(ctx, snap)`, removes `s.prevAddedFiles` on disk in `s.policyDir`, writes back bundle rego/data files, and executes `DryRunSmoke` before storing snapshot)
- **Description**: Previously, `copyDir(policyDir, tmp)` in `Rollback` copied the disk directory that already contained new files introduced by the current bundle. Overlaying the old bundle on top left the newly added `.rego` files intact on disk and in the reloaded snapshot (a union rather than a true rollback). Furthermore, rollback did not invoke `DryRunSmoke`. Fix tracks `addedFiles []string` upon `LoadBundle` in `s.prevAddedFiles`; `Rollback` removes those added files both in the dry-run `tmpDir` and on `policyDir` before overlaying the previous bundle, and executes `DryRunSmoke` before atomic store swap.
- **New Tests**: `internal/policy/bundle_test.go:TestStore_BundleRollback_RestoresFilesAndRunsSmoke` (loads bundle A with 2 files, loads bundle B with A + 1 new file, verifies new file on disk, rolls back, verifies new file from B is deleted on disk, revision restored to A, and DryRunSmoke passes).
- **Status**: PASSED

### B2 (P2) Cluster sync bisa memundurkan policy (regression/flapping)
- **Location**: `internal/server/cluster.go:148-164`, `internal/server/cluster.go:195`
- **Description**: In HA gossip sync, the condition `peerPayload.StartedAt < myPayload.StartedAt || peerPayload.Epoch > myPayload.Epoch` allowed older nodes to win even if they held an older epoch, causing policy regression and flapping. Fix refactors decision into `shouldPullFromPeer(my, peer SyncPayload) bool` where a peer is authoritative only if it has a differing revision or data hash AND its epoch is strictly higher than the local node's epoch, or its epoch is identical and `StartedAt` is lower (tie-breaker). Nodes with lower epochs never overwrite higher-epoch policies regardless of uptime.
- **New Tests**: `internal/server/cluster_test.go:TestCluster_ShouldPullFromPeer_TableDriven` (table-driven test verifying: `{peer older+lower epoch: no pull (prevent regression)}`, `{peer higher epoch: pull}`, `{same epoch, peer older started: pull}`, `{same epoch, peer younger started: no pull}`, and `{identical revision and hash: no pull}`). Existing gossip sync test also passes.
- **Status**: PASSED

### B3 (P2) Query /v1/query: Rego arbitrer = SSRF via http.send
- **Location**: `internal/server/admin.go:879-887`
- **Description**: `postQuery` evaluated arbitrary user-supplied Rego queries via `rego.Query(q)` without builtin filtering, creating SSRF and data exfiltration hazards via builtins such as `http.send`. Fix parses query string `q` and rejects queries containing `http.send`, `opa.runtime`, `net.`, or `crypto.` with an immediate HTTP 400 Bad Request (`query contains forbidden builtin or function: ...`).
- **New Tests**: `internal/server/rest_api_test.go:TestServer_QueryAPI_SSRF_Protection` (tests queries containing `http.send`, `opa.runtime`, `net.`, `crypto.` each returning 400 Bad Request, while legitimate queries like `data.gateway.authz.decision` return 200 OK).
- **Status**: PASSED

### B4 (P2) Rollback bundle tanpa audit trail
- **Location**: `internal/server/admin.go:648-662`
- **Description**: `rollbackBundle` (`POST /v1/admin/bundle/rollback`) restored the previous bundle snapshot without emitting an audit event, leaving no trail for bundle rollbacks. Fix emits an audit event with `RuleID: "admin.bundle.rollback"`, `KeyID: author` (extracted from `X-Admin-User` header or defaulted to `"admin"`), `Epoch: snap.Epoch`, `Reason: "rollback to revision " + snap.Revision`, `Decision: "allow"`, and `Stage: "admin"` before responding with 200 JSON.
- **New Tests**: `internal/server/bundle_e2e_test.go:TestBundle_E2E_BuildSignUploadSmokeRollback` (asserts that POST `/v1/admin/bundle/rollback` with `X-Admin-User: test-admin` records an `admin.bundle.rollback` audit event with expected KeyID, Epoch, and Reason).
- **Status**: PASSED

### B5 (P2) err.Error() mentah ke respons (~12 titik) — sanitasi
- **Location**:
  - `internal/server/admin.go:357-361` (helper `writeInternalErr`)
  - `internal/server/admin.go:232, 382, 465, 585, 801, 915, 936, 1134` (replaced raw 500 error messages)
  - `internal/server/templates.go:32, 74` (replaced raw 500 error messages)
- **Description**: Multiple 500 Internal Server Error response locations returned raw `err.Error()` strings directly to clients, potentially leaking internal filesystem paths, directory structures, and database errors. Fix introduces `writeInternalErr(w http.ResponseWriter, err error)` which logs the underlying error detail with `slog.Error("internal error", "err", err)` and outputs a sanitized generic JSON error `{"error": "internal error"}` with HTTP 500. All raw 500 writeErr calls in `admin.go` and `templates.go` were updated.
- **New Tests**: `internal/server/server_test.go:TestAdmin_PolicyValidate_InternalErrorSanitized` (forces `validatePolicy` failure by removing the policies directory; asserts HTTP 500 response, verifies body contains `"internal error"` and does NOT leak the internal directory path, and verifies detailed error was logged).
- **Status**: PASSED

### B6 (P2) Peer body unbounded read (OOM via peer jahat)
- **Location**:
  - `internal/server/cluster.go:21-25` (constants `maxClusterBundleBytes = 64 << 20` and `maxClusterAuditBytes = 32 << 20`)
  - `internal/server/cluster.go:228-235` (`pullBundle`: wrapped with `io.LimitReader`)
  - `internal/server/cluster.go:320` (`queryClusterAudit`: wrapped with `io.LimitReader`)
- **Description**: `pullBundle` in `cluster.go` previously read the entire peer HTTP response into memory via `io.ReadAll(resp.Body)` without byte limit. Similarly, cluster audit fan-out decoded JSON array bodies without bounds, posing an OOM vulnerability if a rogue peer returned an unbounded payload. Fix applies `io.LimitReader(resp.Body, maxClusterBundleBytes+1)` in `pullBundle` (returning an error if size exceeds 64MB) and `io.LimitReader(resp.Body, maxClusterAuditBytes+1)` in `queryClusterAudit` (capping audit JSON decode at 32MB).
- **New Tests**: `internal/server/cluster_test.go:TestCluster_PullBundle_ExceedsLimit` (streams 65MB from a fake peer handler; asserts that `pullBundle` terminates cleanly with `"exceeds max size"` error without panic or OOM).
- **Status**: PASSED

### B7 (P2) Daily-count DB fetch di dalam critical section
- **Location**: `internal/ratelimit/limiter.go:153-167`, `internal/ratelimit/limiter.go:210-235`
- **Description**: In `Limiter.Allow`, `DailyToolCallsCount` was queried while holding `kl.mu.Lock()`. If the SQLite query blocked or took time, all concurrent requests for that key (including non-tool calls and fast evaluations) were serialized behind database I/O. Fix checks `needsFetch` and queries `l.audit.DailyToolCallsCount` outside the lock before acquiring `kl.mu.Lock()`. Inside `kl.mu.Lock()`, a double-check guard ensures that if another concurrent goroutine has already populated `kl.dailyChecked = true`, the limiter adopts the existing count rather than overwriting or re-querying.
- **New Tests**: `internal/ratelimit/limiter_test.go:TestLimiter_ConcurrentAllow_NoDeadlockWithSlowAudit` (spawns 50 concurrent goroutines calling `Allow` against a 100ms slow audit stub; completes in ~0.10s without deadlock. All existing ratelimit tests pass).
- **Status**: PASSED

### B8 (P2) Docker rego: action destruktif dikecualikan dari write-allowlist
- **Location**:
  - `policies/stages/docker.rego:196-199` (`docker_write_action`)
  - `policies/stages/docker_test.rego:44-47, 168-176`
- **Description**: In `docker.rego`, both `image_not_allowed` and `docker_write_action` contained `not action in ["rm", "rmi", "delete", "down", "stop", "kill"]`. This meant that destructive actions on non-protected containers were completely exempted from the `docker_write_allowlist` requirement, allowing anyone (including unprivileged strangers in onboarding mode) to stop, kill, or remove non-protected containers. Fix removes the destructive action exclusion from `docker_write_action` so destructive actions require explicit allowlist permission in `docker_write_allowlist`, while retaining the exclusion in `image_not_allowed` (since image checks do not apply to container lifecycle stops/kills).
- **New Tests**: `policies/stages/docker_test.rego:test_docker_stranger_stop_denied` (stranger in bypass mode attempting `stop box-x` is denied with `docker.write_not_allowlisted`), `test_docker_stop_normal_allowed` (agent with `stop` permission in allowlist is allowed with `docker.allow`), and `test_docker_rm_protected_denied` (protected container deletion remains blocked by shield with `shield.container.protected`).
- **Status**: PASSED (OPA test suite: 174/174 passed)

### B9 (P2) Sighup/reload data prod_shield smoke-lockout: closedMode detection
- **Location**:
  - `internal/policy/smoke.go:127-133`
  - `internal/policy/store_test.go:314-350`
- **Description**: In `internal/policy/smoke.go`, `closedMode` was calculated as `closedMode := false; if v, ok := cfg["bypass_unknown_keys"].(bool); ok { closedMode = !v }`. If `bypass_unknown_keys` was omitted from `config` in `data.json`, `closedMode` evaluated to `false`. Consequently, smoke test fixture `ls allow` ran with an unregistered key `k-stranger-smoke` expecting `"allow"`. Because Rego default is fail-closed (`config.unknown_key_closed`), `DryRunSmoke` always failed, causing reloads or SIGHUP updates without the explicit flag to fail and permanently brick the admin plane. Fix defaults `closedMode = true`, setting it to `false` only when `bypass_unknown_keys == true` explicitly.
- **New Tests**: `internal/policy/store_test.go:TestDryRunSmoke_ClosedModeDefault` (verifies `DryRunSmoke` passes on data missing `bypass_unknown_keys` flag under default closed mode, and also passes on data where `bypass_unknown_keys == true`).
- **Status**: PASSED

---

## Final Verification Gates Summary

| Quality Gate | Target Command | Result | Details |
|---|---|---|---|
| **Build** | `go build ./...` | **PASS** | Clean build across all packages and CLI binaries |
| **Race Tests** | `go test -race -count=1 ./...` | **PASS** | All unit, integration, and E2E tests green across the entire repository |
| **Linter** | `golangci-lint run` | **PASS** | 0 issues |
| **Formatting** | `gofmt -l cmd/ pkg/ internal/` | **PASS** | Clean formatting (0 files formatted) |
| **OPA Policy Tests** | `opa test policies/` | **PASS** | 174/174 passed (+1 new test case) |
| **Security/Hygiene** | Working tree inspection | **PASS** | No secrets hardcoded, no dependencies added, `owl/` untouched |
