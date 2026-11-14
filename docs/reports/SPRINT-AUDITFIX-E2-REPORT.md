# SPRINT REPORT: Cerberus Audit-Fix Batch E2 — Policy Loader/Coverage + Engine/Ratelimit

## Executive Summary
Batch E2 completes the audit fixes across clusters B & C (Policy Loader/Coverage and Engine/Rate Limiting), strictly disjoint from Batch E1. All 11 items have been implemented, tested with race detection, verified with 0 linter issues, and checked for clean formatting.

---

## Detailed Item Fixes & Architecture

### E2.1: `decodeData` Single-Pass Decoding
- **Location**: `internal/policy/loader.go:107-130`
- **Issue**: `decodeData` performed double unmarshaling: first into `var keys map[string]json.RawMessage` to validate top-level keys, then again into `var data map[string]any` to decode values.
- **Fix**: Streamlined into a single-pass unmarshal directly into `var data map[string]any`. Validates top-level keys and required keys (`config`, `agents`) directly against `data` map keys.
- **Results**: Eliminates an entire redundant JSON unmarshaling pass and raw message slice allocations. Benchmark `BenchmarkDecodeData` confirms fast, allocation-efficient parsing (~37.4 µs/op).

### E2.2: Coverage-Gate: Caller Context, Pre-Staging Outside `s.mu`, and Goroutine Drain
- **Location**: `internal/policy/coverage.go:31-60`, `internal/policy/bundle.go:375-440`
- **Issue**: `bundle.go` ran full OPA test-suite synchronously while holding `Store.mu`, blocking concurrent operations (`ReplaceData`, `Reload`) during bundle installation. `coverage.go` created an isolated `context.Background()` and ignored test failures (`tr.Fail` / `tr.Error`), leaking test runner goroutines if returning early.
- **Fix**:
  1. Updated `ComputeCoverage(ctx context.Context, policyDir string) (*CoverageReport, error)` to accept caller's context.
  2. Moved staging directory creation, Rego compilation, smoke tests, and bundle coverage evaluation BEFORE `s.mu.Lock()` in `LoadBundle`.
  3. Fully drained the `runner.RunTests(ctx, nil)` channel before returning, avoiding goroutine leaks in OPA tester, and returning an error if any test fails (`tr.Fail` or `tr.Error != nil`).
  4. Bundles with test files (`_test.rego`) now stage those test files into `tmpDir` so that `ComputeCoverage` can execute and validate bundle tests before store activation.
- **Tests**:
  - `TestStore_LoadBundle_RedSuiteRejected`: Verifies bundles with failing test cases are cleanly rejected before activation.
  - `TestStore_LoadBundle_PrestagingDoesNotBlockConcurrentReload`: Confirms concurrent `ReplaceData` / `Reload` calls proceed without waiting on bundle test coverage staging.

### E2.3: `Snapshot.Modules` Foundation for Post-Query
- **Location**: `internal/policy/snapshot.go:25`, `internal/policy/loader.go:66-78`
- **Issue**: Needed parsed AST modules preserved on `Snapshot` for subsequent post-query analysis without re-parsing rego files.
- **Fix**: Added `Modules map[string]*ast.Module` to `policy.Snapshot`. Populated via `result.ParsedModules()` from the existing OPA loader invocation—zero redundant parses.
- **Tests**: `TestLoad_BuildsQuery` validates `snap.Modules` is populated for all parsed policies while eval decisions remain identical.

### E2.4: `OnSwap` Unsubscribe Lifecycle
- **Location**: `internal/policy/store.go:24-85`, `internal/engine/engine.go:65,95`, `internal/ratelimit/limiter.go:102,115`
- **Issue**: `Store.OnSwap` appended callbacks indefinitely without an unsubscribe mechanism, accumulating subscriptions over component lifetimes.
- **Fix**:
  1. `Store.OnSwap(f func(*Snapshot)) func()` now returns a cancellation closure that atomically removes the registered callback from `s.onSwaps`.
  2. Exposed `SwapCallbacksLen() int` for test verification.
  3. Added `(e *Engine) Close()` and `(l *Limiter) Close()` to trigger unsubscribe on component cleanup.
- **Tests**:
  - `TestStore_OnSwap_Unsubscribe`
  - `TestEngine_New_OnSwapLifecycle` (100x loop confirms stable callback count)
  - `TestLimiter_New_OnSwapLifecycle` (100x loop confirms stable callback count)

### E2.5: Metric Epoch Cardinality Bound
- **Location**: `internal/engine/metrics.go:65-75`, `internal/engine/engine.go:95-102`
- **Issue**: `cacheHitsEpoch` and `cacheMissesEpoch` retained time-series labels per epoch without resetting, causing Prometheus metric series to grow unbounded over policy reloads.
- **Fix**: Added `ResetEpochMetrics()` which calls `.Reset()` on both `cacheHitsEpoch` and `cacheMissesEpoch`. Invoked during each snapshot swap callback in `Engine`.
- **Tests**: `TestEngine_ResetEpochMetrics_OnSwap` uses `prometheus/testutil.CollectAndCount` to verify metric series count remains bounded at 1 across multiple reloads.

### E2.6: `rule_id` Metric Cardinality Bound
- **Location**: `internal/policy/snapshot.go:27`, `internal/policy/loader.go:132-160`, `internal/engine/engine.go:187,415-425`
- **Issue**: `decisionsTotal` metric recorded client or arbitrary rule IDs without bounding, presenting a potential label cardinality explosion vector.
- **Fix**:
  1. Data-driven rule ID collection: `Snapshot.RuleIDs` collects rule IDs from rego AST objects and engine internal rules (`internal.default`, `internal.unknown_stage`, `internal.eval_error`, `internal.timeout`).
  2. `metricRuleID(snap, ruleID)` whitelists registered rule IDs and collapses any unrecognized rule ID to `"other"`.
- **Tests**: `TestEngine_RuleID_CardinalityBound` asserts unknown rule IDs map to `"other"`.

### E2.7: Dynamic `metricStage` Label Set
- **Location**: `internal/policy/snapshot.go:26`, `internal/policy/loader.go:162-185`, `internal/engine/engine.go:425-438`
- **Issue**: `metricStage` previously had a hardcoded list omitting stages such as `"ssh"` and `"db"`.
- **Fix**:
  1. Dynamically extracts registered stages from module AST package declarations (`package stages.<stage>`) and `data.stages`.
  2. `metricStage(snap, stage)` returns the stage name if registered in `snap.Stages` (or in standard stages: `llm`, `tool`, `http`, `docker`, `ssh`, `db`), mapping unknown stages to `"other"`.
- **Tests**: `TestEngine_MetricStage_Dynamic` confirms `"ssh"` and `"db"` map to valid labels, while unknown stages map to `"other"`.

### E2.8: Elimination of Double Deep-Copy on LLM Messages
- **Location**: `internal/masking/masking.go:80-95`, `internal/engine/engine.go:320-330`
- **Issue**: `applyPromptMasking` manually duplicated `in.Messages` slice and map elements, then immediately passed them into `masking.Apply`, which performed a second full deep copy.
- **Fix**: Added support for `[]map[string]any` directly in `masking.Apply`, eliminated the manual pre-copy loop in `applyPromptMasking`, and invoked `masking.Apply(rules, "response", in.Messages)` directly.
- **Tests**: `TestEngine_MaskPrompt_AllocsReduction` and existing masking unit tests verify correctness and reduced allocations.

### E2.9: Ratelimit Cleanup: In-Lock I/O Removal, Dead Fields, and Static Aliases
- **Location**: `internal/ratelimit/limiter.go`
- **Issue**:
  1. DB query fallback was executed inside `kl.mu.Lock()`, introducing blocking I/O under lock.
  2. Unused dead fields: `cfg` on `keyLimiter`, `curEpoch` on `Limiter`, and `IsQuotaAlert` on `Verdict` (0 consumers).
  3. Repeated date formatting string `"20060102"` and dynamic variadic slice allocations for alias lookups.
- **Fix**:
  1. Removed the fallback query branch inside `kl.mu` (prefetch outside lock suffices; race window handled on next call).
  2. Removed `cfg` and `curEpoch` fields. Removed `IsQuotaAlert` field from `Verdict`.
  3. Defined package constant `const dayLayout = "20060102"` and pre-allocated static alias slices (`rpmAliases`, `burstAliases`, `toolHourlyAliases`, `dailyQuotaAliases`).
- **Tests**: `internal/ratelimit` tests all passing; `git grep` confirms no remaining references to dead fields.

### E2.10: Config Named Defaults
- **Location**: `internal/config/config.go:15-25, 56-62`
- **Issue**: Hardcoded default strings (`":8089"`, `"policies"`, `"data/prod.json"`, `"cerberus.db"`) used in `config.Load`.
- **Fix**: Defined named constants in the main const block:
  - `DefaultAddr = ":8089"`
  - `DefaultPolicyDir = "policies"`
  - `DefaultDataFile = "data/prod.json"`
  - `DefaultAuditDB = "cerberus.db"`
- **Tests**: `internal/config` tests passing.

### E2.11: `main.go` Comma-OK Type Assertion
- **Location**: `cmd/cerberus/main.go:106`
- **Issue**: Direct type assertion `data["agents"].(map[string]any)` could panic during boot if PostgreSQL data lacked an `"agents"` map.
- **Fix**: Replaced with safe comma-ok type assertion `agents, _ := data["agents"].(map[string]any)`.
- **Tests**: `TestBootFromPostgres_NoAgentsDoesNotPanic` in `cmd/cerberus/main_test.go`.

---

## Verification Summary
- **Compilation**: `go build ./...` passed across all binaries and packages.
- **Linter**: `golangci-lint run` passed with 0 issues.
- **Formatting**: `gofmt -l .` verified clean (0 files changed).
- **Concurrency & Race Detection**: `go test -race -count=1 ./...` verified clean across all packages.
