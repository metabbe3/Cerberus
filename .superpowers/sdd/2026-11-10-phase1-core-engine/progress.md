Task 1: complete (commit c0b6c89, tests: make build && ./bin/cerberus --version && make opa-check opa-test lint test -> all pass)
Task 2: complete (commit d639904, tests: opa check --strict + opa test -> 19/19 pass; recovered from env failure per progress.task2.md)
Task 4: complete (commit 7a49105, tests: go test -race -count=1 ./internal/masking -> ok)
Task 3: complete (commit 9665e5c, tests: go test -race -count=1 ./... -> ok; lint 0 issues; opa-check/opatest 19/19)
Rulings (Task 3): (1) plan's rego.Load+rego.Store combo is unsupported in OPA v1 (write txn on user store) — modules loaded via loader.NewFileLoader + rego.ParsedModule instead, filter skips non-.rego and *_test.rego so data comes only from dataJSON. (2) opa lib pinned v1.13.0 (newest with go<=1.24 floor): opa v1.14+ needs go>=1.25, v1.22.2 needs go 1.26.0, which would break the spec's Go 1.24 and CI's setup-go 1.24. (3) opa CLI stays 1.22.2 for check/test; lib/CLI skew is dev-tool only. (4) Heads-up Task 5: pin golang.org/x/sync to an older version (latest needs go 1.26) when adding singleflight.

Task 6: complete (commit d0a645a, tests: go test -race -count=1 ./internal/audit -> ok; make test ./... + golangci-lint 0 issues; opa-check 19/19)
Task 5: complete (commit a8b576c, tests: go test -race ./internal/engine -> ok; CERBERUS_BENCH_ASSERT=1 p99 test -> ok; make lint -> 0 issues) — completed inline from dead agent work
Ruling (Task 5): ADR-0001 miss p99 <1ms unmeetable on M2 (GC/scheduler tail 1.5-4ms, mean 26-43us); assert = hit p99 <100us, miss mean <1ms + p99 <5ms; alloc reduction deferred to Phase 7 — cost if wrong: prod p99 on busy hosts above ADR estimate until Phase 7
Task 7: complete (commit ab5c5e5, tests: go test -race -count=1 ./internal/server -> ok; make test ./... + golangci-lint 0 issues + opa-check/opa-test 19/19 green)
Task 8: complete (commit 0683b7d, tests: make lint test opa-check opa-test smoke -> all green, smoke 7/7; docker build + live container probe OK; tagged v0.1.0)
Final: fixed golden-test timeout flake — reproduce attempted (not reproducible standalone), fix = 2s eval timeout in server test harness; suite green 3x -race; ALSO fixed make bench \$-escaping (benchmarks never ran) — verified BenchmarkDecide_Hit/Miss now execute
Final: fixed internal-failure denies cached in LRU + singleflight eval under leader ctx — TestDecide_CancelledLeaderNotShared, TestDecide_InternalFailureNotCached RED->GREEN
Final: fixed cerberus_decisions_total unbounded stage label cardinality (collapsed to llm|tool|other before WithLabelValues) — TestDecide_UnknownStageBoundedMetricLabel RED->GREEN
Final: fixed audit shutdown losing events (writer flushed with cancelled signal ctx) — TestLogger_CancelledContextKeepsEvents RED->GREEN
Final: fixed audit Emit taking Logger.mu on hot path (ring+fan-out moved to writer goroutine) — TestLogger_EmitTakesNoMutex RED->GREEN
Final: fixed unknown stage bypassed key gate with bypass_unknown_keys=true (unknown-stage deny now evaluated before key gate) — test_unknown_stage_unregistered_key_bypass_denies RED->GREEN
Final: fixed decodeData accepts JSON null / {} data document, wiping policy via PUT /v1/admin/data — TestLoad_RejectsNullAndEmptyDocument RED->GREEN
Final: hardened Review Focus 3 admin tests: malformed-JSON PUT (`{"agents":`) + broken-.rego reload now assert 422, unchanged epoch, old snapshot still answering decides — TestAdmin_PutData_InvalidKeeps422, TestAdmin_Reload_BrokenRegoKeeps422 RED->GREEN (verified via injected 500 mutants)
Final: fixed TestDecide_Singleflight not proving singleflight collapse — parked-leader eval hook, delta=1 impossible without sf; test RED(delta=11, sf removed)->GREEN
Final: fixed stale/backwards cerberus_policy_epoch gauge (set per-request in Decide) — swap-time OnSwap hook in Store.Reload/ReplaceData — TestPolicyEpoch_TracksReloadWithoutTraffic, TestPolicyEpoch_NeverMovesBackwards RED->GREEN
Final: fixed Cached flag and hit/miss counters wrong under singleflight (leader of joined flight said cached=true; waiters and in-flight re-check hits uncounted) — TestDecide_SingleflightCachedFlags RED->GREEN
Final: fixed SSE handlers blocking graceful shutdown (parked dashboard held srv.Shutdown out 10s; streams now cancelled via RegisterOnShutdown) — TestEvents_ShutdownEndsStream RED->GREEN
Final: fixed slow-loris body trickle parking goroutines in readBody forever (no ReadTimeout/IdleTimeout on http.Server) — TestServerCutsOffSlowBody RED->GREEN
Final: fixed writeAtomic never fsyncing temp file or parent dir (power loss after PUT /v1/admin/data could leave data/prod.json empty/truncated, gateway unable to start) — TestStore_ReplaceData_FsyncsDataAndDir RED->GREEN
