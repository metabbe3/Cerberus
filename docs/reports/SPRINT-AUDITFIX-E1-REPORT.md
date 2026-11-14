# Sprint Audit-Fix Batch E1 Report: SQLite Audit Lifecycle

**Date:** 2026-11-14  
**Workspace:** `/Users/nicholasandriansurjadi/Documents/cerberus`  
**Status:** Completed & All Gates Passing

---

## 1. Executive Summary

Batch E1 addresses 10 critical reliability, concurrency, performance, and dead-code items across `internal/audit/sqlite.go`, `internal/audit/logger.go`, and `internal/store/pg.go`. All strict guardrails were observed:
- Checkpoints exclusively execute `PRAGMA wal_checkpoint(PASSIVE)` (non-blocking) — TRUNCATE/RESTART are completely avoided.
- WAL size bound configured via writer DSN `_pragma=journal_size_limit(67108864)` (64MB) without runtime pragma churn.
- Queries on the active daily partition reuse the `m.dbs[dayKey]` writer handle without closing it.
- Historical daily files are managed through a concurrent read pool `m.readDBs` (`SetMaxOpenConns(2)`), properly evicted on prune/close, with zero DDL on read paths.

---

## 2. Itemized Implementation Report

### E1.1: Read-Pool Per Daily File
- **Source:** `internal/audit/sqlite.go:68,85,163-192,455-468,680-692,1005-1017`
- **Changes:**
  - Added `readDBs map[string]*sql.DB` to `dbManager` guarded by `m.mu`.
  - Added `getDBForFileRead(fn string) (*sql.DB, error)`: checks active writer handles in `m.dbs[dayKey]` first (reusing active handle per Guardrail 3); on historical files, checks `readDBs` cache; on miss, opens via `openSQLiteRead(fullPath)`, sets `SetMaxOpenConns(2)`, and stores in cache.
  - Updated `query`, `denyCountsSince`, and `queryAggregate` to retrieve handles via `getDBForFileRead` and removed all individual `db.Close()` calls.
  - Evicted and closed all cached handles in `dbManager.prune` and `dbManager.close`.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_1_ReadPoolReuseAndConcurrentQuery`
  - Validates cache miss on first read pass, zero opens (cache hit) on second pass, and 10 concurrent goroutines querying under `-race`.
- **Status:** PASS

### E1.2: maxID Boot Uses Lightweight Path
- **Source:** `internal/audit/sqlite.go:275-296`
- **Changes:**
  - Switched `openSQLite(p)` in `maxID` to `openSQLiteRead(p)`.
  - Avoids executing `PRAGMA journal_mode=WAL`, `os.Chmod`, and full schema table/index creation DDL at boot.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_2_MaxIDBootLightweightNoDDL`
  - Creates 30 empty/fake `.db` files at boot, calls `maxID()`, and asserts all 30 files remain untouched (0 bytes, no schema DDL, no `-wal` or `-shm` generated).
- **Status:** PASS

### E1.3: Timeseries Skip Old Daily Files
- **Source:** `internal/audit/sqlite.go:995-1004`
- **Changes:**
  - Added date inspection guard `if t.Add(24 * time.Hour).Before(since) { break }` inside `queryAggregate` file loop.
  - Since files are sorted descending (newest first), loops break immediately once older day files fall outside the requested window.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_3_TimeseriesSkipOldFiles`
  - Populates partitions for 3 days ago, 2 days ago, and today. Queries past 30-minute window and verifies old files are never opened.
- **Status:** PASS

### E1.4: Persistent Prepared INSERT Statement
- **Source:** `internal/audit/sqlite.go:69,86,194-273,349-397`
- **Changes:**
  - Added `insertStmts map[string]*sql.Stmt` to `dbManager`.
  - Created `getDBAndStmtForTime(t time.Time)` which prepares `insertStmtSQL` once per daily partition and reuses it across flushes via `tx.StmtContext(ctx, stmt)`.
  - Added `invalidateStmt(dayKey)` to close and re-prepare the statement only when execution fails.
  - Closed and evicted statements in `prune` and `close`.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_4_PersistentPreparedInsert`
  - Validates cached statement presence and measures allocations via `testing.AllocsPerRun` (58 allocs/op for batch insert).
- **Status:** PASS

### E1.5: WAL Size Bound + Passive Checkpoint
- **Source:** `internal/audit/sqlite.go:159-166,179,194-200,523-527`
- **Changes:**
  - Created `sqliteDSNWriter(path)` with `_pragma=busy_timeout(2000)&_pragma=journal_size_limit(67108864)`.
  - Configured `openSQLite` to use `sqliteDSNWriter(path)`.
  - Confirmed checkpoints strictly execute `PRAGMA wal_checkpoint(PASSIVE)` (non-blocking) during `prune` and day rotation in `passiveCheckpointOlderDaysLocked`.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_5_WALBoundAndPassiveCheckpointUnderLoad`
  - Ingests 1000 events while 5 concurrent goroutines query in a tight loop. Asserts zero `SQLITE_BUSY` errors and verifies WAL size remains `<= 64MB`.
- **Status:** PASS

### E1.6: Single Definition of RetentionDays
- **Source:** `internal/audit/sqlite.go:22-23,79` and `internal/audit/logger.go:98`
- **Changes:**
  - Defined single exported constant in `internal/audit/sqlite.go`: `const DefaultRetentionDays = 30`.
  - Updated `newDBManager` and `Open` in `logger.go` to use `DefaultRetentionDays` instead of magic numbers.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_6_DefaultRetentionDays`
  - Asserts `DefaultRetentionDays == 30` and verifies fallback when `RetentionDays <= 0`.
- **Status:** PASS

### E1.7: Prune Guard Active and Backdated Files
- **Source:** `internal/audit/sqlite.go:543-554` and `internal/audit/logger_test.go:477-482`
- **Changes:**
  - Guarded `dbManager.prune`: skips files where `dateStr` is active in `m.dbs` OR file mtime `< 24h` (`time.Since(info.ModTime()) < 24*time.Hour`).
  - Protects backdated writes and active writer partitions from premature unlinking.
  - Updated legacy partition test in `logger_test.go` to explicitly backdate mtime via `os.Chtimes` to simulate genuinely aged partitions.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_7_PruneGuardActiveAndBackdated`
  - Writes backdated event for yesterday with 1-day retention and touches an ancient 10-day-old file; verifies yesterday's file survives prune while ancient file is removed.
- **Status:** PASS

### E1.8: Dead Code & Redundant Metrics Cleanup
- **Source:** `internal/audit/logger.go:26-31,51-56,171-177,348` and `internal/audit/sqlite.go:328-360`
- **Changes:**
  - Deleted unused method `SetMaskRulesFunc(fn)`.
  - Removed unused field `MaskRules []masking.Rule` from `audit.Options`.
  - Removed `extraRules` parameter from `dbManager.insertBatch`.
  - Deleted duplicate metric `AuditShipDroppedTotal` (`cerberus_audit_ship_dropped_total`) and its increments. Preserved `ShipDropCount` (`cerberus_ship_drops_total`) required by `internal/server/server_test.go:724`.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_8_ShipperMetricSingleDefinition` and `internal/server/server_test.go:TestV1Metrics_AuthAndContent`
  - Grep verification confirms zero residual references; shipper overflow test verifies `cerberus_ship_drops_total` increments properly.
- **Status:** PASS

### E1.9: Logger.Prune Wired to Startup
- **Source:** `internal/audit/logger.go:136-150`
- **Changes:**
  - Documented `Logger.Prune(now time.Time)` as an exported operational API for CLI and testing.
  - Wired startup call `_ = l.Prune(time.Now().UTC())` inside `Open` following background worker startup.
- **Tests:** `internal/audit/lifecycle_test.go:TestE1_9_StartupPruneWired`
  - Asserts prune count increments automatically upon `Open()`.
- **Status:** PASS

### E1.10: PG Store Hygiene
- **Source:** `internal/store/pg.go:188-191,217-220,240-243,271-274,282-285,293-296,322-325`
- **Changes:**
  - `ListTemplates`: checks `json.Unmarshal([]byte(pol), &polDoc)` error and returns an explicit `fmt.Errorf("store: unmarshal template %s policy: %w", id, err)` instead of silently emitting null policies.
  - `saveData`: captures `err` on `json.Marshal` for config, agent policy, team policy, domain policy, prod_shield, and ssh policy, logging warnings via `p.log.Warn(...)`.
- **Tests:** `internal/store/pg_test.go:TestListTemplates_CorruptedJSON`
  - Seeds a template row with malformed JSON (`"{invalid-json"`) and asserts that `ListTemplates` returns a descriptive unmarshal error.
- **Status:** PASS

---

## 3. Verification & Quality Gates

| Gate | Command | Result | Notes |
|------|---------|--------|-------|
| **Go Build** | `go build ./...` | **PASS (0)** | Zero compilation errors across all binaries and packages |
| **Go Test Full** | `go test -race -count=1 ./...` | **PASS (0)** | Full repo green (including audit, server, policy, proxy, sdk) |
| **Audit + Store Test** | `go test -race -count=3 ./internal/audit/... ./internal/store/...` | **PASS (0)** | Deflaked, 3 consecutive passes with 0 race warnings |
| **Linter** | `golangci-lint run` | **PASS (0)** | 0 issues reported across entire codebase |
| **Format** | `gofmt -l cmd/ pkg/ internal/` | **PASS (0)** | Clean, empty output |
| **Dependencies** | `git diff go.mod go.sum` | **PASS (0)** | Zero new dependencies added |
| **Owl Protection** | `git status owl/` | **PASS (0)** | Untouched (`owl/` directory clean) |
| **Git Safety** | `git status` | **PASS** | No commits or pushes performed |

---

## 4. Modified Files Reference

- [internal/audit/sqlite.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/sqlite.go)
- [internal/audit/logger.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/logger.go)
- [internal/audit/logger_test.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/logger_test.go)
- [internal/audit/lifecycle_test.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/lifecycle_test.go)
- [internal/store/pg.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/store/pg.go)
- [internal/store/pg_test.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/store/pg_test.go)
