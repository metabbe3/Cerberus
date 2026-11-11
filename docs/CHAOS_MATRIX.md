# Cerberus Chaos Matrix & Fuzz Report (Sprint 4D)

## 1. Fuzz Testing Crash Report

- **Target**: `FuzzDecide` (`internal/engine/fuzz_test.go`)
- **Corpus Coverage**:
  - Malformed stages (`"%%%$$$@@@"`, `"\x00\x00\x00"`, `"unknown_stage"`, `""`)
  - Non-object / malformed tool arguments (strings, arrays, `null`, numbers, broken JSON)
  - Oversized payloads (10MB string payloads)
  - Unicode and embedded null bytes (`\u0000`, `\x00`)
  - Partial IPs and malformed addresses (`"10.0."`, `"192.168."`, `"::::"`, `"localhost"`)
- **Executions**: >33,400 fuzz executions (fuzzing with 10 workers)
- **Crashes Detected**: **0 (CLEAN - NO CRASHES)**
- **Invariant Validated**: Sub-millisecond decision evaluation never panics under adversarial or malformed inputs, fail-closed guarantee upheld across all stages.

---

## 2. Chaos Engineering Matrix

| Chaos Scenario | Injected Fault | Invariant / Expected Behavior | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Audit Sink Death** | Dead, closed, or blocking audit sink during high traffic | Decision latency remains <1ms; zero decisions dropped or aborted | Average decision latency <100µs across 1000 consecutive decisions. Zero dropped decisions. | **PASS** |
| **Corrupt Bundle Upload** | Non-gzip payload, truncated tar stream, 0xFF garbage bytes, empty payload | Bundle rejected with 422/error; active snapshot, epoch, and policy stay live and unmodified | All 4 corrupt payloads rejected; active snapshot retained with unchanged epoch. | **PASS** |
| **Clock Skew Attack** | Bundle revision timestamp set in the future (year 2099) | Reject bundle with `ErrFutureRevision`; prevent future timestamp hijacking | Refused with `ErrFutureRevision` and clock skew warning; old snapshot stays live. | **PASS** |
| **Unauthorized Break-Glass** | Request from untrusted agent IP with `X-Break-Glass: true` header | Reject emergency bypass; enforce normal policy gating; log security alert | Header ignored with warning; request gated and denied fail-closed. | **PASS** |
| **Privileged Break-Glass** | Request with `X-Break-Glass` from unix socket or with valid admin token | Bypass all policies for emergency fix; emit real-time SSE alert + BIG RED audit event | All policies bypassed with `ops.break_glass`; real-time SSE event emitted. | **PASS** |
| **Concurrent Race Stress** | Concurrent decision flights, bundle swaps, token bucket refills, and peer sync | Zero data races under Go race detector (`-race`) | Whole test suite passes with zero data races. | **PASS** |
| **Node Gossip Sync** | Peer node with older uptime / newer bundle revision | Younger node detects difference and auto-pulls bundle from eldest peer | Younger node automatically downloads, verifies, and installs bundle. | **PASS** |
| **Distributed Audit Merge** | Distributed query with `GET /v1/audit?cluster=true` across partitioned nodes | Query gathers and merge-sorts records strictly by timestamp descending | Multi-node events correctly interleaved in chronological order (newest-first). | **PASS** |
