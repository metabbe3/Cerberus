# ADR-0004: Partial Evaluation (`/v1/compile`) as Non-Goal for Cerberus Phase 5

## Status
Accepted (Non-Goal)

## Context
OPA provides a compile API endpoint (`POST /v1/compile`) powered by partial evaluation (`rego.Partial`). This capability partially evaluates Rego policies against template inputs with specified "unknowns" (e.g. `input.key_id` or `input.user`), producing residual ASTs or simplified Rego rules. In traditional OPA deployments, this is used for:
1. Translating authorization rules into SQL/Elasticsearch query filters (`WHERE` clauses).
2. Generating simplified rules for offline edge sidecars or kernel-level packet filters (e.g. eBPF).

During Sprint 5D, adding a partial evaluation endpoint (`POST /v1/compile`) was investigated to precompile Production Shield rules for unknown keys (yielding simplified "always deny dangerous pattern X" rules).

## Decision
We deliberately classify `POST /v1/compile` and runtime partial evaluation as a **Non-Goal** for Cerberus Phase 5.

### Rationale

1. **Centralized Runtime Gateway Architecture**:
   Cerberus is built from the ground up as an authoritative, low-latency runtime decision engine (`POST /v1/decide`). With singleflight coalescing, prepared-query caching, and lock-free in-memory LRU evaluation, decisions complete in sub-millisecond timeframes (~100µs on cache hit, ~1ms on eval). Client sidecars and proxies (`cerberus-proxy`) achieve optimal throughput by calling the runtime gateway directly.

2. **Complexity vs. Operational Benefit**:
   Dynamic stage dispatch in Cerberus routes evaluations through `data.stages[input.stage].decision` with comprehensive data lookups (`data.agents`, `data.teams`, `data.prod_shield`). Partially evaluating these dynamic dispatch trees into residual Rego or AST representations creates complex, highly fragmented ASTs that downstream consumers (such as reverse proxies or agents) cannot evaluate without running their own embedded OPA engine.

3. **Adequacy of Sprint 5 Safety Nets**:
   The primary motivation for policy inspection and pre-verification has been comprehensively addressed by:
   - **Sprint 5A (Policy Studio & Smoke Gate)**: Automated dry-run smoke testing prevents invalid rules from activating.
   - **Sprint 5B (Explain & Trace)**: `POST /v1/admin/explain` and `POST /v1/decide?explain=true` provide granular rule-level trace evaluation without execution risk.
   - **Sprint 5C (Replay Diff & Coverage Gate)**: `POST /v1/admin/replay` evaluates draft policies against the last 500 real audit events to project exact impact, and bundle activation enforces a strict ≤5 point test coverage drop limit.

4. **Fail-Closed Shield Invariants**:
   Production Shield already implements fail-closed baseline enforcement in Rego (`policies/shield/prod.rego`) and in the proxy tier. Adding partial evaluation AST compilation does not increase runtime security posture.

## Future Considerations
If Cerberus expands into direct kernel eBPF bytecode generation or backend database SQL filter synthesis in Phase 6+, a dedicated offline compiler toolchain can be evaluated as an independent subsystem rather than a runtime gateway endpoint.
