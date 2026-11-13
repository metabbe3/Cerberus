# Cerberus Documentation Archive & Index

This directory contains architectural specifications, benchmark reports, decision records, and operational plans created during the development of Cerberus. Use this one-line index to navigate the documentation library quickly.

---

## Primary Guides

| Document | Contents | When to Consult |
|---|---|---|
| [SETUP.md](SETUP.md) | Single source of truth for architecture, complete env/flag reference, Docker Compose production stack, and operational troubleshooting | Setting up production or development environments, configuring flags/env, or deploying services |
| [GUIDE.md](GUIDE.md) | Operational walkthrough for running the engine, loading policy files, interacting with admin endpoints, and understanding error formats | Hands-on policy authoring, testing endpoints via curl, and administrative operations |
| [INTEGRATION.md](INTEGRATION.md) | In-depth integration guide for AI agents, SDK wrappers (`GuardedExecutor`), data schema definitions, and token handling | Integrating client applications, developing SDKs, or wiring agents into Cerberus |
| [DEPLOY.md](DEPLOY.md) | Historical deployment notes for bare-metal OS installations (systemd on Linux, launchd on macOS) and standalone distroless containers | Deploying Cerberus as a native OS service outside of Docker Compose |

---

## Security, Testing & Benchmarking

| Document | Contents | When to Consult |
|---|---|---|
| [BENCH.md](BENCH.md) | Concurrency benchmark results (~85k TPS sustained, latency profiles across 1–128 concurrent clients) | Sizing infrastructure, evaluating engine throughput, or performance regression testing |
| [BYPASS_MATRIX.md](BYPASS_MATRIX.md) | Security test matrix cataloging known attack vectors, command injection patterns, glob escapes, and verification rules | Conducting security reviews, red-team auditing, or updating rule definitions |
| [CHAOS_MATRIX.md](CHAOS_MATRIX.md) | Fault injection test matrix covering database disconnects, slow upstreams, network partitions, and fail-closed behaviors | Planning disaster recovery testing or verifying system resilience under failure modes |
| [REVIEW-2026-11-13.md](REVIEW-2026-11-13.md) | Architecture review dated 2026-11-13 analyzing in-path LLM tap isolation, proxy sockets, and multi-stage gates | Understanding gate enforcement design decisions and security isolation models |

---

## Architectural Decision Records (ADR)

| Document | Contents | When to Consult |
|---|---|---|
| [ADR-0001](adr/ADR-0001-high-traffic-concurrency.md) | Decision record establishing in-memory LRU caching, lockless reads, and asynchronous SQLite audit logging for high concurrency | Reviewing the core concurrency architecture and caching strategy |
| [ADR-0002](adr/ADR-0002-universal-gateway.md) | Decision record defining the universal multi-stage gateway architecture across HTTP, Docker, and SSH | Designing or adding new enforcement gates or protocol adapters |
| [ADR-0003](adr/ADR-0003-multi-node-ha.md) | Decision record defining multi-node high availability with PostgreSQL as the system of record and local file fallbacks | Setting up clustered deployments or database synchronization |
| [ADR-0004](adr/ADR-0004-partial-evaluation-non-goal.md) | Decision record outlining why Rego partial evaluation was deemed a non-goal in favor of explicit split-state evaluation | Understanding OPA query architecture and policy evaluation mechanics |

---

## Philosophy & Conventions

| Document | Contents | When to Consult |
|---|---|---|
| [CONVENTIONS.md](CONVENTIONS.md) | Strict engineering rules, coding standards for Go/Rego/TypeScript, zero-trust requirements, and error-handling patterns | Contributing code, submitting PRs, or conducting code reviews |
| [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) | Core architectural philosophy: "police what is called, not advertised", fail-closed defaults, and separation of brain from gates | Understanding why architectural trade-offs were made and maintaining core principles |
| [ROADMAP.md](ROADMAP.md) | Multi-phase development roadmap from core engine foundations to distributed gateways and dashboard observability | Tracking project milestones, future capabilities, and development progress |

---

## Execution Plans (Superpowers)

| Document | Contents | When to Consult |
|---|---|---|
| [Phase 1: Core Engine](superpowers/plans/2026-11-10-phase1-core-engine.md) | Original execution plan for implementing the Go OPA engine, decide APIs, masking, and SQLite audit trail | Reviewing the foundational engine implementation history |
| [Phase 2: Owl Dashboard](superpowers/plans/2026-11-11-phase2-owl.md) | Original execution plan for building the Owl Next.js 15 administrative UI, real-time SSE stream, and metrics | Reviewing the dashboard implementation history and API contracts |
