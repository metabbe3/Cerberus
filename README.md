# Cerberus — OPA-style Policy Engine for AI Agent Gateways 🔥

[![CI](https://github.com/metabbe3/Cerberus/actions/workflows/ci.yml/badge.svg)](https://github.com/metabbe3/Cerberus/actions/workflows/ci.yml)
[![Docker Image](https://img.shields.io/badge/GHCR-cerberus%3Alatest-blue?logo=docker)](https://github.com/metabbe3/Cerberus/pkgs/container/cerberus)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **The "OPA" for the AI agent ecosystem**: a single policy enforcement gateway for tool/command/data permissions, at-rest & in-flight masking, and multi-team governance — evaluated with deterministic Rego rules, hot-reloaded dynamically, zero recompilation needed.

📖 **Comprehensive Setup & Env Reference:** See [docs/SETUP.md](docs/SETUP.md) for full architecture diagrams, installation pathways, and configuration tables.

---

## Quickstart (5 lines)

```bash
git clone https://github.com/metabbe3/Cerberus && cd Cerberus
cp .env.example .env && sed -i.bak "s|^CERBERUS_ADMIN_TOKEN=.*|CERBERUS_ADMIN_TOKEN=$(openssl rand -base64 32)|" .env && rm -f .env.bak
docker compose -f docker-compose.prod.yml up -d
curl -s http://127.0.0.1:8090/tap/healthz
docker compose -f docker-compose.prod.yml exec engine wget -qO- --post-data='{"key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"kubectl get pods"}}' --header="Content-Type: application/json" http://127.0.0.1:8089/v1/decide/tool
```

---

## Services & Tooling

Cerberus packages its entire ecosystem into a single unified container image (`ghcr.io/metabbe3/cerberus:latest`):

### 5 Core Services
| Service | Binary | Role | Port / Target |
|---|---|---|---|
| **Engine** | `cerberus` | Policy decision brain, OPA evaluator, admin API, metrics, audit DB | `:8089` (Internal) |
| **LLM Tap** | `cerberus-tap` | In-path LLM proxy, stream capture, redaction & fail-closed deny | `127.0.0.1:8090` |
| **Docker Proxy** | `cerberus-proxy` | Docker daemon socket protection shield (container isolation) | `127.0.0.1:2377` |
| **Egress Proxy** | `cerberus-proxy` | Outbound HTTP/CONNECT proxy enforcing CIDR & host shields | `127.0.0.1:8088` |
| **SSH Bastion** | `cerberus-ssh` | Command-level SSH inspection & audit gate | `127.0.0.1:2222` |

### 3 Offline CLI Tools
| Binary | Role | Usage |
|---|---|---|
| **`cerberus-bundle`** | Policy Bundle Compiler | Compiles and validates Rego policy sets offline |
| **`cerberus-redteam`** | Red-Team Suite | Runs deterministic security attack simulations & bypass checks |
| **`loadgen-stress`** | Stress Testing Tool | High-concurrency benchmark tool (sustained ~85k TPS) |

---

## Core Concepts

1. **Production-grade Rego Policies:** Deterministic, auditable policy-as-code evaluated in microsecond-to-millisecond latency.
2. **Policy vs. Data Split:** `authz.rego` defines static decision logic; JSON / PostgreSQL stores dynamic team, agent, and limit data — hot-reloaded dynamically without process restarts.
3. **Per-Key & Per-Team Governance:** Agents are governed by LiteLLM `key_id` identifiers with configurable fail-open/fail-closed bypass flags.
4. **Enforcing ACTUAL Invocations:** Tool permissions (`allowed_tool_calls`, `restricted_tool_calls`) are verified against the exact tool and parameters invoked by the LLM.
5. **Decision Points:**
   - `POST /v1/decide/llm`: Pre-call model allowlists (glob-aware), cumulative budgets, and prompt injection/pattern scanner (EN+ID).
   - `POST /v1/decide/tool`: Pre-execution tool validation, argument constraints (bare-array, allowlists, regex, range), and masking.
   - `POST /v1/decide`: Generic decision endpoint covering `llm`, `tool`, `http`, `docker`, `ssh`, and `custom:*` stages.
6. **Dynamic Masking:** Regex-driven redaction, masking (`10****.7`), and hashing (`sha256`) applied per-agent on tool arguments and LLM prompt turns.
7. **Emergency Kill-Switch & Break-Glass:** Immediate estate-wide or per-key execution kill switch with 15-minute dashboard break-glass overrides.
8. **Three Enforcement Planes:**
   - Client SDK `GuardedExecutor` (Go, Python, TypeScript)
   - Docker socket proxy (`cerberus-proxy`) shielding protected containers
   - Egress HTTP proxy (`cerberus-proxy`) shielding internal CIDRs and DNS spoofing
9. **PostgreSQL System of Record:** Dual persistence with database-backed revision history and seamless local file fallback.

---

## Monitoring & Observability

- **`GET /v1/health/components`:** Estate-wide health summary reporting engine, agents, kill-switch, postgres, and audit subsystems.
- **`GET /v1/audit/timeseries`:** Epoch-aligned aggregated server-side time buckets for Grafana/Owl dashboards.
- **Owl Dashboard (Next.js 15):** Web UI providing live audit stream, time-series metrics, policy inspection, and agent configuration.
- **Daily Rotating Audit Logs:** SQLite WAL mode with at-rest masking and asynchronous fire-and-forget log shipping.

---

## Repository Layout

```
Cerberus/                        # Monorepo: engine + Owl dashboard + SDKs
  cmd/                           # Service and CLI binaries
    cerberus/                    # Policy engine binary (:8089)
    cerberus-tap/                # LLM in-path proxy gate (:8090)
    cerberus-proxy/              # Docker socket & egress proxy (:2377 / :8088)
    cerberus-ssh/                # SSH bastion command inspection (:2222)
    cerberus-bundle/             # Offline Rego bundle utility
    cerberus-redteam/            # Security attack simulation suite
    loadgen-stress/              # High-throughput load generator
  internal/                      # Core engine, OPA evaluation, audit, store, masking
  policies/                      # Rego bundles (gateway, stages, shield)
  migrations/                    # PostgreSQL system-of-record schema (001_postgres.sql)
  owl/                           # Next.js 15 administrative dashboard
  sdk/{go,python,ts}/            # Multi-language SDKs (GuardedExecutor, retries, hot-cache)
  docs/                          # Documentation index (see docs/SETUP.md, docs/ARCHIVE.md)
  docker-compose.prod.yml        # Production 5-service single-image compose stack
  Dockerfile                     # Multi-stage container build manifest
```

---

## Admin API (Bearer CERBERUS_ADMIN_TOKEN)

| Endpoint | Method | Description |
|---|---|---|
| `/v1/admin/data` | `GET`, `PUT` | Read or update full policy configuration data (persisted to PostgreSQL) |
| `/v1/admin/templates` | `GET`, `PUT`, `DELETE` | Server-side policy templates management |
| `/v1/health/components` | `GET` | Single endpoint estate health status |
| `/v1/audit` | `GET` | Query decision audit logs with time and field filters |
| `/v1/audit/timeseries` | `GET` | Aggregated decision time-series buckets for visualization |
| `/v1/status`, `/v1/events` | `GET` | Real-time status and SSE event stream |
