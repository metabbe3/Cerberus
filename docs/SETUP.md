# Cerberus Production Setup & Reference Guide

Cerberus is a zero-trust policy engine and security gateway designed for AI agents. This document provides the unified architecture overview, complete environment and CLI flag reference, advanced deployment options, execution verification steps, and operational troubleshooting.

> 💡 **Mencari instalasi cepat?** Lihat [docs/QUICKSTART.md](QUICKSTART.md) untuk panduan quickstart <5 menit dengan skrip installer otomatis.

---

## 1. Architecture Overview

Cerberus separates the policy decision engine from traffic enforcement gates. The central policy engine (`cerberus`) embeds Open Policy Agent (OPA) to evaluate declarative Rego rules in microsecond-to-millisecond timescales, loading policy data either from local JSON files or a PostgreSQL system of record with live hot-reloading. Specialized enforcement gates intercept agent interactions across critical control planes:

- **`cerberus-tap` (LLM Gate):** Intercepts in-path LLM API requests and SSE streams with automated at-rest redaction, in-flight inspection, and fail-closed deny capabilities.
- **`cerberus-proxy` (Docker & Egress Gate):** Acts as a guarded Unix socket gateway for the Docker daemon preventing container escape, as well as an outbound HTTP/CONNECT egress proxy shielding production CIDRs.
- **`cerberus-ssh` (Bastion Gate):** Inspects bastion session commands per-execution via the engine before relaying to upstream targets.
- **`owl` (Management Dashboard):** Administrative UI providing real-time SSE audit streaming, decision analytics, and agent governance.

```
+-----------------------------------------------------------------------------------------+
|                                  Host / Agent Runtime                                   |
+-----------------------------------------------------------------------------------------+
       |                         |                                |                 |
       | :8090 (LLM traffic)     | :2377 (Docker) / :8088 (Egress)| :2222 (SSH)     | :3000 (UI)
       v                         v                                v                 v
+---------------+        +----------------+               +---------------+   +-----------+
| cerberus-tap  |        | cerberus-proxy |               | cerberus-ssh  |   |    owl    |
|  (LLM Gate)   |        |(Socket & Egress|               | (Bastion Gate)|   |(Dashboard)|
+---------------+        +----------------+               +---------------+   +-----------+
       |                         |                                |                 |
       | (decide queries)        | (embedded / decide)            | (decide queries)| (api)
       +--------------------\    |    /---------------------------+                 |
                             \   v   /                                              |
                       +-----------------------+                                    |
                       |    cerberus engine    |<-----------------------------------+
                       | :8089 (Loopback/Int)  |
                       |  OPA / Cache / Audit  |
                       +-----------------------+
                               |        |
                 +-------------+        +-------------+
                 v                                    v
         +---------------+                    +---------------+
         | SQLite Audit  |                    |  PostgreSQL   |
         | (Daily WAL)   |                    | (Opt. Record) |
         +---------------+                    +---------------+
```

---

## 2. Configuration & Flag Reference (12-Factor)

Every service supports declarative configuration via environment variables and CLI flags. When both are supplied, CLI flags take precedence over environment variables.

### 2.1 Engine (`cerberus`)

*Source: `internal/config/config.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| `CERBERUS_ADMIN_TOKEN` | *(env only)* | `""` | **Yes** | Master bearer token for admin API (`/v1/admin/*`) and inter-service authentication. Prohibited on argv to prevent `/proc` leaks. |
| `CERBERUS_ADDR` | `-addr` | `:8089` | No | HTTP server listen address for decide, admin, and health endpoints. |
| `CERBERUS_POLICY_DIR` | `-policy-dir` | `/policies` | No | Directory path containing compiled Rego policy bundles. |
| `CERBERUS_DATA_FILE` | `-data-file` | `/data/prod.json` | No | Path to initial/fallback JSON policy data file. |
| `CERBERUS_AUDIT_DB` | `-audit-db` | `/audit/cerberus.db` | No | SQLite database file path for buffered audit logging. |
| `CERBERUS_PG_DSN` | `-pg-dsn` | `""` | No | PostgreSQL connection DSN (system of record; empty = flat-file only). |
| `CERBERUS_AUDIT_RETENTION_DAYS` | `-audit-retention-days` | `30` | No | Days to retain daily rotating SQLite audit logs before pruning. |
| `CERBERUS_DECISION_LOG_SHIP_URL` / `CERBERUS_SHIP_URL` | `-ship-url` | `""` | No | Optional HTTP endpoint for asynchronous decision log export. |
| `CERBERUS_BUNDLE_PUBKEY` | `-bundle-pubkey` | `""` | No | Base64/PEM ed25519 public key for bundle signature verification. |
| `CERBERUS_LOG_LEVEL` | `-log-level` | `info` | No | Structured log level (`debug`, `info`, `warn`, `error`). |
| `CERBERUS_CACHE_SIZE` | `-cache-size` | `10000` | No | Maximum entries in the LRU decision cache. |
| `CERBERUS_EVAL_TIMEOUT` | `-eval-timeout` | `3s` | No | Execution timeout budget per policy evaluation (e.g. `10ms`, `3s`). |
| `CERBERUS_REQUIRE_AGENT_KEYS` | *(env only)* | `false` | No | Fail-closed gate flag requiring registered agent keys; false allows fail-open onboarding. |
| `CERBERUS_TRUST_UNIX_SOCKET` | *(env only)* | `false` | No | Trust local caller UID/GID when communicating over Unix domain sockets. |
| `CERBERUS_DEFAULT_ACTION` | *(env only)* | `allow` | No | Fallback decision action when no explicit policy matches (`allow` or `deny`). |

---

### 2.2 LLM Tap Gate (`cerberus-tap`)

*Source: `cmd/cerberus-tap/main.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| `CERBERUS_TAP_LISTEN` / `CERBERUS_TAP_ADDR` | `-listen` | `0.0.0.0:8090` | No | In-path proxy listen address. |
| `CERBERUS_TAP_UPSTREAM` | `-upstream` | `https://api.anthropic.com` | No | Upstream target LLM API base URL. |
| `CERBERUS_ENGINE_URL` | `-engine-url` | `http://engine:8089` | No | Cerberus engine base URL. Empty runs in visibility-only mode. |
| `CERBERUS_ADMIN_TOKEN` | `-engine-token` | `""` | **Yes** | Bearer token for authenticating queries to `-engine-url`. |
| `TAP_ADMIN_TOKEN` | `-admin-token` | `""` | No | Bearer token guarding inspection endpoints (`/tap/turns`, `/tap/stats`, `/tap/kill`). |
| `CERBERUS_TAP_RETENTION_DAYS` | `-retention-days` | `14` | No | Days to retain historical tap database files (`tap-YYYYMMDD.db`). |
| *(none)* | `-data-dir` | `/data` | No | Directory path where rotating daily SQLite stores are written. |
| *(none)* | `-strict` | `true` | No | Fail-closed toggle: deny LLM calls when engine is unreachable or returns error. |

---

### 2.3 Docker Socket & Egress Proxy (`cerberus-proxy`)

*Source: `cmd/cerberus-proxy/main.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| `CERBERUS_PROXY_LISTEN` | `-listen` | `0.0.0.0:2377` | No | Docker proxy listen address (TCP port or Unix domain socket `unix:///path`). |
| `CERBERUS_PROXY_DOCKER_HOST` | `-docker-host` | `unix:///var/run/docker.sock` | No | Target Docker daemon host or socket URL. |
| `CERBERUS_EGRESS_ADDR` / `CERBERUS_PROXY_EGRESS_ADDR` | `-egress-addr` | `0.0.0.0:8088` | No | HTTP CONNECT outbound egress proxy listen address shielding private CIDRs. |
| `CERBERUS_PROXY_DEFAULT_KEY` | `-default-key` | `k-default-agent` | No | Fallback agent key identifier for requests without client identity headers. |
| `CERBERUS_ADMIN_TOKEN` | `-admin-token` | `""` | No | Master bearer token for authenticating proxy requests. |
| `CERBERUS_POLICY_DIR` | `-policy-dir` | `/gate-policies` | No | Directory containing Rego policy rules. |
| `CERBERUS_DATA_FILE` | `-data-file` | `/gate-data/prod.json` | No | Path to policy data JSON. |
| `CERBERUS_AUDIT_DB` | `-audit-db` | `/audit/proxy-audit.db` | No | Path to SQLite audit database. |
| `CERBERUS_EVAL_TIMEOUT` | *(env only)* | `3s` | No | Evaluation timeout budget. |
| `CERBERUS_LOG_LEVEL` | `-log-level` | `info` | No | Structured logging verbosity (`debug`, `info`, `warn`, `error`). |

---

### 2.4 SSH Bastion Gate (`cerberus-ssh`)

*Source: `cmd/cerberus-ssh/main.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| `CERBERUS_SSH_LISTEN` | `-listen` | `0.0.0.0:2222` | No | SSH server listen address. |
| `CERBERUS_ENGINE_URL` | `-engine-url` | `http://engine:8089` | No | Cerberus policy engine base URL for command decision evaluation. |
| `CERBERUS_ADMIN_TOKEN` | `-engine-token` | `""` | **Yes** | Bearer authentication token for queries to the engine. |
| `CERBERUS_SSH_UPSTREAM_HOST` | `-upstream-host` | `""` | No | Target upstream SSH host (passed as policy context). |
| `CERBERUS_SSH_UPSTREAM_USER` | `-upstream-user` | `""` | No | Target upstream SSH user (passed as policy context). |
| `CERBERUS_SSH_UPSTREAM_KEY` | `-key-file` | `""` | No | Upstream SSH private key PEM file path. When unset, runs in **decide-only audit mode** (no relay). |
| *(none)* | `-hostkey-file` | `/data/cerberus_ssh_hostkey` | No | Bastion server host private key path (auto-generated on boot if missing). |
| `CERBERUS_SSH_UPSTREAM_HOSTKEY` | `-upstream-hostkey` | `""` | No | Base64-encoded upstream public host key pin. |

---

### 2.5 Owl Dashboard (`owl`)

*Source: `owl/lib/session.ts`, `owl/lib/engine.ts`*

| Environment Variable | Default | Required? | Description |
|---|---|---|---|
| `OWL_ADMIN_PASSWORD` / `OWL_PASSWORD` | `""` | **Yes** | Master administrator login password for Owl web dashboard. |
| `OWL_SESSION_SECRET` | `""` | **Yes** | 32-byte secret key used to cryptographically sign session cookies. |
| `CERBERUS_URL` | `http://engine:8089` | No | Target Cerberus policy engine base URL. |
| `CERBERUS_ADMIN_TOKEN` | `""` | **Yes** | Admin bearer token used by Owl server to query `/v1/admin/*` and metrics. |
| `PORT` | `3000` | No | Next.js server HTTP port. |

---

### 2.6 Agent Credentials & Client Integration

| Environment Variable | Usage | Description |
|---|---|---|
| `CERBERUS_AGENT_SECRET` | Client Secret | Raw bearer secret generated for agent identification (`sk-cb-...`). |
| `CERBERUS_AGENT_KEY` | Policy Key ID | SHA-256 digest of secret token, matched against `data/prod.json` rules. |
| `ANTHROPIC_BASE_URL` | Agent Runtime | Set to `http://127.0.0.1:8090` to route LLM requests through Tap. |
| `X_TAP_KEY` | Agent Header | Header `X-Tap-Key` identifying agent instance to Cerberus Tap. |
| `HTTP_PROXY` / `HTTPS_PROXY` | Agent Runtime | Set to `http://127.0.0.1:8088` to route outbound network calls through Egress Proxy. |
| `DOCKER_HOST` | Agent Runtime | Set to `tcp://127.0.0.1:2377` to route container actions through Docker Proxy. |

---

## 3. Operational Verification

### 3.1 Verify Service Health
Check engine health status via internal network or loopback:
```bash
curl -fsS http://127.0.0.1:8089/healthz
# Expected output: ok
```

Check LLM tap health status on host loopback:
```bash
curl -fsS http://127.0.0.1:8090/tap/healthz
# Expected output: ok
```

Check Owl dashboard status:
```bash
curl -fsS http://127.0.0.1:3000/api/health 2>/dev/null || curl -I http://127.0.0.1:3000
# Expected output: HTTP 200 / 307
```

### 3.2 Smoke Tests (Policy Decisions)

**Check 1: Allow valid tool call (`kubectl get pods`):**
```bash
curl -fsS -X POST http://127.0.0.1:8089/v1/decide/tool \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(grep CERBERUS_ADMIN_TOKEN .env | cut -d'=' -f2-)" \
  -d '{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"kubectl get pods"}}'
```
*Expected output contains: `"decision":"allow"`, `"rule_id":"ai.tool.allow"`.*

**Check 2: Deny dangerous shell command (`rm -rf /`):**
```bash
curl -fsS -X POST http://127.0.0.1:8089/v1/decide/tool \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(grep CERBERUS_ADMIN_TOKEN .env | cut -d'=' -f2-)" \
  -d '{"stage":"tool","key_id":"k-glob","tool_call":"bash","args":{"cmd":"rm -rf /"}}'
```
*Expected output contains: `"decision":"deny"`, `"rule_id":"shield.cmd.dangerous"`.*

---

## 4. Advanced Production Deployment

### 4.1 Systemd (Linux Bare-Metal)
Units are available under `deploy/systemd/`:
- `cerberus-engine.service`: Runs `/usr/local/bin/cerberus`
- `cerberus-proxy.service`: Runs `/usr/local/bin/cerberus-proxy`
- Environment loaded from `/etc/cerberus/cerberus.env` (permissions `0600 root:cerberus`).

### 4.2 High Availability & Policy Synchronization
- **PostgreSQL System of Record:** When `CERBERUS_PG_DSN` is configured, engine instances write through to PostgreSQL. Policies are synced across multiple engine instances via database state.
- **SIGHUP Reload:** Zero-downtime policy reload can be triggered at any time:
  ```bash
  docker compose -f docker-compose.prod.yml exec engine kill -HUP 1
  ```
