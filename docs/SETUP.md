# Cerberus Production Setup & Reference Guide

Cerberus is a zero-trust policy engine and security gateway designed for AI agents. This document provides the unified architecture overview, complete environment and CLI flag reference, installation pathways, execution verification steps, and operational troubleshooting.

---

## 1. Architecture Overview

Cerberus separates the policy decision engine from traffic enforcement gates. The central policy engine (`cerberus`) embeds Open Policy Agent (OPA) to evaluate declarative Rego rules in microsecond-to-millisecond timescales, loading policy data either from local JSON files or a PostgreSQL system of record with live hot-reloading. Specialized enforcement gates intercept agent interactions across critical control planes: `cerberus-tap` intercepts in-path LLM API requests and SSE streams with automated at-rest redaction and fail-closed deny capabilities; `cerberus-proxy` acts as a guarded Unix socket gateway for the Docker daemon as well as an outbound HTTP/CONNECT egress proxy shielding production CIDRs; and `cerberus-ssh` inspects bastion session commands. In production, all five services run from a single hardened, non-root (UID 10001) multi-stage container image (`ghcr.io/metabbe3/cerberus:latest`), publishing strictly to loopback addresses (`127.0.0.1`) and communicating over an isolated Docker network.

```
+-----------------------------------------------------------------------------------+
|                                Host / Agent Runtime                               |
+-----------------------------------------------------------------------------------+
      |                                    |                                  |
      | :8090 (LLM traffic)                | :2377 (Docker) / :8088 (Egress)  | :2222 (SSH)
      v                                    v                                  v
+------------------+             +--------------------+             +-------------------+
|   cerberus-tap   |             |   cerberus-proxy   |             |   cerberus-ssh    |
|   (LLM Gate)     |             | (Socket & Egress)  |             |  (Bastion Gate)   |
+------------------+             +--------------------+             +-------------------+
      |                                    |                                  |
      | (decide queries)                   | (embedded Rego                   | (decide queries)
      |                                    |  eval via ro mount)              |
      +-----------------------------\      |      /---------------------------+
                                     \     v     /
                               +-----------------------+
                               |    cerberus engine    |
                               | :8089 (Internal Only) |
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

## 2. Configuration & Flag Reference

Every service supports declarative configuration via environment variables and CLI flags. When both are supplied, CLI flags take precedence over environment variables.

### 2.1 Engine (`cerberus`)

*Source: `internal/config/config.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| `CERBERUS_ADDR` | `-addr` | `:8089` | No | HTTP server listen address for decide, admin, and health endpoints. |
| `CERBERUS_POLICY_DIR` | `-policy-dir` | `policies` | No | Directory path containing compiled Rego policy bundles. |
| `CERBERUS_DATA_FILE` | `-data-file` | `data/prod.json` | No | Path to initial/fallback JSON policy data file. |
| `CERBERUS_AUDIT_DB` | `-audit-db` | `cerberus.db` | No | SQLite database file path for buffered audit logging. |
| `CERBERUS_PG_DSN` | `-pg-dsn` | `""` | No | PostgreSQL connection DSN (system of record; empty = flat-file only). |
| `CERBERUS_AUDIT_RETENTION_DAYS` | `-audit-retention-days` | `30` | No | Days to retain daily rotating SQLite audit logs before pruning. |
| `CERBERUS_DECISION_LOG_SHIP_URL` / `CERBERUS_SHIP_URL` | `-ship-url` | `""` | No | Optional HTTP endpoint for asynchronous decision log export. |
| `CERBERUS_ADMIN_TOKEN` | *(env only)* | `""` | **Yes** | Master bearer token for admin API (`/v1/admin/*`). Prohibited on argv to prevent process inspection leaks. |
| `CERBERUS_LOG_LEVEL` | `-log-level` | `info` | No | Structured log level (`debug`, `info`, `warn`, `error`). |
| `CERBERUS_CACHE_SIZE` | `-cache-size` | `10000` | No | Maximum entries in the LRU decision cache. |
| `CERBERUS_EVAL_TIMEOUT` | `-eval-timeout` | `10ms` | No | Execution timeout budget per policy evaluation (e.g. `10ms`, `5s`). |

---

### 2.2 LLM Tap Gate (`cerberus-tap`)

*Source: `cmd/cerberus-tap/main.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| *(none)* | `-listen` | `127.0.0.1:8090` | No | In-path proxy listen address. |
| *(none)* | `-upstream` | `https://api.z.ai/api/anthropic` | No | Upstream target LLM API base URL. |
| *(none)* | `-engine-url` | `""` | No | Cerberus engine base URL (e.g. `http://engine:8089`). Empty runs in visibility-only mode. |
| `CERBERUS_ADMIN_TOKEN` | `-engine-token` | `""` | No | Bearer token for authenticating calls to `-engine-url`. |
| *(none)* | `-data-dir` | `.` | No | Directory path where rotating daily SQLite stores (`tap-YYYYMMDD.db`) are written. |
| *(none)* | `-strict` | `false` | No | Fail-closed toggle: deny LLM calls when engine is unreachable or returns error. |
| `TAP_ADMIN_TOKEN` | `-admin-token` | `""` | No | Bearer token guarding inspection endpoints (`/tap/turns`, `/tap/stats`). |
| *(none)* | `-retention-days` | `14` | No | Days to retain historical tap database files (0 = keep indefinitely). |

---

### 2.3 Docker Socket & Egress Proxy (`cerberus-proxy`)

*Source: `cmd/cerberus-proxy/main.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| `CERBERUS_PROXY_LISTEN` | `-listen` | `:2375` | No | Listen address (TCP port or Unix domain socket `unix:///path`). |
| `CERBERUS_PROXY_DOCKER_HOST` | `-docker-host` | `unix:///var/run/docker.sock` | No | Target Docker daemon host or socket URL. |
| `CERBERUS_PROXY_EGRESS_ADDR` | `-egress-addr` | `""` | No | Optional HTTP CONNECT egress proxy listen address (e.g. `0.0.0.0:8088`). |
| `CERBERUS_PROXY_DEFAULT_KEY` | `-default-key` | `k-default-agent` | No | Fallback agent key identifier for requests without client identity headers. |
| `CERBERUS_POLICY_DIR` | `-policy-dir` | `policies` | No | Directory containing Rego policy rules. |
| `CERBERUS_DATA_FILE` | `-data-file` | `data/prod.json` | No | Path to policy data JSON. |
| `CERBERUS_AUDIT_DB` | `-audit-db` | `cerberus.db` | No | Path to SQLite audit database. |
| `CERBERUS_LOG_LEVEL` | `-log-level` | `info` | No | Structured logging verbosity (`debug`, `info`, `warn`, `error`). |

---

### 2.4 SSH Bastion Gate (`cerberus-ssh`)

*Source: `cmd/cerberus-ssh/main.go`*

| Environment Variable | CLI Flag | Default | Required? | Description |
|---|---|---|---|---|
| *(none)* | `-listen` | `0.0.0.0:2222` | No | SSH server listen address. |
| *(none)* | `-engine-url` | `http://host.docker.internal:8089` | No | Cerberus policy engine base URL for command decision evaluation. |
| `CERBERUS_ADMIN_TOKEN` | `-engine-token` | `""` | No | Bearer authentication token for queries to the engine. |
| `CERBERUS_SSH_UPSTREAM_HOST` | `-upstream-host` | `""` | No | Target upstream SSH host (passed as policy context). |
| `CERBERUS_SSH_UPSTREAM_USER` | `-upstream-user` | `""` | No | Target upstream SSH user (passed as policy context). |
| `CERBERUS_SSH_UPSTREAM_KEY` | `-key-file` | `""` | No | Upstream SSH private key PEM file path. When unset, runs in **decide-only audit mode** (no relay). |
| *(none)* | `-hostkey-file` | `/data/cerberus_ssh_hostkey` | No | Bastion server host private key path (auto-generated on boot if missing). |
| `CERBERUS_SSH_UPSTREAM_HOSTKEY` | `-upstream-hostkey` | `""` | No | Base64-encoded upstream public host key pin. |

---

## 3. Installation Pathways

### Pathway A: Quick Start (Production GHCR Image)

1. Clone or copy the deployment compose manifest:
   ```bash
   git clone https://github.com/metabbe3/Cerberus.git
   cd Cerberus
   ```

2. Initialize your `.env` configuration file from the template:
   ```bash
   cp .env.example .env
   ```

3. Generate secure secrets and populate `.env`:
   ```bash
   # Generate random tokens
   ENGINE_TOKEN=$(openssl rand -base64 32)
   TAP_TOKEN=$(openssl rand -base64 32)

   # Populate .env
   sed -i.bak "s|^CERBERUS_ADMIN_TOKEN=.*|CERBERUS_ADMIN_TOKEN=${ENGINE_TOKEN}|" .env
   sed -i.bak "s|^TAP_ADMIN_TOKEN=.*|TAP_ADMIN_TOKEN=${TAP_TOKEN}|" .env
   rm -f .env.bak
   ```

4. Launch the 5-service stack:
   ```bash
   docker compose -f docker-compose.prod.yml up -d
   ```

---

### Pathway B: Build from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/metabbe3/Cerberus.git
   cd Cerberus
   ```

2. Build the unified multi-stage container image locally:
   ```bash
   docker build -t ghcr.io/metabbe3/cerberus:latest .
   ```

3. (Optional) Compile native binaries directly on host:
   ```bash
   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/ ./cmd/...
   ```

4. Launch using the built image:
   ```bash
   cp .env.example .env
   # Edit .env with your tokens
   docker compose -f docker-compose.prod.yml up -d
   ```

---

## 4. Operational Verification

### 4.1 Verify Service Health
Check engine health status directly using the internal network:
```bash
docker compose -f docker-compose.prod.yml exec engine wget -qO- http://127.0.0.1:8089/healthz
# Expected output: ok
```

Check LLM tap health status on host loopback:
```bash
curl -s http://127.0.0.1:8090/tap/healthz
# Expected output: ok
```

### 4.2 Verify Decision Evaluation
Execute a test tool decision evaluation against the policy engine:
```bash
docker compose -f docker-compose.prod.yml exec engine wget -qO- \
  --post-data='{"key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"kubectl get pods"}}' \
  --header="Content-Type: application/json" \
  http://127.0.0.1:8089/v1/decide/tool
```

Expected JSON response:
```json
{
  "decision": "allow",
  "rule_id": "ai.tool.allow",
  "reason": "tool call kubernetes_get_pods allowed",
  "masked_args": null,
  "epoch": 1,
  "cached": false
}
```

---

## 5. Troubleshooting & FAQ

- **Port Conflict (`bind: address already in use`):**
  Ensure no legacy gate instances or conflicting services are binding to `127.0.0.1:8090`, `127.0.0.1:2377`, `127.0.0.1:8088`, or `127.0.0.1:2222`. Inspect active listeners with `lsof -i :8090` or `docker ps`.
- **Engine Fails to Boot (`CERBERUS_ADMIN_TOKEN is required`):**
  `CERBERUS_ADMIN_TOKEN` must be non-empty in your `.env` file. For security, it cannot be passed as a CLI flag.
- **Fail-Closed Tap Denials (`strict mode active`):**
  When `-strict` is set on `cerberus-tap`, any network partition or failure to reach `http://engine:8089` results in request denial. Verify both containers share the `internal` Docker network.
- **Read-Only Filesystem / Permission Errors:**
  Containers run as UID `10001` (`cerberus`). All persistent write operations must target designated named volumes (`engineaudit`, `tapdata`, `proxyaudit`, `egressaudit`, `sshdata`) or tmpfs mounts (`/tmp`). Bind mounts (`/policies`, `/data`) must have read permissions for UID 10001.
