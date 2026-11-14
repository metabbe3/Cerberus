# SPRINT MVP-60 REPORT: Packaging & Installer

**Status:** COMPLETE (All Milestones M1–M5 Passed)  
**Worktree:** `~/Documents/cerberus-wt-mvp`  
**Target:** Quickstart < 5 menit, 100% 12-Factor secrets, zero-leak credential hygiene.

---

## 1. Executive Summary & Verification Matrix

| Milestone | Item | Status | Verification Check |
|---|---|---|---|
| **M1** | `scripts/get.sh` installer | ✅ PASS | `bash -n scripts/get.sh` passed; idempotent test passed (secrets only echoed on first run, hidden on rerun; chmod 0600 enforced). |
| **M2** | `docker-compose.prod.yml` 12-factor | ✅ PASS | `docker compose -f docker-compose.prod.yml config -q` validated; all 6 services (engine, tap, proxy, egress, ssh, owl) configured with `${VAR:?err}` or `${VAR:-default}`. |
| **M3** | `.env.example` lengkap | ✅ PASS | Enumerated all variables from `internal/config` and `cmd/*` with 1-line explanation, defaults, and `openssl rand -hex 24` generators. |
| **M4** | README + QUICKSTART + SETUP | ✅ PASS | `docs/QUICKSTART.md` created (3 install pathways, agent runtime wiring, initial FAQ); `README.md` rewritten with component table & stage matrix; `docs/SETUP.md` synchronized. |
| **M5** | CI workflow GHCR build & push | ✅ PASS | `.github/workflows/ci.yml` added `docker` job (`needs: [test]`, `main`-only, multi-tagged `latest` + sha, `ghcr.io/metabbe3/cerberus`). YAML syntax validated. |

---

## 2. Milestone Details

### M1: `scripts/get.sh` Bootstrapper
- **Location:** `scripts/get.sh` (executable `chmod +x`)
- **Key Capabilities:**
  - `set -euo pipefail` throughout.
  - Automated download of `docker-compose.prod.yml`, `policies`, and templates with git sparse-checkout fallback.
  - Generates `.env` with secure random tokens:
    - `CERBERUS_ADMIN_TOKEN="cb_adm_$(openssl rand -hex 24)"`
    - `TAP_ADMIN_TOKEN="cb_tap_$(openssl rand -hex 24)"`
    - `OWL_ADMIN_PASSWORD="cb_owl_$(openssl rand -hex 16)"`
    - `OWL_SESSION_SECRET="$(openssl rand -hex 32)"`
    - `CERBERUS_AGENT_SECRET="sk-cb-$(openssl rand -hex 24)"`
    - `CERBERUS_AGENT_KEY="$(echo -n $SECRET | sha256sum)"`
  - Restricts permissions immediately to `chmod 600 .env`.
  - Starts stack using `docker compose -f docker-compose.prod.yml up -d --wait`.
  - Runs 2 automated smoke tests:
    1. Allow: `kubectl get pods` via `k-glob` (`rule_id: ai.tool.allow`).
    2. Deny: `rm -rf /` via Production Shield (`rule_id: shield.cmd.dangerous`).
  - **Idempotency & Zero-Leak Secret Discipline:**
    - On first generation: Prints generated credentials once with a prominent warning banner.
    - On subsequent executions: Reuses existing `.env` without echoing any secrets to stdout (only path is displayed).
  - Prints agent integration environment variables (`ANTHROPIC_BASE_URL`, `X-Tap-Key`, `HTTP_PROXY`, `DOCKER_HOST`) and Owl URL (`http://127.0.0.1:3000`).

### M2: `docker-compose.prod.yml` 12-Factor Penuh
- **Location:** `docker-compose.prod.yml`
- **Services (6 Services):**
  1. `engine`: Policy brain on `127.0.0.1:8089` (loopback + internal network), healthcheck `/healthz`, non-root, read-only rootfs.
  2. `tap`: In-path proxy on `127.0.0.1:8090`. Replaced hardcoded `api.z.ai` with `${CERBERUS_TAP_UPSTREAM:-https://api.anthropic.com}`.
  3. `proxy`: Docker daemon socket shield on `127.0.0.1:2377`.
  4. `egress`: Outbound HTTP/CONNECT egress proxy on `127.0.0.1:8088`.
  5. `ssh`: SSH bastion command audit gate on `127.0.0.1:2222`.
  6. `owl`: Administrative dashboard built from `./owl/Dockerfile` on `127.0.0.1:3000`. Wired to `CERBERUS_URL: http://engine:8089` and `OWL_ADMIN_PASSWORD` / `OWL_SESSION_SECRET`.
- **12-Factor Enforcement:**
  - Required tokens fail fast with `${VAR:?error message}`.
  - Optional settings provide sane defaults via `${VAR:-default}`.
  - Internal network and volumes (`engineaudit`, `tapdata`, `proxyaudit`, `egressaudit`, `sshdata`) preserved.

### M3: `.env.example` Lengkap
- **Location:** `.env.example`
- **Sections:**
  1. Core Policy Engine (`CERBERUS_ADMIN_TOKEN`, `CERBERUS_ADDR`, `CERBERUS_POLICY_DIR`, `CERBERUS_DATA_FILE`, `CERBERUS_AUDIT_DB`, `CERBERUS_AUDIT_RETENTION_DAYS`, `CERBERUS_EVAL_TIMEOUT`, `CERBERUS_LOG_LEVEL`, `CERBERUS_CACHE_SIZE`, `CERBERUS_PG_DSN`, `CERBERUS_DECISION_LOG_SHIP_URL`, `CERBERUS_BUNDLE_PUBKEY`, `CERBERUS_REQUIRE_AGENT_KEYS`, `CERBERUS_TRUST_UNIX_SOCKET`, `CERBERUS_DEFAULT_ACTION`).
  2. Inter-Service Communication (`CERBERUS_ENGINE_URL`).
  3. LLM Tap Gate (`CERBERUS_TAP_UPSTREAM`, `CERBERUS_TAP_LISTEN`, `TAP_ADMIN_TOKEN`, `CERBERUS_TAP_RETENTION_DAYS`).
  4. Docker Enforcer & Egress Proxy (`CERBERUS_PROXY_LISTEN`, `CERBERUS_PROXY_DOCKER_HOST`, `CERBERUS_EGRESS_ADDR`, `CERBERUS_PROXY_DEFAULT_KEY`).
  5. SSH Bastion Gate (`CERBERUS_SSH_LISTEN`, `CERBERUS_SSH_UPSTREAM_HOST`, `CERBERUS_SSH_UPSTREAM_USER`, `CERBERUS_SSH_UPSTREAM_KEY`, `CERBERUS_SSH_UPSTREAM_HOSTKEY`).
  6. Owl Dashboard (`OWL_ADMIN_PASSWORD`, `OWL_SESSION_SECRET`).
  7. Quickstart Agent Credentials (`CERBERUS_AGENT_SECRET`, `CERBERUS_AGENT_KEY`).

### M4: README + QUICKSTART + SETUP Documentation
- **`docs/QUICKSTART.md` (New):**
  - Three distinct installation pathways:
    - Pathway 1: Automatic 1-line bootstrapper (`get.sh`).
    - Pathway 2: Manual Docker Compose (12-factor production).
    - Pathway 3: Native build from source (Go + Node.js + OPA).
  - Runtime integration recipes: Claude Code (`ANTHROPIC_BASE_URL`), Cursor IDE, generic OpenAI / Anthropic SDKs (Python), `HTTP_PROXY` outbound egress shield, and `DOCKER_HOST` socket isolation.
  - Initial FAQ troubleshooting: HTTP 401 token mismatch, HTTP 403 unknown agent key in fail-closed mode.
- **`README.md` (Updated):**
  - Installation section rewritten to point directly to `docs/QUICKSTART.md`.
  - Added CI build badge.
  - Component table covering all 6 services (`engine`, `tap`, `proxy`, `egress`, `ssh`, `owl`) with roles and port bindings.
  - Enforcement stage matrix:
    - `shell` / `tool`: ✅ Live
    - `http` (egress): ✅ Live
    - `docker`: ✅ Live
    - `ssh`: ✅ Live
    - `llm`: ✅ Live
    - `db`: ⏳ Coming Soon
    - `k8s`: ⏳ Coming Soon
- **`docs/SETUP.md` (Updated):**
  - Synchronized with new 12-factor configuration parameters and Owl service. Kept as the deep reference guide without duplicating quickstart content.

### M5: CI Build & Push Image to GHCR
- **Location:** `.github/workflows/ci.yml`
- **Implementation:**
  - Added `docker` job with `needs: [test]`.
  - Restricted execution strictly to `main` branch pushes: `if: github.ref == 'refs/heads/main' && github.event_name == 'push'`.
  - Configured permissions `contents: read`, `packages: write`.
  - Automated login to `ghcr.io` via `secrets.GITHUB_TOKEN`.
  - Multi-target image build from `./Dockerfile` pushed with both tags:
    - `ghcr.io/metabbe3/cerberus:latest`
    - `ghcr.io/metabbe3/cerberus:${{ github.sha }}`

---

## 3. Compliance with Rules Keras

1. **No protected code modified:**
   - Directories `internal/`, `cmd/`, `pkg/`, `policies/` were **NOT modified** (verified via `git status`).
2. **No commit or push:**
   - Changes remain unstaged/uncommitted in the worktree.
3. **Verification commands:**
   - `bash -n scripts/get.sh` → ✅ Passed (Exit code 0).
   - `CERBERUS_ADMIN_TOKEN="dummy" OWL_ADMIN_PASSWORD="dummy" OWL_SESSION_SECRET="dummy" docker compose -f docker-compose.prod.yml config -q` → ✅ Passed (Exit code 0).
   - YAML workflow check (`ruby -ryaml`) → ✅ Passed.
