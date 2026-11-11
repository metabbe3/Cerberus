# Cerberus — OPA-style Policy Engine untuk AI Agent Gateway 🔥

> "OPA-nya" ekosistem agent: satu pintu policy untuk tool/command/data permission,
> data masking, dan governance per-key/per-team — dievaluasi Rego, hot-reload dari
> dashboard, tanpa recompile.

## Status
**PRODUCTION LIVE** di `cerberus.hivepos.id` — engine Go + Rego embed (OPA sebagai
library, µs–ms in-process), **Owl 🦉** dashboard (Next.js 15), **PostgreSQL system
of record**, SDK Go/Python/TypeScript, egress + docker-socket proxy enforcement.
OPA test **152/152** · go test 10 packages + `-race` · gofmt/vet clean ·
~85k TPS sustained (lihat [docs/BENCH.md](docs/BENCH.md)).

Owner: Nicholas. Dibangun oleh Hermes Agent.

## Quickstart

```sh
make build
export CERBERUS_ADMIN_TOKEN=change-me
./bin/cerberus                       # :8089 — panduan lengkap: docs/GUIDE.md

# PostgreSQL system of record (opsional; tanpa ini = file flat):
export CERBERUS_PG_DSN="postgres://cerberus:***@host:5433/cerberus"
psql -f migrations/001_postgres.sql # sekali saja

# Owl dashboard (separate server, proxied — token never reaches the browser):
cd owl && cp .env.example .env.local  # fill CERBERUS_ADMIN_TOKEN
npm install && npm run dev            # http://localhost:3000

curl -s -X POST localhost:8089/v1/decide/tool -H 'Content-Type: application/json' \
  -d '{"key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"kubectl get pods"}}'
```

- Arah & fase: [docs/ROADMAP.md](docs/ROADMAP.md)
- Aturan kode (Go/Rego/TS): [docs/CONVENTIONS.md](docs/CONVENTIONS.md)
- Deploy per-OS (systemd/launchd/distroless): [docs/DEPLOY.md](docs/DEPLOY.md)
- Desain publik vs dashboard: [docs/DESIGN_PHILOSOPHY.md](docs/DESIGN_PHILOSOPHY.md)

## Konsep inti

1. **Rego = production-grade choice** — policy-as-code deterministic, auditable,
   dipakai Netflix/Pinterest/Coinbase.
2. **Policy vs Data split**: `authz.rego` = logika stabil; data JSON/Postgres =
   kebijakan (dashboard-managed) → hot-reload tanpa recompile/restart.
3. **Governance per-key & per-team independen**: key terdaftar di `agents` dipolisi
   oleh key_id saja. Bypass flags fail-open untuk onboarding; `bypass_unknown_keys
   = false` = fail-closed.
4. **Polisi yang DIPANGGIL, bukan yang diiklankan**: `allowed_tool_calls` /
   `restricted_tool_calls` (prefix-glob, case-insensitive; `allowed_models`
   glob-aware) dievaluasi terhadap tool yang model SUNGGUH invoke — bukan toolset
   yang client advertise.
5. **Decision points**:
   - `POST /v1/decide/llm` — pre-call: model allowlist (glob), budget kumulatif,
     blocked_patterns deep-scan prompt + messages[] (EN+ID).
   - `POST /v1/decide/tool` — pre-exec: tool check + argument constraints
     (bare-array / allowlist / regex_allow / range) + masking.
   - `POST /v1/decide` — generic: stage di body (`llm|tool|http|docker|ssh|custom:*`).
6. **Masking**: regex per-agent (redact `[REDACTED]` / mask `10****.7` / hash
   sha256) untuk tool-args DAN percakapan LLM (`masked_prompt` di decision +
   audit) — aktif via PUT data, tanpa deploy.
7. **Kill switch per-key**: `kill_switch.keys[key_id] = true` → SEMUA stage deny
   `ops.kill_switch` + Break-Glass 15 menit dari dashboard.
8. **Enforcement tiga jalur** (bukan cuma advisory):
   - SDK `GuardedExecutor` (deny = fungsi tak pernah terpanggil)
   - **Docker socket-proxy** (`cmd/cerberus-proxy` :2377) — satu-satunya jalan ke
     docker.sock; container terlindungi & mount docker.sock = 403
   - **Egress CONNECT proxy** (:8088) — CIDR prod shield + anti-host-spoof +
     DNS-all-IP check di jalur keluar
9. **PostgreSQL system of record**: boot dari PG (`CERBERUS_PG_DSN`), tiap admin
   PUT auto-persist, fallback file + WARN saat PG mati. Removal agent = disable
   (audit history stabil), bukan delete.

## Monitoring & Observability

- **`GET /v1/health/components`** — satu endpoint laporan estate
  (engine/agents/kill_switch/postgres/audit; status `ok|degraded|down`; kill
  aktif tampil degraded + daftar key).
- **`GET /v1/audit/timeseries?since&until&buckets`** — agregasi server-side
  bucket epoch-aligned (default 48, cap 500) dengan split allow/deny lintas
  daily audit files — pola Grafana/Datadog: bucket dihitung di server, bukan
  raw event dikirim ke browser. `until` (exclusive) juga tersedia di
  `GET /v1/audit` → range query bebas & compare antar date-range = dua call.
- **Tab Monitoring Owl** — pola SRE dashboard: estate health strip, KPI tiles +
  sparkline (total/allow/deny/peak), chart stacked allow-vs-deny (SVG murni),
  window selector **1 jam / 6 jam / 24 jam / 7 hari** + auto-refresh 60 detik.
- **Login hardening**: password + session HMAC httpOnly + brute-force lockout
  (5 gagal / IP / 15 menit → kunci 15 menit, `429 + Retry-After`).
- Audit: SQLite WAL buffered-channel single-writer, rotasi harian
  `audit-YYYYMMDD.db`, masking at-rest, ship-out fire-and-forget.

## Layout

```
Cerberus/                        # MONOREPO — engine + Owl dashboard + SDK (satu versi)
  cmd/cerberus/                  # engine binary (HTTP :8089)
  cmd/cerberus-proxy/            # docker socket-proxy + egress proxy (enforcement)
  cmd/cerberus-redteam/          # suite serangan deterministik (exit 0 = hijau)
  cmd/loadgen-stress/            # load generator (docs/BENCH.md)
  internal/                      # engine, masking, store (Postgres), audit, util
  policies/                      # gateway/authz.rego + stages/{ai,http,docker,ssh}.rego + shield/
  migrations/                    # 001_postgres.sql (system of record)
  owl/                           # DASHBOARD "Owl" 🦉 (Next.js 15 + shadcn) — tab Monitoring
  sdk/{go,python,ts}/            # SDK multi-bahasa (GuardedExecutor, retry+cache+fail-closed)
  deploy/                        # systemd / launchd / distroless Dockerfile / harden script
  docs/                          # GUIDE, DEPLOY, BENCH, BYPASS_MATRIX, DESIGN_PHILOSOPHY, ADR
```

## Data schema

`config{bypass_unknown_teams, bypass_unknown_keys, kill_switch{keys[]}}` ·
`teams{name, allowed_models, allowed_tools, budget_limit}` ·
`agents[key_id]{name, team_id, allowed_tool_calls, restricted_tool_calls,
tool_argument_constraints, allowed_models (glob), budget_limit, risk_tier,
masking[{pattern, transform: redact|mask|hash, scope}], prod_access}` ·
`blocked_patterns[]` · `prod_shield{dangerous_cmd_patterns, protected_cidrs,
protected_hosts, protected_containers, exempt_keys}` · `templates[]`
(server-side, builtin immutable 409).

Key = LiteLLM key_id/token_id (GET /key/info) — NEVER raw sk- secret.

## Admin API (Bearer CERBERUS_ADMIN_TOKEN)

| Endpoint | Fungsi |
|---|---|
| `GET/PUT /v1/admin/data` | baca/tulis seluruh policy data (epoch, persist ke PG) |
| `GET/PUT/DELETE /v1/admin/templates` | template server-side (builtin 409) |
| `GET /v1/health/components` | laporan kesehatan estate satu endpoint |
| `GET /v1/audit?since&until&…` | query event audit (range bebas) |
| `GET /v1/audit/timeseries` | bucket agregasi allow/deny untuk chart |
| `GET /v1/status` · `GET /v1/events` | status + SSE stream live |
