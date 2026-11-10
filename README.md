# Cerberus — OPA-style Policy Engine untuk AI Agent Gateway 🔥

> "OPA-nya" ekosistem agent: satu pintu policy untuk tool/command/data permission,
> data masking, dan governance per-key/per-team — dievaluasi Rego, hot-reload dari
> dashboard, tanpa recompile.

## Status
DESIGN (spec review) — belum implementasi. Owner: Nicholas. Dibangun oleh Hermes Agent.

## Konsep inti (dari diskusi owner, 10-11 Nov 2026)

1. **Rego = production-grade choice** (owner: "I like rego because it's for production grade")
   — policy-as-code deterministic, auditable, dipakai Netflix/Pinterest/Coinbase.
2. **Policy vs Data split**: `authz.rego` = logika stabil; `data/*.json` = kebijakan
   (dashboard-managed) → hot-reload tanpa recompile/restart.
3. **Governance per-key & per-team independen** (pola owner): key terdaftar di `agents`
   dipolisi oleh key_id saja — team-nya TIDAK perlu terdaftar. Bypass flags fail-open
   untuk semua yang belum terdaftar (fase onboarding), fail-closed setelah
   `bypass_unknown_keys/teams = false`.
4. **Polisi yang DIPANGGIL, bukan yang diiklankan**: `allowed_tool_calls` /
   `restricted_tool_calls` (prefix-glob / substring-glob, case-insensitive) dievaluasi
   terhadap tool yang model SUNGGUH invoke — bukan toolset yang client advertise.
   (Pelajaran owner: policing `input.tools` menolak request utuh gara-gara tool
   yang cuma ditawarkan.)
5. **Dua decision point**:
   - `POST /v1/decide/llm` — pre-call: model allowlist, budget, blocked_patterns.
   - `POST /v1/decide/tool` — pre-exec: tool_calls check + argument constraints
     (bare-array / explicit allowlist / regex_allow / range) + **masking** (redact/mask/hash).
6. **Masking di Rego**: args/response ditransform sebelum kembali — hasil masked bisa
   langsung dieksekusi agent.
7. **Dashboard** (Next.js + shadcn): agents table, tool matrix, constraint & masking
   editor, budget bar, live decision stream (SSE dari audit log), "create rule from
   this event" 1 klik, Rego editor + validate utk advanced.
8. **SDK**: Go native, Python, TypeScript (HTTP + gRPC) + contoh hook LiteLLM.

## Layout (rencana)

```
Cerberus/                        # MONOREPO — engine + Owl dashboard + SDK (satu versi)
  cmd/cerberus/                  # engine binary (HTTP :8089 + gRPC :8090)
  internal/                      # engine, masking (port GoAgent), cache LRU, audit, sse
  policies/                      # gateway/authz.rego + stages/{ai,docker,http,k8s}.rego
  data/                          # kebijakan JSON (dashboard-managed, hot-reload)
  owl/                           # DASHBOARD "Owl" 🦉 (Next.js + shadcn) — SSE decision stream
  sdk/{go,python,ts}/            # SDK multi-bahasa (publish pip/npm dari sini)
  deploy/                        # Dockerfile, docker-compose, docker-socket-proxy example
  docs/adr/                      # ADR per keputusan arsitektur
```

## Data schema (lihat data/prod.json & data.template.json)

`config{bypass_unknown_teams, bypass_unknown_keys}` · `teams{name, allowed_models,
allowed_tools, budget_limit}` · `agents[key_id]{name, team_id, allowed_tools | allowed_tool_calls,
restricted_tools | restricted_tool_calls, tool_argument_constraints{tool{arg: bare[] |
{type:allowlist|regex_allow|range}}}, budget_limit, risk_tier, log_level, masking[{pattern,
transform, scope}]}` · `blocked_patterns[]`.

Key = LiteLLM key_id/token_id (GET /key/info) — NEVER raw sk- secret.
