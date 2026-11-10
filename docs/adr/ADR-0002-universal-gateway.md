# ADR-0002: Universal Gateway — fleksibel untuk workload apa pun (AI, Docker, HTTP, CI, DB)

**Status**: Accepted · **Date**: 2026-11-10 · **Owner**: Nicholas

## Context

Owner: "Bisa bikin untuk yang lain juga? Docker dll? Biar ini fleksibel untuk apapun?"
Cerberus tidak boleh terkunci ke use case AI-agent — policy engine yang sama harus
bisa menjaga Docker API, kubectl, HTTP API internal, CI runners, sampai database.

OPA sendiri membuktikan pola ini: input JSON netral + policy Rego = bisa authorize
apa saja. Cerberus mengikuti pola yang sama tapi dengan pengalaman integrasi yang
lebih sederhana (satu endpoint `/v1/decide`, schema input seragam).

## Decision

### 1. Input contract netral (stage-based, bukan AI-specific)

Satu schema input untuk semua workload:

```json
{
  "stage": "llm|tool|http|docker|k8s|ci|db|custom:<x>",
  "key_id": "<identity>",
  "action": "deploy|delete|read|write|exec|...",
  "resource": "container:nginx|secret:prod-db|endpoint:/v1/admin|...",
  "args": { ... bebas ... },
  "context": { "source_ip": "...", "time": "...", "team": "..." }
}
```

`stage` = jenis decision point. AI agents pakai `llm` + `tool`; Docker proxy pakai
`docker`; HTTP middleware pakai `http`. Rego match per stage — policy lain tidak
saling ganggu.

### 2. Adapter layer (bukan core)

Workload spesifik hidup di adapter tipis yang MENERJEMAHKAN, bukan di engine:

| Adapter | Cara kerja |
|---|---|
| **AI/LiteLLM** | custom hook pre-call → `stage: llm`; agent SDK pre-exec → `stage: tool` |
| **Docker** | socket-proxy pattern: Cerberus duduk di depan `/var/run/docker.sock`; request HTTP Docker di-rewrite ke input `stage: docker, action: <method>, resource: containers/images/volumes` |
| **Kubernetes** | webhook admission / kubectl proxy → `stage: k8s` |
| **HTTP API** | reverse-proxy middleware (nginx/Caddy/Go) → `stage: http` |
| **CI** | GitHub Actions / job runner pre-step → `stage: ci` |
| **DB** | proxy SQL / pgbouncer auth query → `stage: db` |

Core (`/v1/decide` + Rego + cache + audit) TIDAK berubah saat menambah workload baru.

### 3. Rego per-domain (package per stage)

```
policies/
  gateway/authz.rego      # core: bypass, key lookup, masking, deny default
  stages/ai.rego          # llm + tool rules
  stages/docker.rego      # docker rules
  stages/http.rego        # http rules
  stages/k8s.rego         # k8s rules
```

`gateway.authz.decision` = komposisi: core gate dulu (key terdaftar? bypass?),
lalu dispatch ke `stages.<stage>.decide`. Menambah domain = tambah 1 file rego +
data section — tanpa recompile core, hot-reload seperti biasa.

### 4. Data schema: `domains` section

```json
"domains": {
  "docker": {
    "agents": {
      "<key_id>": { "allowed": ["container:start", "image:pull"], "restricted": ["container:rm"] }
    }
  },
  "http": { ... }
}
```

Dashboard render tab per domain — matrix permission Docker berbeda dari AI tools.

## Consequences

- Cerberus = policy layer universal ala OPA, tapi single-binary + dashboard built-in.
- Menambah workload baru tidak menyentuh engine (adapter + 1 rego file + data).
- Rego tetap satu bahasa untuk semua domain — operator belajar sekali.
- Risk: adapter Docker/k8s butuh testing infra nyata — kirim sebagai adapter
  terpisah setelah core stabil (MVP tetap: AI dulu, docker/docker-sock kedua).

## Prioritas build (owner-align)

1. Core engine + AI stages (`llm`/`tool`) — MVP, langsung dipakai agent existing.
2. `http` stage + reverse-proxy example (nginx/Caddy config sample).
3. `docker` stage + socket-proxy adapter (docker-compose demo).
4. `k8s` + `ci` + `db` — menyusul sesuai kebutuhan nyata.
