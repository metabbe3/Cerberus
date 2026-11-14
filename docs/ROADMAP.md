# Cerberus Roadmap

Direction, phase order, stack decisions, and the rules every phase follows.
Conventions (Go/Rego/TS style) live in [CONVENTIONS.md](CONVENTIONS.md).
Each phase gets its own task-level plan under `docs/superpowers/plans/` when it is reached.

Decisions locked (2026-11-10): Owl dashboard runs as a **separate Next.js server**
(independent deploy/update in prod); docs in English; engine is one static Go binary.

## Monorepo layout (final)

```
Cerberus/
  cmd/cerberus/            # engine binary: HTTP :8089 (+ gRPC :8090 from Phase 3)
  internal/
    policy/                # load rego+data → Snapshot; atomic store; reload
    engine/                # Decide(): cache → singleflight → eval → mask → audit
    masking/               # regex rules, redact/mask/hash
    audit/                 # async batcher → SQLite WAL; ring buffer; subscribe
    server/                # net/http handlers, admin auth, SSE
    config/                # env/flag parsing
  policies/
    gateway/authz.rego     # core gate + stage dispatch
    stages/ai.rego         # llm + tool rules
    stages/{http,docker,k8s}.rego   # later phases
    **/*_test.rego         # opa test
  data/                    # policy data JSON (hot-reload, dashboard-managed)
  owl/                     # Next.js 15 + shadcn dashboard (separate server, own Dockerfile)
  sdk/{go,python,ts}/      # Phase 3
  deploy/                  # Dockerfile(s), docker-compose, caddy/docker-socket examples
  docs/{adr,ROADMAP.md,CONVENTIONS.md,GUIDE.md,superpowers/plans/}
```

One semver for the whole repo (`vX.Y.Z` git tag). Engine, Owl, SDKs release together.

## Phases

| # | Phase | Deliverable | Depends on | Plan file |
|---|---|---|---|---|
| 0 | Scaffold | go.mod, Makefile, golangci, CI, CONVENTIONS | — | folded into Phase 1 plan (Task 1) |
| 1 | **Core engine + AI stages** | Single Go binary: `/v1/decide`, `/v1/decide/{llm,tool}`, cache, masking, audit SQLite, SSE, admin data API, `/healthz` `/readyz` `/metrics`, Dockerfile, bench ≥ ADR-0001 targets | 0 | [2026-11-10-phase1-core-engine.md](superpowers/plans/2026-11-10-phase1-core-engine.md) |
| 2 | **Owl dashboard** | Next.js 15 + shadcn, separate server; agents table, tool matrix, constraint/masking editor, live decision stream, "create rule from event", settings flags, Rego view+validate | 1 | written when Phase 1 ships |
| 3 | **SDK + gRPC** | gRPC `:8090` (`DecideRequest/DecideResponse` proto); `sdk/go` (native client, gRPC+HTTP), `sdk/python` (httpx, LiteLLM `CustomLogger` pre-call hook example), `sdk/ts` (fetch); publish pip/npm from monorepo | 1 | TBD |
| 4 | **http stage** | `stages/http.rego`, `domains.http` data, Caddy `forward_auth` example in `deploy/caddy/`, Go `net/http` middleware in `sdk/go/middleware` | 1 (3 nice-to-have) | TBD |
| 5 | **docker stage** | `stages/docker.rego`, socket-proxy adapter `cmd/cerberus-docker-proxy` (rewrites Docker API → `stage: docker`), docker-compose demo | 1 | TBD |
| 6 | **k8s / ci / db stages** | only when a real consumer exists (YAGNI) | 1 | TBD |
| 7 | **Release hardening** | goreleaser, multi-arch images, SBOM, upgrade/migration notes, load test report | 1–5 | TBD |

Phase order rationale: ADR-0002 says AI → http → docker. Dashboard is pulled to Phase 2 because
the owner's core concept (#7 in README) is dashboard-managed data; without it, hot-reload is curl-only.

## Phase 2 direction — Owl (Next.js + shadcn), separate server

**Stack (pinned):** Next.js 15 App Router · TypeScript `strict` · Tailwind v4 · shadcn/ui
(style `new-york`, `components.json` committed) · `@tanstack/react-query` · `@tanstack/react-table` ·
`react-hook-form` + `zod` · `next-themes` · `sonner` · `lucide-react` · Vitest + Testing Library ·
Playwright (3 smoke flows max).

**Architecture rules:**

1. **Browser never talks to the engine directly.** Next.js route handlers under `app/api/*` proxy to
   the engine with `CERBERUS_URL` + `CERBERUS_ADMIN_TOKEN` (server-side env only). The admin token
   never reaches the client.
2. **SSE** `app/api/events/route.ts` streams `GET /v1/events` from the engine → client uses
   `EventSource('/api/events')`.
3. **Data model is the engine's JSON.** One `lib/schema.ts` zod schema mirrors `data/*.json`; every
   form parses with it before `PUT /api/data`. No second data model.
4. **shadcn rules:** `components/ui/*` = generated, never hand-edited (re-run `npx shadcn add` to
   update). Feature components in `components/<feature>/`. Use `cn()` from `lib/utils`. Theme via CSS
   variables in `globals.css` only — no hardcoded colors. Dark mode via `next-themes`. Forms = shadcn
   `Form` + `zod`. Tables = one shared `DataTable` wrapper over TanStack Table (not per page).
   Toasts = `sonner`. Loading = `Skeleton`, errors = `Alert`, empty = one shared `EmptyState`.
5. **Pages:** `/` (overview: decisions/min, allow/deny ratio, top denied rules) · `/agents` (table) ·
   `/agents/[keyId]` (tabs: tools, constraints, masking, models/budget) · `/decisions` (live stream +
   filter; row action "Create rule from this event" pre-fills the agent editor) · `/policy` (read-only
   Rego viewer + "Validate" → `POST /api/policy/validate`) · `/settings` (bypass flags, with a red
   confirm when flipping to fail-closed).
6. **Testing:** Vitest for `lib/schema.ts` and any pure helper; Playwright smoke: load agents table,
   edit one agent and save (epoch increments), decision stream shows a new event. Nothing else until
   it hurts.
7. **Deploy:** `owl/Dockerfile` (Node 22-alpine, `next build`, `output: 'standalone'`).
   `deploy/docker-compose.yml` runs `cerberus` + `owl`. Owl is optional at runtime — the engine works
   without it.

## Go best practices (summary — full rules in CONVENTIONS.md)

stdlib first (`net/http` ServeMux 1.22 patterns, `log/slog`, `flag`, `embed`, `sync/atomic`,
`context`). Dependencies capped at: `open-policy-agent/opa`, `modernc.org/sqlite` (no cgo → static
binary), `hashicorp/golang-lru/v2`, `golang.org/x/sync` (singleflight, errgroup),
`prometheus/client_golang`, later `google.golang.org/grpc`. Anything else needs a one-line
justification in the PR.

## Concurrency rules (from ADR-0001, made testable)

| Rule | Enforced by |
|---|---|
| No lock on the hot path | `Store.Current()` is `atomic.Pointer.Load()`; `go test -race` in CI |
| Reload = build new snapshot off-path, then swap | `TestStore_ReloadDoesNotBlockCurrent` |
| Cache keyed by (epoch, input) — reload invalidates | `TestDecide_EpochInvalidatesCache` |
| Identical concurrent inputs → one eval | singleflight; `TestDecide_Singleflight` (misses == 1 for 100 goroutines) |
| Eval timeout → deny fail-closed, never hang | `TestDecide_TimeoutDenies` |
| Audit never blocks a decision | buffered chan + `select default` drop; `TestLogger_FullChannelDrops` |
| Single SQLite writer goroutine | only `audit.run()` holds the write path |
| Benchmarks gate merge | `BenchmarkDecide_{Hit,Miss}` 8 goroutines × 10k: p99 < 0.1ms hit, < 1ms miss |

## Testing strategy

- **Rego:** `opa test policies/ -v` — every rule_id has ≥1 allow and ≥1 deny test. Fixtures in
  `policies/testdata/data.json`.
- **Go unit:** table-driven, stdlib `testing`, `httptest`. Golden decision JSON for the public
  `/v1/decide` contract in `internal/server/testdata/*.golden.json`.
- **Race + bench:** `go test -race ./...` and `go test -bench=. -benchmem ./internal/engine` in CI;
  p99 asserted in a companion test behind `CERBERUS_BENCH_ASSERT=1`.
- **Smoke:** `make smoke` = start binary, curl allow/deny/masked/reload, assert exit 0.
- **Dashboard:** see Phase 2 §6.
- **No mocks of OPA.** Tests evaluate real Rego against fixture data; the engine is the unit.

## Next (Future Scope — Post-U2)

Features noted from LiteLLM patterns and enterprise feedback reserved for future iterations (explicitly outside current U2 scope):
- **Internal-user self-service portal**: End-users view their own key usage, rate limits, and audit logs (LiteLLM `internal_user`).
- **Organization hierarchy**: Multi-tenancy structure for Org > Team > Project isolation.
- **Per-model budgets**: Granular quotas and call rate allocations pinned to specific model identifiers.
- **SSO / OIDC identity providers**: Direct Google Workspace, Okta, and Azure AD integration via engine provider modules (see ADR-0005).
- **Cost-per-call metering**: Multiplied token counts from tap metrics against dynamic model pricing tables.
- **Custom dashboard builder**: NEVER — anti-scope. Keep opinionated, security-focused operational dashboards.

