# Conventions

Rules every contributor (human or model) follows. Short on purpose; if a rule needs a paragraph,
it belongs in an ADR.

## Go

- Go **1.24**, module `github.com/metabbe3/cerberus`. `gofmt` + `go vet` + `golangci-lint`
  (`errcheck, govet, staticcheck, unused, gosec, revive, gocritic`) must pass.
- Package layout: `cmd/` binaries, `internal/` everything else. No `pkg/` until an SDK needs to
  import it (Phase 3 moves client types to `sdk/go`).
- One responsibility per package; files ≤ ~400 lines; split by behavior, not by layer.
- Errors: `fmt.Errorf("policy: load %s: %w", path, err)` — prefix with package name, wrap with
  `%w`. Sentinel errors exported as `var ErrX = errors.New(...)`. Never `panic` outside `main` init.
- `context.Context` is the first param of anything that does I/O or can be cancelled.
- Logging: `log/slog` JSON handler; keys `key_id, stage, rule_id, decision, epoch, latency_us`.
  No `fmt.Println`.
- Config: env vars `CERBERUS_*` with `flag` overrides, parsed once in `internal/config`. Required
  secrets (`CERBERUS_ADMIN_TOKEN`) fail startup if empty.
- HTTP: Go 1.22 `ServeMux` patterns (`mux.HandleFunc("POST /v1/decide", ...)`).
  `http.MaxBytesReader` 1 MiB on every body. `ReadHeaderTimeout` 5s. JSON only;
  `Content-Type: application/json`.
- Concurrency: see ROADMAP table. `atomic.Pointer[T]` for snapshots, never `sync.RWMutex` on the
  hot path. Every goroutine has an owner that stops it (`ctx` or `Close()`).
- Tests: `_test.go` next to code; table-driven; `t.Parallel()` where safe; `testdata/` for
  fixtures; `t.TempDir()` for SQLite. Name: `TestType_Method_Condition`.
- Comments: doc comment on every exported symbol. `// ponytail: <ceiling> — <upgrade path>` on
  deliberate shortcuts.
- Commits: Conventional Commits (`feat(engine): ...`, `fix(rego): ...`, `test:`, `docs:`, `chore:`).
  One task = one commit.

## Rego

- `import rego.v1` in every file. Package = path (`gateway.authz`, `stages.ai`).
- Every `decision` object has exactly `{decision, rule_id, reason}`; `rule_id` is
  `<domain>.<subject>.<verdict>` and **stable** (dashboard keys off it).
- Default deny in core only; stages never define `default`.
- Each new stage: one file `policies/stages/<stage>.rego` exposing `decision` + one line in core
  dispatch + `domains.<stage>` data section + `_test.rego`.
- `opa fmt --write` before commit; `opa check --strict`.

## Data JSON

- Schema documented once in README; Owl's `lib/schema.ts` mirrors it. Unknown top-level fields are
  rejected on `PUT /v1/admin/data` (strict decode).
- `_comment` keys allowed anywhere, ignored by Rego.
- Key = LiteLLM `key_id`/`token_id`. Never a raw `sk-` secret in data.

## TypeScript / Owl

- `strict: true`, no `any` (use `unknown` + zod). ESLint `next/core-web-vitals` +
  `@typescript-eslint/strict`. Prettier default.
- Server-only secrets in route handlers; `import 'server-only'` in `lib/engine.ts`.
- shadcn rules: see ROADMAP "Phase 2 direction".
