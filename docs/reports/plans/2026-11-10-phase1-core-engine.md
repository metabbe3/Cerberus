# Phase 1: Core Engine + AI Stages — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the Cerberus engine as one static Go binary that answers `POST /v1/decide` for AI stages (`llm`, `tool`) with in-process OPA eval, bounded cache, masking, async SQLite audit, SSE stream, and hot-reloadable data — meeting ADR-0001 latency targets.

**Architecture:** `internal/policy` compiles Rego + data into an immutable `Snapshot` held in an `atomic.Pointer`; `internal/engine` wraps eval with LRU + singleflight + timeout and applies `internal/masking`; `internal/audit` batches decisions to SQLite and fans out to SSE; `internal/server` exposes everything over stdlib `net/http`.

**Tech Stack:** Go 1.24, `github.com/open-policy-agent/opa` (rego), `modernc.org/sqlite`, `hashicorp/golang-lru/v2`, `golang.org/x/sync/singleflight`, `prometheus/client_golang`, OPA CLI (`opa test/check/fmt`).

**Spec:** `README.md`, `docs/adr/ADR-0001-high-traffic-concurrency.md`, `docs/adr/ADR-0002-universal-gateway.md`, `docs/ROADMAP.md`, `docs/CONVENTIONS.md`.

## Global Constraints

- Go 1.24; dependency allowlist in ROADMAP "Go best practices"; anything else needs justification.
- Hot path (`Engine.Decide`) takes no mutex. `go test -race ./...` must pass.
- Eval timeout default **10ms** → `{"decision":"deny","rule_id":"internal.timeout"}`.
- Cache default **10 000** entries; key = `sha256(epoch ‖ canonical JSON(input))`.
- Audit channel default **4096**; when full, drop and increment `cerberus_audit_dropped_total`.
- Listen `:8089`. Body limit 1 MiB. Admin routes require `Authorization: Bearer $CERBERUS_ADMIN_TOKEN`.
- Decision response contract (public, golden-tested):
  ```json
  {"decision":"allow|deny","rule_id":"...","reason":"...","masked_args":{...}|null,"epoch":3,"cached":false}
  ```
- Glob semantics: pattern ending `*` = case-insensitive prefix; otherwise case-insensitive substring. `allowed_tools`/`restricted_tools` = exact match (case-sensitive). Both families may coexist; `restricted` wins over `allowed`.
- Unregistered key: `config.bypass_unknown_keys=true` → allow `config.bypass_unknown_keys`; else deny `config.unknown_key_closed`. Same for team with `bypass_unknown_teams` (`config.bypass_unknown_teams` / `config.unknown_team_closed`); a registered key whose `team_id` is not in `teams` is governed by key only (never denied for missing team).
- Masking transforms (exact): `redact` → `[REDACTED]`; `mask` → first 2 + last 2 chars kept, middle replaced by `*` (strings ≤ 4 chars → all `*`); `hash` → `sha256:` + first 16 hex chars.

## Review Focus

1. Malformed/empty JSON body → `400 {"error":"invalid json"}` — test in Task 7.
2. `stage` unknown (e.g. `"docker"` before Phase 5) → deny `internal.unknown_stage`, not a 500 — Rego test in Task 2.
3. `PUT /v1/admin/data` with invalid JSON or Rego that fails to compile on reload → `422`, old snapshot stays live, epoch unchanged — test in Task 7.
4. `args` containing nested objects/arrays/numbers during masking → strings anywhere in the tree are transformed, non-strings untouched — test in Task 4.
5. Missing `key_id` → deny `config.unknown_key_closed` or bypass per flag (never allow silently) — Rego test in Task 2.

Task order note: Task 4 (masking) and Task 6 (audit) have no upstream deps; run them before Tasks 3 and 5 respectively if the executor prefers never to stub. Suggested order: 1 → 2 → 4 → 3 → 6 → 5 → 7 → 8.

---

### Task 1: Scaffold (Phase 0)

**Files:**
- Create: `go.mod`, `cmd/cerberus/main.go`, `Makefile`, `.golangci.yml`, `.gitignore`, `.github/workflows/ci.yml`
- Modify: `README.md` (Status line)

**Interfaces:**
- Produces: `make build test lint opa-test opa-check bench smoke` targets; CI runs `lint`, `test` (with `-race`), `opa-check`, `opa-test`.

- [ ] **Step 1:** `go mod init github.com/metabbe3/cerberus`; `cmd/cerberus/main.go` prints version (`var version = "dev"`) on `--version` and exits 0.
- [ ] **Step 2:** `Makefile` targets: `build` (`CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o bin/cerberus ./cmd/cerberus`), `test` (`go test -race -count=1 ./...`), `lint` (`golangci-lint run`), `opa-test` (`opa test policies/ -v`), `opa-check` (`opa check --strict policies/`), `bench` (`go test -run=^$ -bench=. -benchmem ./internal/engine`), `smoke` (`scripts/smoke.sh`, Task 8).
- [ ] **Step 3:** `.golangci.yml` enabling `errcheck, govet, staticcheck, unused, gosec, revive, gocritic`.
- [ ] **Step 4:** `.github/workflows/ci.yml`: ubuntu, Go 1.24, `open-policy-agent/setup-opa@v2`, `golangci/golangci-lint-action`, run `make lint test opa-check opa-test`.
- [ ] **Step 5:** `.gitignore`: `bin/`, `*.db`, `*.db-wal`, `*.db-shm`, `owl/node_modules`, `owl/.next`.
- [ ] **Step 6:** Verify: `make build && ./bin/cerberus --version` prints a version; `make opa-check` passes on existing rego.
- [ ] **Step 7:** Commit `chore: scaffold go module, makefile, ci`.

---

### Task 2: Rego restructure — core gate + `stages/ai`

**Files:**
- Modify: `policies/gateway/authz.rego` (becomes core only)
- Create: `policies/stages/ai.rego`, `policies/gateway/authz_test.rego`, `policies/stages/ai_test.rego`, `policies/testdata/data.json`
- Modify: `data.template.json` (add `allowed_models` to the glob agent example, add `"domains": {}`), `data/prod.json` (add `"domains": {}`)

**Interfaces:**
- Produces: `data.gateway.authz.decision` → `{decision, rule_id, reason}` for any input. Go evaluates exactly this query (Task 3).
- Rule IDs (stable): `internal.default`, `internal.unknown_stage`, `config.bypass_unknown_keys`, `config.unknown_key_closed`, `config.bypass_unknown_teams`, `config.unknown_team_closed`, `ai.llm.allow`, `ai.llm.model_not_allowed`, `ai.llm.blocked_pattern`, `ai.llm.budget_exceeded`, `ai.tool.allow`, `ai.tool.restricted`, `ai.tool.not_allowed`, `ai.tool.arg_violation`.

Core `gateway/authz.rego`:
- `default decision := {"decision":"deny","rule_id":"internal.default","reason":"no decision produced"}`
- `agent := data.agents[input.key_id]`; `team := data.teams[agent.team_id]`.
- Gate order: key registered? → (team registered or bypass) → `stage_decision`. Unregistered key/team handled by `config.*` rules per Global Constraints.
- `stage_decision := data.stages.ai.decision if input.stage in {"llm","tool"}`; otherwise `{"decision":"deny","rule_id":"internal.unknown_stage","reason":...}`.
- Exports helpers `call_matches_pattern(pattern, name)` (moved from current file), `agent`, `team` for stages to use via `data.gateway.authz.*`.

`stages/ai.rego` (`package stages.ai`):
- **llm**: deny `ai.llm.budget_exceeded` if `input.context.spend_usd > agent.budget_limit`; deny `ai.llm.blocked_pattern` if any `data.blocked_patterns` substring (case-insensitive) in `input.prompt`; deny `ai.llm.model_not_allowed` if `agent.allowed_models` exists and `input.model` not in it, or `team.allowed_models` exists and `input.model` not in it; else allow `ai.llm.allow`.
- **tool**: deny `ai.tool.restricted` if `input.tool_call` matches any `restricted_tool_calls` (glob) or equals any `restricted_tools` (exact), from agent or team; deny `ai.tool.not_allowed` if an allow-list exists (`allowed_tool_calls`/`allowed_tools` on agent, or `allowed_tools` on team) and no entry matches; deny `ai.tool.arg_violation` if `agent.tool_argument_constraints[input.tool_call][arg]` exists, `input.args[arg]` is present, and it fails its form: bare array / `{type:"allowlist",values}` → value in list; `{type:"regex_allow",patterns}` → `regex.match` any; `{type:"range",min,max}` → numeric in `[min,max]`. Missing arg → not a violation. Else allow `ai.tool.allow`.

- [ ] **Step 1:** Write `policies/testdata/data.json`: `config` both bypass `true`; one team `t1` (`allowed_models:["m1"]`, `allowed_tools:["read"]`); agents `k-glob` (team `t1`, `allowed_tool_calls:["kubernetes*"]`, `restricted_tool_calls:["delete"]`, `allowed_models:["m1"]`, `budget_limit:50`, masking as in `data/prod.json`), `k-exact` (team `nope`, `allowed_tools:["bash"]`, `tool_argument_constraints.bash`: `{"cmd": {"type":"regex_allow","patterns":["^ls( .*)?$"]}, "timeout": {"type":"range","min":1,"max":60}, "env": ["prod","dev"]}`), `k-open` (no team, no lists); `blocked_patterns:["jailbreak"]`; `domains: {}`.
- [ ] **Step 2:** Write failing tests (`opa test`, using `with data as ...` / `with input as ...`), one per rule_id, asserting `decision.rule_id`. Include: unknown stage → `internal.unknown_stage`; missing `key_id` with bypass false → `config.unknown_key_closed`; missing `key_id` with bypass true → `config.bypass_unknown_keys`; `k-glob` + `kubernetes_get_pods` → `ai.tool.allow`; `k-glob` + `kubernetes_delete_pod` → `ai.tool.restricted`; `k-glob` + `read_file` → `ai.tool.not_allowed`; `k-exact` + `bash {cmd:"rm -rf /"}` → `ai.tool.arg_violation`; `k-exact` + `bash {cmd:"ls -la", timeout:30, env:"prod"}` → `ai.tool.allow`; `k-exact` + `bash {timeout:999}` → `ai.tool.arg_violation`; `k-exact` + `bash {env:"staging"}` → `ai.tool.arg_violation`; `k-open` + anything → `ai.tool.allow`; llm `k-glob` model `m1` → `ai.llm.allow`; model `m2` → `ai.llm.model_not_allowed`; `context.spend_usd:51` → `ai.llm.budget_exceeded`; prompt containing `JAILBREAK` → `ai.llm.blocked_pattern`.
- [ ] **Step 3:** Run `make opa-test` → expected FAIL (rules missing).
- [ ] **Step 4:** Implement core + `stages/ai.rego` per the interface above. `opa fmt --write policies/`.
- [ ] **Step 5:** `make opa-check opa-test` → all PASS.
- [ ] **Step 6:** Commit `feat(rego): split core gate and stages/ai with arg constraints and team gate`.

---

### Task 3: `internal/policy` — Snapshot, Loader, atomic Store

**Files:**
- Create: `internal/policy/snapshot.go`, `internal/policy/loader.go`, `internal/policy/store.go`, `internal/policy/store_test.go`, `internal/policy/loader_test.go`

**Interfaces:**
- Produces:
  ```go
  type Snapshot struct {
      Epoch   uint64
      Query   rego.PreparedEvalQuery          // query: data.gateway.authz.decision
      Data    map[string]any                  // parsed data JSON (read-only after build)
      Maskers map[string][]masking.Rule       // key_id → compiled rules (Task 4)
      Loaded  time.Time
  }
  func Load(ctx context.Context, policyDir string, dataJSON []byte, epoch uint64) (*Snapshot, error)
  func LoadFiles(ctx context.Context, policyDir, dataPath string, epoch uint64) (*Snapshot, error)

  type Store struct { /* atomic.Pointer[Snapshot]; policyDir, dataPath; mu serializes reloads only */ }
  func NewStore(ctx context.Context, policyDir, dataPath string) (*Store, error)   // loads epoch 1
  func (s *Store) Current() *Snapshot                                              // atomic load, lock-free
  func (s *Store) Reload(ctx context.Context) (*Snapshot, error)                   // from files; epoch+1 on success; old stays on error
  func (s *Store) ReplaceData(ctx context.Context, dataJSON []byte) (*Snapshot, error) // validate+build → write dataPath (tmp+rename) → swap
  func (s *Store) PolicyDir() string
  var ErrCompile = errors.New("policy: compile failed")
  var ErrData    = errors.New("policy: invalid data")
  ```
- Consumes: `masking.Compile` (Task 4).

- [ ] **Step 1:** Tests: `TestLoad_BuildsQuery` (loads `../../policies` + `../../policies/testdata/data.json`, evals `k-glob` tool input `kubernetes_get_pods`, gets `ai.tool.allow`); `TestLoad_BadRegoReturnsErrCompile` (temp dir with a syntax error → `errors.Is(err, ErrCompile)`); `TestLoad_StrictDataRejectsUnknownTopLevelKey` (`{"bogus":1}` → `errors.Is(err, ErrData)`); `TestLoad_CompilesMaskers` (`Maskers["k-glob"]` len 2); `TestStore_ReloadIncrementsEpoch`; `TestStore_ReloadKeepsOldOnError` (write broken data file, reload errors, `Current().Epoch` unchanged); `TestStore_ReloadDoesNotBlockCurrent` (100 goroutines spinning on `Current()` while `Reload` runs 10× under `-race`); `TestStore_ReplaceData_WritesFileAtomically` (file content equals input; no `*.tmp` left).
- [ ] **Step 2:** `go test ./internal/policy` → FAIL (not implemented).
- [ ] **Step 3:** Implement. `Load`: `rego.New(rego.Query("data.gateway.authz.decision"), rego.Load([]string{policyDir}, nil), rego.Store(inmem.NewFromObject(data)), rego.StrictBuiltinErrors(true)).PrepareForEval(ctx)`. `rego.Load` must skip `*_test.rego` (use a filter func). Strict data decode: allowed top-level keys `config, teams, agents, blocked_patterns, domains, _comment`. Build `Maskers` from `agents[*].masking` via `masking.Compile`.
- [ ] **Step 4:** `go test -race ./internal/policy` → PASS.
- [ ] **Step 5:** Commit `feat(policy): snapshot loader and lock-free atomic store with reload`.

---

### Task 4: `internal/masking`

**Files:**
- Create: `internal/masking/masking.go`, `internal/masking/masking_test.go`

**Interfaces:**
- Produces:
  ```go
  type Spec struct { Pattern string `json:"pattern"`; Transform string `json:"transform"`; Scope string `json:"scope"` } // scope: "args" | "response" | "" (= both)
  type Rule struct { Re *regexp.Regexp; Transform string; Scope string }
  func Compile(specs []Spec) ([]Rule, error)   // error on bad regex or transform ∉ {redact,mask,hash}
  func Apply(rules []Rule, scope string, v any) (out any, changed bool)  // deep-copies; walks map[string]any / []any / string; non-strings untouched
  ```

- [ ] **Step 1:** Tests with exact values: `TestApply_Redact` (`"token sk-abc123"` → `"token [REDACTED]"`); `TestApply_Mask` (`"nick@example.com"` → `"ni************om"`, and `"abc"` → `"***"`); `TestApply_Hash` (`"sk-abc"` → `"sha256:" + hex(sha256("sk-abc"))[:16]`, computed in test); `TestApply_Nested` (`map[string]any{"a":[]any{"sk-x", 42, map[string]any{"b":"sk-y"}}}` → both strings transformed, `42` untouched, `changed==true`, input not mutated); `TestApply_ScopeFilter` (rule scope `response` not applied when scope `args`; scope `""` applied to both); `TestCompile_BadRegexErrors`; `TestCompile_BadTransformErrors`; `TestApply_NoRulesReturnsSameChangedFalse`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Transforms via `Re.ReplaceAllStringFunc`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(masking): regex rules with redact/mask/hash transforms`.

---

### Task 5: `internal/engine` — Decide with cache, singleflight, timeout, metrics

**Files:**
- Create: `internal/engine/engine.go`, `internal/engine/input.go`, `internal/engine/metrics.go`, `internal/engine/engine_test.go`, `internal/engine/bench_test.go`

**Interfaces:**
- Produces:
  ```go
  type Input struct {
      Stage    string         `json:"stage"`
      KeyID    string         `json:"key_id"`
      Action   string         `json:"action,omitempty"`
      Resource string         `json:"resource,omitempty"`
      Model    string         `json:"model,omitempty"`
      Prompt   string         `json:"prompt,omitempty"`
      ToolCall string         `json:"tool_call,omitempty"`
      Args     map[string]any `json:"args,omitempty"`
      Context  map[string]any `json:"context,omitempty"`
  }
  type Decision struct {
      Decision   string         `json:"decision"`
      RuleID     string         `json:"rule_id"`
      Reason     string         `json:"reason"`
      MaskedArgs map[string]any `json:"masked_args"`   // null when no change
      Epoch      uint64         `json:"epoch"`
      Cached     bool           `json:"cached"`
      LatencyUS  int64          `json:"-"`
  }
  type Options struct { CacheSize int; EvalTimeout time.Duration }   // defaults 10000, 10ms
  type Sink interface { Emit(audit.Event) }                          // Task 6
  func New(store *policy.Store, sink Sink, opts Options) (*Engine, error)
  func (e *Engine) Decide(ctx context.Context, in Input) Decision    // never returns error; failures → deny with internal.* rule_id
  func cacheKey(epoch uint64, in Input) [32]byte                     // sha256(epoch ‖ json.Marshal(in)); json sorts map keys
  ```
- Prometheus metrics on `prometheus.DefaultRegisterer`: `cerberus_decisions_total{stage,decision,rule_id}`, `cerberus_cache_hits_total`, `cerberus_cache_misses_total`, `cerberus_eval_duration_seconds` (histogram), `cerberus_eval_timeouts_total`, `cerberus_policy_epoch` (gauge).
- Consumes: `policy.Store.Current()`, `masking.Apply(snap.Maskers[in.KeyID], "args", in.Args)`, `audit.Event` (Task 6). `audit.Event.Subject` = `Model` for `llm`, `ToolCall` for `tool`, else `Action`.

- [ ] **Step 1:** Tests using `policy.NewStore(ctx, "../../policies", "../../policies/testdata/data.json")` and a recording `Sink`: `TestDecide_AllowFromRego`; `TestDecide_DenyRestricted`; `TestDecide_MasksArgs` (`k-glob` tool `kubernetes_exec` with `args:{"cmd":"use sk-abc and nick@example.com"}` → `MaskedArgs["cmd"] == "use [REDACTED] and ni************om"`); `TestDecide_NoMaskingYieldsNil` (`k-open` → `MaskedArgs == nil`); `TestDecide_SecondCallCached` (`Cached` false then true); `TestDecide_EpochInvalidatesCache` (reload store → next call `Cached==false`, `Epoch` incremented); `TestDecide_Singleflight` (100 goroutines same input → cache misses counter delta == 1); `TestDecide_TimeoutDenies` (`EvalTimeout: 1ns` → `rule_id=="internal.timeout"`, `decision=="deny"`); `TestDecide_UnknownStageDenied`; `TestDecide_EmitsAudit` (sink got 1 event with matching `RuleID` and `Subject`).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement: `snap := store.Current()`; key; `lru.Get` hit → copy with `Cached=true`, emit audit, return; miss → `singleflight.Do(hex(key), func() { ctx, cancel := context.WithTimeout(ctx, opts.EvalTimeout); rs, err := snap.Query.Eval(ctx, rego.EvalInput(in)) ... })`; map `rs[0].Expressions[0].Value` (`map[string]any`) to `Decision`; on `context.DeadlineExceeded` → deny `internal.timeout`; on other error / empty result → deny `internal.eval_error` (slog). Masking after eval, before cache insert (cache stores the masked result). Add `// ponytail: json.Marshal for cache key — hand-rolled hasher only if bench shows it dominating`.
- [ ] **Step 4:** `bench_test.go`: `BenchmarkDecide_Hit` and `BenchmarkDecide_Miss` (unique `ToolCall` per iteration) with `b.RunParallel` (set `b.SetParallelism` so 8 goroutines), record per-op latencies into a slice, report p99 via `b.ReportMetric(p99ns, "p99-ns")`. Companion `TestDecide_P99Targets` (runs only when env `CERBERUS_BENCH_ASSERT=1`) runs 8 goroutines × 10k and asserts hit p99 < 100µs, miss p99 < 1ms.
- [ ] **Step 5:** `go test -race ./internal/engine && make bench` → PASS, p99 printed.
- [ ] **Step 6:** Commit `feat(engine): decide with lru cache, singleflight, eval timeout, masking, metrics`.

---

### Task 6: `internal/audit` — async batcher → SQLite, ring buffer, subscribe

**Files:**
- Create: `internal/audit/event.go`, `internal/audit/logger.go`, `internal/audit/sqlite.go`, `internal/audit/ring.go`, `internal/audit/logger_test.go`

**Interfaces:**
- Produces:
  ```go
  type Event struct {
      ID        int64          `json:"id"`           // set by DB
      Time      time.Time      `json:"time"`
      Stage     string         `json:"stage"`
      KeyID     string         `json:"key_id"`
      Subject   string         `json:"subject"`      // model | tool_call | action
      Decision  string         `json:"decision"`
      RuleID    string         `json:"rule_id"`
      Reason    string         `json:"reason"`
      Epoch     uint64         `json:"epoch"`
      Cached    bool           `json:"cached"`
      LatencyUS int64          `json:"latency_us"`
      Args      map[string]any `json:"args,omitempty"`   // masked args only, never raw
  }
  type Options struct { ChanSize int; BatchSize int; FlushEvery time.Duration; RingSize int } // defaults 4096, 256, 200ms, 1000
  func Open(ctx context.Context, dbPath string, opts Options) (*Logger, error)   // modernc sqlite; PRAGMA journal_mode=WAL; create table+indexes; start run()
  func (l *Logger) Emit(ev Event)                                 // non-blocking; drop + counter when full
  func (l *Logger) Recent(n int) []Event                          // from ring buffer, newest first
  func (l *Logger) Subscribe() (ch <-chan Event, cancel func())   // buffered 64; slow subscriber drops
  type Filter struct { KeyID, Stage, Decision, RuleID string; Since time.Time; Limit int }   // Limit default 100, max 1000
  func (l *Logger) Query(ctx context.Context, f Filter) ([]Event, error)   // newest first
  func (l *Logger) Close() error                                  // flush then close
  var Dropped = promauto.NewCounter(prometheus.CounterOpts{Name: "cerberus_audit_dropped_total"})
  ```

- [ ] **Step 1:** Tests (`t.TempDir()` DB): `TestLogger_EmitFlushQuery` (emit 1000, `Close`, reopen, `Query{Limit:1000}` len==1000); `TestLogger_FullChannelDrops` (`ChanSize:1`, `FlushEvery: time.Hour`, `BatchSize: 1000`, emit 100 — completes within 100ms; `Dropped` delta > 0); `TestLogger_RingRecent` (`RingSize:3`, emit 5, `Recent(10)` == last 3 newest-first); `TestLogger_SubscribeReceives` (subscribe, emit, receive within 1s; cancel closes); `TestLogger_QueryFilters` (by `RuleID` and by `Since`).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement. Table `events(id INTEGER PRIMARY KEY, time INTEGER, stage TEXT, key_id TEXT, subject TEXT, decision TEXT, rule_id TEXT, reason TEXT, epoch INTEGER, cached INTEGER, latency_us INTEGER, args TEXT)`; indexes `(time)` and `(key_id, time)`. Single `run()` goroutine owns writes; one transaction per batch. Ring + subscribers updated in `Emit` path (mutex OK there — not the decision hot path, `Emit` is a channel send). Add `// ponytail: no retention/vacuum — daily DELETE older than N days when the DB grows past concern`.
- [ ] **Step 4:** `go test -race ./internal/audit` → PASS.
- [ ] **Step 5:** Commit `feat(audit): async sqlite batcher with ring buffer and subscriptions`.

---

### Task 7: `internal/server` — HTTP API, admin auth, SSE

**Files:**
- Create: `internal/server/server.go`, `internal/server/decide.go`, `internal/server/admin.go`, `internal/server/events.go`, `internal/server/middleware.go`, `internal/server/server_test.go`, `internal/server/testdata/decide_allow.golden.json`, `internal/server/testdata/decide_deny.golden.json`

**Interfaces:**
- Produces:
  ```go
  type Deps struct { Engine *engine.Engine; Store *policy.Store; Audit *audit.Logger; AdminToken string; Version string }
  func New(d Deps) http.Handler
  ```
- Routes:

  | Method/Path | Auth | Behavior |
  |---|---|---|
  | `POST /v1/decide` | none | body = `engine.Input` → `engine.Decision` JSON 200 |
  | `POST /v1/decide/llm`, `POST /v1/decide/tool` | none | same, forces `stage` |
  | `GET /healthz` | none | `200 ok` |
  | `GET /readyz` | none | 200 if `Store.Current() != nil` else 503 |
  | `GET /metrics` | none | `promhttp.Handler()` |
  | `GET /v1/admin/data` | bearer | current data JSON (`Snapshot.Data`) + header `X-Cerberus-Epoch` |
  | `PUT /v1/admin/data` | bearer | `Store.ReplaceData`; 200 `{"epoch":N}`; 422 `{"error":...}` on validation/compile failure |
  | `POST /v1/admin/reload` | bearer | `Store.Reload`; same responses |
  | `POST /v1/admin/policy/validate` | bearer | body `{"rego":"..."}` → `ast.ParseModule` + `ast.NewCompiler().Compile` with current modules from `Store.PolicyDir()`; 200 `{"ok":true}` or 422 `{"ok":false,"errors":[...]}` |
  | `GET /v1/audit?key_id=&stage=&decision=&rule_id=&since=<RFC3339>&limit=` | bearer | `Audit.Query` → `[]audit.Event` |
  | `GET /v1/events` | bearer | SSE: replay `Recent(50)` then live `Subscribe()`; frames `event: decision\ndata: <Event JSON>\n\n`; `: ping` comment every 15s |

- Middleware: `http.MaxBytesReader(1<<20)`, `Content-Type: application/json` enforced on POST/PUT (415 otherwise), request-id + slog access log, panic recovery → 500, admin bearer via `crypto/subtle.ConstantTimeCompare`.
- Errors: `{"error":"<msg>"}`; 400 invalid json, 401 missing/bad token, 413 body too large, 415 wrong content-type, 422 validation, 503 not ready.

- [ ] **Step 1:** Tests with `httptest.NewServer(New(deps))` on fixture store + `t.TempDir()` audit DB: `TestDecide_AllowGolden` / `TestDecide_DenyGolden` (compare body to golden ignoring `epoch`); `TestDecide_LLMAliasForcesStage` (`/v1/decide/llm` with no `stage` in body → llm rule_id); `TestDecide_InvalidJSON400`; `TestDecide_BodyTooLarge413`; `TestDecide_WrongContentType415`; `TestAdmin_NoToken401`; `TestAdmin_PutData_ReloadsEpoch` (GET epoch N → PUT modified data → GET epoch N+1 and next decide reflects change); `TestAdmin_PutData_InvalidKeeps422` (unknown top-level key → 422, epoch unchanged); `TestAdmin_PolicyValidate_BadRego422`; `TestAdmin_PolicyValidate_GoodRego200`; `TestAudit_QueryReturnsDecision`; `TestEvents_SSEStreamsDecision` (open stream, make a decide call, read one `event: decision` frame within 2s); `TestReadyz`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement per table. SSE uses `http.NewResponseController(w).Flush()` per frame; exits on `r.Context().Done()`.
- [ ] **Step 4:** `go test -race ./internal/server` → PASS.
- [ ] **Step 5:** Commit `feat(server): decide, admin data/reload/validate, audit query, sse events`.

---

### Task 8: `cmd/cerberus` wiring, config, Dockerfile, smoke, GUIDE

**Files:**
- Create: `internal/config/config.go`, `internal/config/config_test.go`, `deploy/Dockerfile`, `deploy/docker-compose.yml`, `scripts/smoke.sh`, `docs/GUIDE.md`
- Modify: `cmd/cerberus/main.go`, `Makefile` (`smoke`), `README.md` (Status → "Phase 1 implemented", quickstart)

**Interfaces:**
- ```go
  type Config struct { Addr, PolicyDir, DataFile, AuditDB, AdminToken, LogLevel string; CacheSize int; EvalTimeout time.Duration }
  func Load(args []string, getenv func(string) string) (Config, error)
  ```
  Env (flag overrides with same name lower-kebab): `CERBERUS_ADDR` (`:8089`), `CERBERUS_POLICY_DIR` (`policies`), `CERBERUS_DATA_FILE` (`data/prod.json`), `CERBERUS_AUDIT_DB` (`cerberus.db`), `CERBERUS_ADMIN_TOKEN` (required → error if empty), `CERBERUS_CACHE_SIZE` (10000), `CERBERUS_EVAL_TIMEOUT` (`10ms`), `CERBERUS_LOG_LEVEL` (`info`).
- `main`: config → store → audit → engine → server; `http.Server{ReadHeaderTimeout: 5s}`; `signal.NotifyContext` SIGINT/SIGTERM → `Shutdown(10s)` then `audit.Close()`; SIGHUP → `Store.Reload` (log result).

- [ ] **Step 1:** `config_test.go`: `TestLoad_RequiresAdminToken`, `TestLoad_Defaults`, `TestLoad_ParsesTimeout`, `TestLoad_FlagOverridesEnv`.
- [ ] **Step 2:** Run → FAIL; implement; PASS.
- [ ] **Step 3:** `main.go` wiring as above. `make build` OK.
- [ ] **Step 4:** `scripts/smoke.sh` (`set -euo pipefail`): start `bin/cerberus` with `CERBERUS_DATA_FILE=policies/testdata/data.json`, `CERBERUS_ADMIN_TOKEN=smoke`, temp audit DB, free port; wait for `/readyz` (max 5s); curl + `grep -q`: tool allow (`k-glob`/`kubernetes_get_pods` → `"ai.tool.allow"`), tool deny (`kubernetes_delete_pod` → `"ai.tool.restricted"`), masked (`args.cmd` contains `sk-abc` → response contains `[REDACTED]`), admin without token → `401`, PUT data with token → `"epoch":2`, `kill -HUP` → GET data header epoch `3`, `/metrics` contains `cerberus_decisions_total`; `trap` kills binary. `make smoke` runs it.
- [ ] **Step 5:** `deploy/Dockerfile`: `golang:1.24-alpine` build (`CGO_ENABLED=0`) → `gcr.io/distroless/static:nonroot`; copy `bin/cerberus`, `policies/`, `data/`; `EXPOSE 8089`; `USER nonroot`; `ENTRYPOINT ["/cerberus"]`. `deploy/docker-compose.yml`: service `cerberus` with env, volumes `./data:/data`, `cerberus-db:/var/lib/cerberus`. `docker build -f deploy/Dockerfile .` succeeds.
- [ ] **Step 6:** `docs/GUIDE.md`: quickstart (`make build`, env, run), the curl examples from smoke, LiteLLM pre-call hook snippet (Python `CustomLogger.async_pre_call_hook` → `POST /v1/decide/llm`, raise on deny), agent tool pre-exec snippet (`POST /v1/decide/tool`, replace args with `masked_args` when non-null), data schema cheatsheet, how to add a stage (3 touches), ops (`/metrics` names, SIGHUP, backup `cerberus.db`).
- [ ] **Step 7:** `make lint test opa-check opa-test smoke` → all PASS.
- [ ] **Step 8:** Commit `feat(cmd): wire engine binary with config, graceful shutdown, dockerfile, smoke, guide`. Tag `v0.1.0`.

---

## Self-review notes

- Spec coverage: README concepts 1–6 → Tasks 2–7; concept 7 (dashboard) → Phase 2; concept 8 (SDK) → Phase 3. ADR-0001 §1–7 → Tasks 3,5,6,7,8 (gRPC deferred to Phase 3; `sync.Pool` JSON buffers deferred until bench says so). ADR-0002 input contract → `engine.Input`; stage dispatch → Task 2; `domains` section accepted by strict decoder (Task 3), unused until Phase 4.
- Type consistency: `engine.Input/Decision`, `audit.Event`, `policy.Snapshot/Store`, `masking.Rule/Apply` referenced identically across Tasks 3–8.
- Budget: `spend_usd` is caller-supplied in `context`; engine does no spend accounting (YAGNI — LiteLLM already tracks spend).

## Verification (end of Phase 1)

```
make lint && make test && make opa-check && make opa-test && make bench && make smoke
docker build -f deploy/Dockerfile -t cerberus:dev .
```

All green + bench p99 under targets = Phase 1 done. Then write `docs/superpowers/plans/<date>-phase2-owl-dashboard.md`.
