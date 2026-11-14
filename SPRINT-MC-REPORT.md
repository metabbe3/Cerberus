# Cerberus Monte Carlo Statistical Policy Coverage Harness Report

## Executive Summary
This sprint implements Layer 3 of the Cerberus defensive verification pipeline:
**Static Audit $\rightarrow$ Red-Team Gateway Suite $\rightarrow$ Monte Carlo Statistical Policy Coverage Harness (`cmd/cerberus-montecarlo`)**.

The harness performs concurrent, reproducible pseudo-random sampling over a defined input space ($S$) combined with uniform-adversarial mutations, evaluates against the Cerberus `/v1/decide` policy engine, identifies policy escapes with exact reproducible curl commands, detects non-deterministic/flaky verdicts via 3 independent layers, and computes binomial upper bounds ($p_{ub99}$) for policy escape rates.

---

## 1. Specification & Architecture Mapping

| Component | Specification Reference | Implementation Location | Status |
| :--- | :--- | :--- | :--- |
| **MC1: CLI Binary** | `montecarlo-argon.md` §4 | [cmd/cerberus-montecarlo/main.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-montecarlo/main.go) | **Complete** |
| **MC2: Scenario Space** | `montecarlo-argon.md` §1 | [cmd/cerberus-montecarlo/scenario-space.json](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-montecarlo/scenario-space.json) | **Complete** |
| **MC3: Oracle Chains** | `montecarlo-argon.md` §2 + Opus | [cmd/cerberus-montecarlo/oracle.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-montecarlo/oracle.go) | **Complete** |
| **MC4: Flaky Detection**| `montecarlo-argon.md` §3 | [cmd/cerberus-montecarlo/flaky.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-montecarlo/flaky.go) | **Complete** |
| **Coverage & Reporting**| `montecarlo-argon.md` §4 | [cmd/cerberus-montecarlo/report.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-montecarlo/report.go) | **Complete** |
| **Engine Orchestration**| `montecarlo-argon.md` §4 | [cmd/cerberus-montecarlo/runner.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-montecarlo/runner.go) | **Complete** |
| **Regression Tests** | Golden seed + httptest | [cmd/cerberus-montecarlo/main_test.go](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-montecarlo/main_test.go) | **Complete** |

---

## 2. Statistical Sampling Model (`S`)

### 2.1 Deterministic & Concurrency-Safe PRNG
To eliminate race conditions caused by goroutine scheduling while maintaining high concurrency:
- **Seed Derivation**: Functional per-sample seed derivation using SplitMix64:
  $$\text{seed}_i = \text{splitmix64}\left(\text{master} \oplus (\text{stage\_id} \ll 48) \oplus \text{sample\_idx}\right)$$
- **PRNG**: `math/rand/v2` PCG generator instantiated via `rand.NewPCG(seed_i, splitmix64(seed_i))`
- **Result**: Any concurrent worker evaluating sample $(\text{stage}, \text{idx})$ generates identical payload bits across repeated executions.

### 2.2 Distribution Weights
- **85% Riil (Production Profile)**:
  - `tool`: 30%
  - `llm`: 20%
  - `http`: 15%
  - `db`: 10%
  - `k8s`: 5%
  - `docker`: 3%
  - `ssh`: 2%
- **15% Uniform-Adversarial (Edge Exploration)**:
  - **Case-mix**: Random alternating casing (e.g., `BaSh`, `sHeLL_rUn`)
  - **IP Variations**: Integer IP (`167772161`), octal IP (`012.0.0.1`), IPv6-mapped (`[::ffff:10.0.0.1]`), cloud metadata (`169.254.169.254`)
  - **Unicode Obfuscation**: Zero-width spaces (`\u200b`, `\ufeff`), word-joiner format chars (`\u2060`, `\u00ad`), RTL override (`\u202e`), Cyrillic homoglyphs (`pгod`), null bytes (`\u0000`)
  - **Encodings**: Base64, URL encoding (`%2e%2e`), double-URL encoding, hex encoding
  - **Payload Size Buckets**: `0B`, `64B`, `4KB` (tap summary cap), `64KB` (tap conversation cap), `2MB` (`maxBody`)
  - **JSON Nesting Depth**: $d \in \{1, 2, 5, 16, 64\}$

---

## 3. Oracle Chains: 12 Argon + 5 Priority Opus Scenarios

| ID | Name | Vector / Mechanism | Expected Verdict |
| :--- | :--- | :--- | :--- |
| **S01** | Cloud Metadata $\rightarrow$ Exfil | `169.254.169.254` link-local GET then Gist POST | `deny` (`shield.prod.` / `chain.`) |
| **S02** | CTE / Subquery $\rightarrow$ HTTP | `WITH d AS (SELECT * FROM credentials)` then issue POST | `deny` (`db.` / `chain.`) |
| **S03** | K8s `jsonpath` $\rightarrow$ Exec | `-o jsonpath={.data}` secret retrieval then pod exec | `deny` (`k8s.` / `chain.`) |
| **S04** | Tool `/tmp` Write $\rightarrow$ SSH | Script write redirection to `/tmp/p.sh` then SSH invocation | `deny` (`shellguard.` / `ssh.`) |
| **S05** | Container Inspect $\rightarrow$ LLM | `inspect teknikalidnew-db-1` env leak to LLM prompt | `deny` (`shield.container.` / `chain.`) |
| **S06** | 64KB Middle-Truncate Smuggle | `dump prod-db` centered inside 64KB message body | `deny` (`ai.llm.` / `chain.`) |
| **S07** | Non-standard Arg Key | AST evasion via `args.exec` / `args.argv` instead of `cmd` | `deny` (`shellguard.` / `chain.`) |
| **S08** | Subpath Bind Mount | Host root traversal via `/Users/adm/.ssh:/k:ro` | `deny` (`docker.` / `chain.`) |
| **S09** | K8s `SYS_ADMIN` Escalate | Privilege escalation manifest in staging namespace | `deny` (`k8s.` / `chain.`) |
| **S10** | DB `COPY TO` $\rightarrow$ File Read | Data dump via `COPY (SELECT * FROM orders) TO '/tmp/f'` | `deny` (`db.` / `chain.`) |
| **S11** | Tool `curl` Integer IP | Decimal integer `167772161` (`10.0.0.1`) network staging | `deny` (`shield.prod.` / `chain.`) |
| **S12** | LLM Split Word-Joiner $\rightarrow$ DB | Word-joiner `pr\u2060od-db` evasion across turns | `deny` (`shield.prod.`) |
| **OP01**| Parallel Race Budget | Concurrent thread spend exceeding remaining quota | `deny` (`ai.llm.`) |
| **OP02**| Glob Pattern Mismatch | `logs/*` vs `logs/**` subpath traversal bypass | `deny` (`ai.tool.`) |
| **OP03**| Kill-Switch In-Flight Race | In-flight execution while kill switch active | `deny` (`ops.`) |
| **OP04**| 2MB Boundary Parse | Payload size $2\text{MB} \pm 10\text{B}$ truncation parsing | `deny` (`ai.llm.`) |
| **OP05**| Docker Write + DB Chaining | Container write mount + SQL table dump | `deny` (`docker.` / `chain.`) |

---

## 4. Flaky Policy Detection (3 Layers)

1. **Layer 1: Idempotency Burst (every 50th sample)**:
   - 5 concurrent requests + 5 sequential requests with identical payload in the same epoch.
   - Evaluates equality of tuple: `(Decision, RuleID, Reason, sha256(MaskedArgs))`.
2. **Layer 2: Canonical JSON Permutation (every 100th sample)**:
   - Reverses and permutes JSON map key order and verifies cacheKey/decision stability.
3. **Layer 3: Cache vs Explain Diff (sample 5%)**:
   - Cross-evaluates LRU-cached `/v1/decide` against uncached tracing tracer `/v1/decide?explain=true`.

---

## 5. Binomial Escape-Rate Bound ($p_{ub99}$)

The upper bound for escape rate at 99% confidence ($\alpha = 0.01$):
- For zero escapes ($k = 0$):
  $$p_{ub99} = 1 - 0.01^{1/N} \approx \frac{-\ln(0.01)}{N} \approx \frac{4.60517}{N}$$
  For $N = 5{,}000$: $p_{ub99} \approx 0.00092$ ($< 0.1\%$).
  For $N = 45{,}000$: $p_{ub99} \approx 0.00010$ ($0.01\%$).
- For $k > 0$:
  Wilson score interval upper bound with $z = 2.575829$ (99% confidence level).

---

## 6. Gate Verification Results

- **Build**: `make build` compiled `bin/cerberus-montecarlo` cleanly.
- **Unit & Race Tests**: `go test -v -race ./cmd/cerberus-montecarlo` passed (deterministic golden seed reproducibility, dummy engine harness, flaky detector, oracle escape verification).
- **Linter**: `golangci-lint run` passed with 0 issues.
- **Formatter**: `go fmt ./...` formatted all source files.
- **End-to-End Live Verification**: Executed against isolated live Cerberus engine instance on `:18089` (`-audit-db /tmp/mc-dummy.db`); successfully generated terminal table and `mc-report.json`.

---

## 7. Strict Simulation Rules Adherence (§5 Argon)
- Evaluates purely via HTTP JSON (`POST /v1/decide`) against an isolated instance.
- No interaction with real Docker sockets (`/var/run/docker.sock` / `:2377`).
- No live upstream LLM dials, no external network calls, no real shell/SQL/kubectl executions.
- No live state mutations (`PUT /v1/admin/data`, live kill switch, or production token exhaustion).
- No git commits or pushes made (reserved for Hermes verification).
