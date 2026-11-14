# CHANGELOG-AUDIT — Cerberus Security & Quality Ledger
> Ledger auditable: SEMUA temuan (finding) + perbaikan (improvement) dicatat di file ini sejak 11 Nov 2026.
> Format entri: ID · tanggal · sumber (auditor/red-team/monte-carlo/owner) · severity · status (OPEN/FIXED/ACCEPTED) · commit fix · bukti verify.
> File ini TIDAK boleh dihapus/di-rewrite — hanya append. Satu sumber kebenaran "apa yang pernah ditemukan & apa yang sudah ditutup".

## Format
```
| ID | Tanggal | Sumber | Severity | Temuan | Status | Fix commit | Bukti |
```

## Ledger

### 2026-11-14 (Batch U Owl UX — breach center + explorer)
- U [DONE] GET /v1/audit/breaches server-side (3-tier severity, top offenders) + halaman /breaches Owl + severity map + detail per-agent; U7 Policy Explorer read-only: GET /v1/policy/modules + POST /v1/policy/test-run (282 test runnable dari dashboard); fix U1 audit-args-NULL. Gate: make test hijau penuh, opa 282/282, lint 0, vitest 55/55, build 21 pages. (AGY Flash build, Hermes verify mandiri)


### 2026-11-14 (Monte Carlo run-1 — 45.000 sampel, seed 20261114, engine terisolasi :18089)
- MC-R1 [P0] **FIXED** (5 iterasi, 14 Nov): 12.353 → 3.534 (MC-P0 `45ec079`: SSRF link-local deny + taint-tracking chain.tainted_exfil + authz.unknown_key fail-closed + ai.llm oversized/unscanned) → 589 (MC-P1 `b32176a`: shellguard fail-closed arg-key + docker inspect protected + ssh staged-script + db COPY-TO file-drop + IP-normalize + unicode strip; oracle chain_broken semantics) → 588 palingsifalse-OP02 (MC-P2 `32cabe0`: messages[] prod-scan + runner session_id isolasi taint) → **0 ESCAPE (MC-P3 `977210a`: shield.protected_path enforcement — protected_paths data dulu dead; fixture OP02 autentik)**. Bukti final: mc-report-5.json 45.000 sampel, 0 escape, 0 flaky, p_ub99 0,0001, `[PASS] MONTE CARLO COVERAGE VERIFIED`. OPA 257→282/282 (+25 regression). Loop run→fix→test→rerun tuntas 5 putaran.
- MC-R1 [INFO] PASS: 7 stage individual (tool/llm/http/db/k8s/docker/ssh × 5.000) = 0 escape, 0 flaky, p_ub99 0,000921 — parser/matcher/unicode/encoding tertahan. TPS 4.067, p99 13ms.
- MC-R1 [INFO] PASS: flaky-detect 3-cara (idempotency burst, JSON permutation, cache-vs-explain) = 0 flaky verdict.
- Harness: cmd/cerberus-montecarlo committed (branch wt/montecarlo); catalog docs/qa/MONTE-CARLO.md; guardrail isolasi diverified (loopback-only, tanpa docker.sock/upstream LLM/egress nyata).


### 2026-11-14 (gate pasca-merge R+H+S+M)
- QA-FLAKE-1 FIXED: `internal/policy` race test hang (604s lokal / 15m32s CI `fe1afc8`) — akar: `ComputeCoverage` menjalankan suite rego 247-test in-process di dalam `LoadBundle` dry-run gate; test rollback memanggil 3× (≈6 full-suite) → di CI 2-core + `-race` panic timeout 25m. Fix: (1) `CERBERUS_SKIP_POLICY_SUITE=1` env guard di `ComputeCoverage` (skip Load+RunTests, smoke tetap), (2) `Makefile test:` pakai flag + target `test-full` baru, (3) 5 test gate (RedSuiteRejected, CoverageDropGate, Coverage×3) dipaksa suite-ON via `t.Setenv` (non-paralel) — kontrak gate tetap teruji. Bukti: `internal/policy` race hijau 203.9s dengan flag (dulu timeout 604s); `make opa-test` tetap penjaga suite 247/247. Fix commit: lihat commit F3-fix batch ini.
- MERGE-REG-1: wt/hardening membawa balik substring-match + bug scope di authz.rego → ditangkap saat merge, FIXED `39bd060` (sudah dicatat di atas, redundansi disengaja utk lintas-referensi ledger-vs-commit)

### 2026-11-13 (audit 5-domain deleg_8c9be9c2 + 5-auditor round-2, 94 temuan)
- Batch A P0/P1 (token hard-coded, tar-slip, zip-bomb, deadlock, rate-limit) → FIXED `390b9f1` — verify: rotasi token live, /v1/status 401 tanpa token
- Batch B P2 (rollback restore, cluster epoch, /v1/query builtin-block, err-leak) → FIXED `8aa9f9b` — verify: live probe per item
- Batch C (tool-gate non-SSE, shellguard Assigns, tap admin fail-closed, proxy auth) → FIXED `92cd819` — verify: tap /tap/turns 401, egress host:http ditolak

### 2026-11-13/14 (red-team Opus 25 + Argon 17 = 42 temuan, 10 P0)
- RT-P0-1 key_id impersonasi via body (Opus) → FIXED `5d626a8` (batch R) — X-Agent-Key sha256 constant-time; verify: grep decide.go + test
- RT-P0-2 substring allowlist bypass (Opus) → FIXED `5d626a8` — exact/glob/endswith; verify: opa-test 247/247
- RT-P0-3 bundle package-merge guard (Opus) → FIXED `5d626a8` — ast.ParseModule; verify: test bundle signed+alien package reject
- RT-P0-4 tap >2MB fail-closed (Opus) → FIXED `5d626a8` — maxBody const + head/tail marker; verify: unit test
- RT-P0-5 unix-socket auto-admin (Argon) → FIXED `5d626a8` — CERBERUS_TRUST_UNIX_SOCKET opt-in; verify: break_glass.go:99
- RT-P0-6 smoke key vakum (Argon) → FIXED `5d626a8` — k-smoke-fixture terdaftar; verify: smoke.go
- RT-P0-7 rollback tulis data-merah + PG overwrite (Argon) → FIXED `5d626a8` — raw di revisions utk rollback, LIST endpoint key-redact (mandor patch); verify: test rollback+revisions
- RT-P0-8 SSE input di start-event tak diverifikasi (Opus) → FIXED `39bd060` (batch H) — startInput verify + reconstruct; verify: main.go:658-731 + test
- RT-P0-9 redirect 3xx host baru tanpa re-eval (Opus) → FIXED `39bd060` — ErrUseLastResponse + maxRedirects 5 + decide per-hop; verify: egress.go:425-483 + test 302→deny
- RT-P0-10 (klaim) LLM full-scan 4000 char → FIXED `39bd060` — capConversation 64KB head+tail marker (H3 versi baru)

### 2026-11-14 (batch R merge fix mandor)
- R7 follow-up: listRevisions bocor api_key di output JSON (test TestRules_RollbackRestoresRawSecret) → FIXED `5d626a8` — redactSecretKeys (key-aware) + masking.Apply; verify: test hijau + grep output [REDACTED]

### 2026-11-14 (merge H conflict resolution)
- wt/hardening authz.rego membawa kembali substring-match non-glob (regresi RT-P0-2) + bug scope name/target → DITANGKAP SAAT MERGE, FIXED `39bd060` — exact/prefix + normalize(); verify: opa 188/188 (kini 247/247 pasca-S)

### 2026-11-14 (Opus adversarial analysis — prior utk monte carlo)
- Prior dari 9 temuan riil: parser/matcher semantics 55%, boundary/state 30%, crypto 15% (0 kegagalan)
- 15 skenario kandidat OPEN (belum diuji, menunggu harness MC): chaining docker-write+db, http→llm masking response, race budget, glob ** mismatch, unicode homoglyph args, dialect stored-proc, configmap policy override, tap hold-verify TOCTOU, 2MB truncation parse, rate-limit key-rotate, redirect suffix, kill-switch race, PG mirror divergence silent, bundle pin v1, gossip TTL window
- 5 kelas tak-layak-simulasi (managed by process, bukan test): social engineering, insider bundle, host opsec kompromi, policy buy-off organisasi, LLM persuasion human

### 2026-11-14 (Argon gap-analysis Owl UX — batch U input)
- U-GAP-1 KRITIS: audit args NULL saat deny tanpa masking (engine.go auditArgsFor pakai d.MaskedArgs nil) → OPEN → fix di batch U1
- U-GAP-2: severity per rule_id belum ada → OPEN → U2 (map TS)
- U-GAP-3: agregat /agents client-side limit 1000 salah hitung → OPEN → U3 agents-summary
- U-GAP-4: kuota harian/budget tak terekspos → OPEN → U3
- U-GAP-5: kill_switch tanpa metadata (waktu/alasan/event pemicu) → OPEN (fase L)
- U-GAP-6: filter Stage Owl cuma llm/tool → OPEN → U6
