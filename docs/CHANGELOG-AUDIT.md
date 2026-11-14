# CHANGELOG-AUDIT — Cerberus Security & Quality Ledger
> Ledger auditable: SEMUA temuan (finding) + perbaikan (improvement) dicatat di file ini sejak 11 Nov 2026.
> Format entri: ID · tanggal · sumber (auditor/red-team/monte-carlo/owner) · severity · status (OPEN/FIXED/ACCEPTED) · commit fix · bukti verify.
> File ini TIDAK boleh dihapus/di-rewrite — hanya append. Satu sumber kebenaran "apa yang pernah ditemukan & apa yang sudah ditutup".

## Format
```
| ID | Tanggal | Sumber | Severity | Temuan | Status | Fix commit | Bukti |
```

## Ledger

### 2026-11-14 (DEPLOY cerberus.hivepos.id LIVE + CI flake campaign closed)
- DEPLOY [DONE] cerberus.hivepos.id live: engine binary baru (pid 76516, :8089, PG 5433 + audit-db + prod.json kontinu) + Owl U2 di :3006 (standalone, OWL_POLICY_DIR absolut). Smoke: /login / / /overview /breaches /agents /settings = 200 publik; auth-login 401 JSON benar; /v1/audit/breaches 200; /v1/policy/modules 200; /v1/admin/users 200 (user admin DB seed); upstream PUT→GET round-trip key_hint-only (key tak pernah dikembalikan, verifikasi grep=0), test koneksi 186ms, dummy key dibersihkan.
- CI [FIXED] 3 lapis flake berurutan pada 43579569539→43580561064→43581899998: (1) lint 15 temuan fase E/F/G (switch/G115/G301/G124/G101/G704/revive docs) commit 66e1031; (2) TestBreachesAndAgentsSummary + TestLatencyStatsAndFailClosed sleep-vs-async → poll-retry deadline 5s commit 0ce2637+6db9c99; (3) TestAuth_UserManagementAndRoleViewer akar PRODUK: SQLite :memory: = DB per-koneksi, pool koneksi ke-2 = "no such table: events" → openSQLite SetMaxOpenConns(1) khusus :memory: commit 66c58d6. CI 43582978737 FULL SUCCESS.
- README [DONE] sync post-U2 (70c5fef): db/k8s Live (bukan Coming Soon), kuota COUNT bukan USD (#396), +6 endpoint auth/users/breaches/policy/upstream, seksi Bukti Pengujian (MC 0-escape, redteam, 282/282).


### 2026-11-14 (U2 Production-Grade Dashboard — 7 fase, riset Argon+Opus+LiteLLM)
- U2 [DONE] A 58e196f Command Center (safety banner, deny-rate+delta, fail-closed tile, nav 5 pilar) · B 4e854ef Inspector drawer+trace+fingerprint dedup+URL filter · C 98e3eb5 Agents server-side+quota burn+bundle trust trail · D 4b4b175 polish ID formal+empty-states · E 4fd5908 user DB auth (Argon2id, sessions, lockout, RBAC viewer 403, ADR-0005) · F 6026fb3 block-key 1-klik+CSV RFC4180 · G upstream LLM fleksibel (AES-256-GCM store, PUT/test endpoint, tap hot-reload atomic, Owl UpstreamCard) — budget USD dicetak tebal OUT per keputusan positioning #396. Gate: make test hijau (semua pkg), vitest 57/57, build 21+ pages. Item 24 (downstream capture toggle + halaman Turns) → U3. (AGY Flash A-F + Hermes G sendiri)


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

## F4 ACCEPTANCE RUN — 14 Nov 2026 (mandor: Hermes)
- F4-LOAD: engine terisolasi :18089, loadgen 6 level — MAX SUSTAINED 105.800 TPS (p99 1,3ms, err 0%) — naik dari baseline 85k. Status: DONE.
- F4-REDTEAM: 12 serangan vs gerbang live (8089/8088/2377) — 10 BLOCKED / 2 WARN / 0 EXPOSED, exit 0. Status: DONE.
- F4-MC: Monte Carlo 27.000 sampel (7 stage × 3.000 + chains 6.000, seed 20261114) — 0 escape, 0 flaky, p_ub99 0,000171. Status: DONE.
- F4-QUICKSTART: scripts/get.sh live GitHub syntax-verified (321 baris), QUICKSTART.md 270 baris konsisten. Status: DONE.
- F4-PILOT: teknikal-agent via cerberus-tap :8090 key k-tekbot — full-loop terverifikasi (request+response turn terekam tap-DB, ai.llm.allow di audit engine, deny fail-closed terekam kind=blocked). TEMUAN: token admin gate STALE pasca-rotasi #395 → tap strict fail-closed senyap; FIX: compose gate disinkronkan + recreate, verify 200. Status: FIXED (pola: rotasi token WAJIB sentuh ~/cerberus-gate/docker-compose.yml).
- F5: tag v0.1.0 setelah soak 48h + ROADMAP update. Status: OPEN.

## STRESS + RED-TEAM OWNER RUN — 14 Nov 2026 malam (mandor: Hermes)
- STRESS-CONCURRENCY (engine GHCR image terisolasi, loadgen 12 level 1→2048 conn): MAX SUSTAINED **35.822 TPS** (err 0% di semua level); p50 naik 1,4ms→30,2ms, p99 maks 274ms pada 2048 conc. Knee: ~512 conc (21k TPS). Engine native binary sebelumnya (12 Nov): 105,8k TPS single-stage — Docker+bridge = ~1/3 native, masih jauh di atas kebutuhan MVP-60.
- TAP BENCH (reverse proxy LLM penuh: decide+capture+turn-write+forward): **~2.467 TPS** pada 200 conc (p50 16,6ms / p90 77ms) dengan upstream 404-cepat. Path blocked cepat: ~1.138 TPS.
- RED-TEAM MANUAL (11 probe cheat): stage-spoof args docker di tool → masih allow BY DESIGN (stage=tool, args hanya masking; docker exec lewat stage docker yang di-gate) — CATATAN utk docs; k-bad kill-switch → DENY benar; K-OPEN case → deny (timeout policy, fail-closed); unicode homoglyph k-оpen → bypass_unknown_keys=true di testdata (prod: false, tertutup); SQLi PUT data → 422 schema reject; X-Cerberus-Key spoof → docker deny by allowlist; body 11MB/20MB → koneksi diputus (cap 10MiB); CL+TE smuggling → 415; admin no-auth → 401; k-rate 30 burst → semua 200 (k-rate tak ada limit di testdata — CATATAN: default prod k-default-agent ada burst). TIDAK ADA ESKAPE POLICY.
