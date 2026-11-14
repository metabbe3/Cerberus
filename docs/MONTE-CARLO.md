# Monte Carlo Attack-Scenario Catalog — Cerberus

> Standar dokumentasi (owner, 14 Nov): SEMUA skenario monte carlo yang diuji — dan yang TIDAK diuji — wajib tercatat di dokumen ini. Hasil run (`mc-report.json`) dicatat di `docs/CHANGELOG-AUDIT.md`.
>
> Sumber: analisis adversarial Opus (15 skenario + prior) × spesifikasi harness Argon (12 oracle chaining + sampling deterministik). Diuji via `cmd/cerberus-montecarlo`.

## 1. Tujuan & Metode

- **Lapisan QA ke-3**: static audit (94 temuan) → red-team suite (10 serangan live) → **statistical coverage** (ribuan kombinasi per run).
- **Dua lapis**: (a) LLM membangun ruang skenario + prior dari data riil; (b) harness empiris menembak engine TERISOLASI. LLM saja = prior subjektif; engine run = bukti.
- **Target**: escape-rate < 0,1% per stage dengan N=5.000/stage (confidence 99%, zero-failure binomial). k>0 escape → tolak rilis → wajib fix + regression test → rerun.

## 2. Prior dari Data Historis (9 temuan bug nyata)

- ≈55% kebocoran = **parser/matcher semantics** (substring allowlist, body impersonasi, SSE parse, DNS TOCTOU, redirect) → fuzz difokuskan di sini.
- ≈30% = boundary/state bug (unix-socket auto-admin, rollback raw secret, bundle merge).
- ≈15% (0 kegagalan) = **crypto** (ed25519) → tidak diprioritaskan.

## 3. Ruang Sampling (scenario-space.json)

**Weighted 85% profil riil**: tool 30% · llm 20% · http 15% · db 10% · k8s 5% · docker 3% · ssh 2%.
**Uniform-adversarial 15%**: case-mix (`BaSh`), IP integer/oktal (`167772161`, `012.0.0.1`), IPv6-mapped (`[::ffff:10.0.0.1]`), metadata link-local (`169.254.169.254`), unicode (zero-width `\u200b`, format `\u2060`/`\u00ad`, RTL `\u202e`, homoglyph Cyrillic `pгod`, NUL), encoding (base64, URL `%2e%2e`, hex, double-encode), panjang {0B, 64B, 4KB, 64KB, 2MB}, nesting JSON {1,2,5,16,64}.
**Chains**: transition matrix Source {http,db,k8s,docker,tool,llm} × Sink {http,tool,ssh,k8s,db}, 2 aksi per session.
**Seed**: `math/rand/v2` PCG, `seed_i = splitmix64(master ^ stage<<48 ^ idx)` — reproducible konkuren.

## 4. Oracle Chaining S01–S12 (Argon — pasangan A1→A2, expected deny + rule baru)

| ID | Rantai | Celah yang diuji | Expected |
|---|---|---|---|
| S01 | HTTP metadata 169.254.169.254 → HTTP POST exfil | link-local tak ada di shield cidrs; A2 ke host allowlisted | deny `shield.prod.link_local_metadata` + `chain.tainted_exfil` |
| S02 | DB `WITH`-CTE secret → HTTP POST | db.rego hanya cek `^\s*select\b` | deny `db.sensitive_table` + `chain.db_to_egress_exfil` |
| S03 | K8s get secret `-o jsonpath={.data}` → exec | hanya `-o yaml\|json` yang diblok | deny `k8s.secret_read` + `chain.k8s_secret_to_exec` |
| S04 | Tool tulis `/tmp/p.sh` → SSH `sh /tmp/p.sh` | ssh.rego tanpa AST guard | deny `shellguard.redir_write_forbidden` + `ssh.ast_violation` |
| S05 | Docker inspect prod-db → LLM "parse env PGPASSWORD" | inspect dianggap readonly | deny `shield.container.protected` + `chain.container_secret_to_llm` |
| S06 | LLM 64KB middle-truncation → tool read | capConversation buang tengah, forward penuh | deny `ai.llm.oversized_uninspected` + `chain.tainted_prompt_tool` |
| S07 | Tool arg-key non-standar (`exec`) baca id_rsa → SSH connect | shellguard hanya cek cmd/command/script | deny `shellguard.unparseable` + `chain.cred_harvest_to_ssh` |
| S08 | Docker bind `/Users/adm/.ssh:/k:ro` → start | regex mount `(:|$)` miss subpath | deny `docker.host_root_forbidden` + `chain.tainted_container_start` |
| S09 | K8s manifest capabilities SYS_ADMIN → port-forward | escalation_patterns tanpa cek capabilities | deny `k8s.privilege_escalation` + `chain.k8s_escalated_access` |
| S10 | DB `COPY TO '/tmp/f'` → tool read_file | hanya `COPY..TO PROGRAM` diblok | deny `db.destructive_statement` + `chain.db_file_drop_read` |
| S11 | Tool `curl http://167772161` (IP integer) → read | ipv4_pattern tak deteksi integer IP | deny `shield.prod.ip_blocked` + `chain.network_staging_read` |
| S12 | LLM multi-turn split `\u2060` → db `pr\u2060od-db` | word-joiner tak di-strip normalize() | deny `shield.prod.llm_target` + `shield.prod.no_access` |

## 5. Skenario Tambahan Opus 13–27 (urut bahaya — sampling & statis)

13. **Chaining docker-write + db** — dump table → tulis keluar via pair valid per-stage (exfiltration path).
14. **Chaining http + llm masking** — response HTTP tak discan → masuk prompt berikutnya (injection via data).
15. **Race budget paralel** — N thread baca budget sama sebelum increment; total approved > limit = bug.
16. **Glob `logs/*` vs `logs/**`** — dua impl matcher berbeda untuk path bersarang; matriks path×pattern.
17. **Unicode homoglyph di ARGS tool** — normalize() baru level prompt, belum args; nama file homoglyph vs allowlist exact.
18. **DB dialect parse** — MySQL backtick, `CALL purge()` stored-proc; corpus SQL per-dialect vs golden verdict.
19. **data.json via k8s configmap** — configmap berisi policy data alternatif; unsigned wajib ditolak.
20. **Tap hold-verify TOCTOU** — tool_result flush sebelum verify selesai (delay verify > stream speed).
21. **Capture 2MB cap truncation** — JSON terpotong memutus escape; parser fallback pass-through; payload 2MB±10B.
22. **Rate-limit key-id rotate** — 100 key_id dari 1 api_key_sha; aggregate limit harus tetap kena.
23. **Redirect suffix re-check** — 3-hop `a.prod.com` → `prod.com.evil.io`; host final vs rule.
24. **Kill-switch race per-key** — request in-flight saat kill di-set; audit log consistency.
25. **Audit mirror divergence** — PG mirror mati diam-diam; wajib fail-closed bukan fail-open.
26. **Bundle rollback window** — replay signature v1 setelah v2 aktif.
27. **Cluster gossip TTL** — kill di node A belum propagate ke B dalam window TTL.

## 6. Deteksi Flaky Policy (3 cara)

1. **Idempotency burst** — sampel ke-50 dikirim 5× paralel+sekuensial epoch sama; tuple `(Decision, RuleID, Reason, MaskedArgsHash)` harus identik.
2. **Canonical JSON permutation** — acak urutan key + format angka (`80` vs `80.0`); verdict & cacheKey tak boleh berubah.
3. **Cache vs explain diff** — `/v1/decide` (LRU/singleflight) vs `/v1/admin/explain` (uncached); selisih = `FLAKY_VERDICT`.

## 7. TIDAK Dites — Butuh Human/Proses (threat model di-manage, bukan test)

1. Social engineering admin (phish bearer token).
2. Insider operator sah memasang bundle rule longgar.
3. Host compromised (api_key dibaca dari env/ps).
4. Legal/policy buy-off (org membuka CIDR prod demi kecepatan).
5. LLM persuasion terhadap user manusia (disable kill switch).

## 8. Larangan Mutlak Harness (safety guardrails)

1. TIDAK menyentuh docker.sock / container produksi (`teknikalidnew-db-1`) — hanya `POST /v1/decide` engine terisolasi.
2. TIDAK menembak upstream LLM nyata — dummy loopback `httptest.Server` saja.
3. TIDAK ada egress nyata — semua host/IP hanya string JSON atau mock dialer.
4. TIDAK mengeksekusi command/SQL/kubectl/SSH asli — murni policy-eval HTTP.
5. TIDAK mengubah state engine produksi — instance terisolasi, `--audit-db=/tmp/cerberus-mc-dummy.db`, key sintetis.

## 9. Output & Kriteria Lolos

- `mc-report.json`: tabel per-stage (samples, TPS, p50/p99, allow/deny, flaky, escapes, p_ub99) + coverage matrix per rule-family + dead-rule list + `escapes[]` (seed, input_json, expected vs actual, `repro_curl`).
- **Lolos** = 0 escape pada 45k sampel, 0 flaky. Escape apapun → ledger OPEN → fix + regression test → rerun sampai 0 (rules owner 14 Nov).
