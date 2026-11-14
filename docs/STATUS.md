# Status & Progress — Cerberus

> Halaman ini = peta satu-klik untuk pembaca repo: posisi proyek sekarang, apa saja yang sudah diuji, dan ke mana mencari bukti. Di-update tiap fase (sumber internal: mission tracker; semua klaim di sini harus punya link bukti).

**Update terakhir:** 14 Nov 2026 — Monte Carlo PASS (0 escape / 45k) · lanjut Batch U Owl

## Posisi Sekarang

MVP untuk 60 user eksternal + ratusan agent (target rilis: **v0.1.0**). Semua merge di `main`, CI hijau (test + lint + OPA + GHCR image otomatis).

| Fase | Status | Bukti |
|---|---|---|
| Audit 5-domain + fix batch A/B/C | ✅ DONE | [CHANGELOG-AUDIT.md](CHANGELOG-AUDIT.md) (94 temuan, semua FIXED + bukti live) |
| Red-team suite (10 serangan live) | ✅ DONE | `cmd/cerberus-redteam` — 9 BLOCKED / 1 WARN / 0 EXPOSED |
| Hardening merge R+H+S+M | ✅ DONE | commit `5d626a8`→`fe1afc8`, CI hijau |
| F3: exec wrapper + unifikasi engine + tenant quota + SSH pubkey + cluster + custom-stage | ✅ DONE | commit `d29384e`, OPA 257/257, CI hijau termasuk GHCR image pertama |
| Monte Carlo: harness + 5 run iteratif → **0 escape / 45k sampel** | ✅ DONE | [MONTE-CARLO.md](qa/MONTE-CARLO.md) · ledger MC-R1 FIXED · 12.353→0 dalam 4 batch fix (`45ec079`→`977210a`) |
| Batch U: Owl UX (breach center, detail per-agent, policy explorer) | ⏳ QUEUED | rencana di ledger & tracker |
| F4: acceptance (quickstart fresh-VM, 10 serangan, load, soak 48h, pilot real-agent containerized) | ⏳ QUEUED | — |
| F5: release v0.1.0 + ROADMAP + soak | ⏳ QUEUED | [ROADMAP.md](ROADMAP.md) |

## Apa yang Sudah Diuji (3 lapis QA)

1. **Static audit** — 94 temuan dari 5 auditor independen → semua fixed, tiap fix ada commit + bukti live: [CHANGELOG-AUDIT.md](CHANGELOG-AUDIT.md)
2. **Red-team suite** — 10 serangan live vs engine (spoof key/host, raw-IP, burst, kill-switch hijack, injection): [BYPASS_MATRIX.md](qa/BYPASS_MATRIX.md) · [CHAOS_MATRIX.md](qa/CHAOS_MATRIX.md)
3. **Statistical coverage (Monte Carlo)** — 45.000 sampel (8 stage × 5.000 + 10.000 chain), 5 run iteratif, escape 12.353→**0**, 0 flaky: [MONTE-CARLO.md](qa/MONTE-CARLO.md) · [ledger MC-R1](CHANGELOG-AUDIT.md)

**Regresi dijaga oleh:** OPA suite 257/257 (`make opa-test`) · race test 19 pkg (CI) · lint 0 · coverage-drop gate di bundle activation.

## Rantai Traceability

```
temuan (audit/red-team/MC)  →  baris ledger (docs/CHANGELOG-AUDIT.md: ID·tanggal·severity·status)
                            →  fix (commit SHA di pesan ledger)
                            →  regression test (suite OPA / Go test / redteam CLI)
                            →  bukti (log run live / CI run / mc-report.json)
```

- Setiap merge WAJIB append ledger — tidak ada fix tanpa baris, tidak ada baris tanpa bukti.
- Laporan sprint per-batch (arsip historis): [reports/](reports/)
- Keputusan desain: [adr/](adr/) · [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md)

## Yang TIDAK Diuji (dan mengapa)

Lima kelas ancaman di luar jangkauan test otomatis (social engineering, insider, host-compromised, keputusan legal, persuasion manusia) — dikelola via proses operasional, bukan test: [MONTE-CARLO.md §7](qa/MONTE-CARLO.md).
