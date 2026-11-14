# Status & Progress — Cerberus

> Halaman ini = peta satu-klik untuk pembaca repo: posisi proyek sekarang, apa saja yang sudah diuji, dan ke mana mencari bukti. Di-update tiap fase (sumber internal: mission tracker; semua klaim di sini harus punya link bukti).

**Update terakhir:** 14 Nov 2026 — Fase F3 selesai · MC build in-flight

## Posisi Sekarang

MVP untuk 60 user eksternal + ratusan agent (target rilis: **v0.1.0**). Semua merge di `main`, CI hijau (test + lint + OPA + GHCR image otomatis).

| Fase | Status | Bukti |
|---|---|---|
| Audit 5-domain + fix batch A/B/C | ✅ DONE | [CHANGELOG-AUDIT.md](CHANGELOG-AUDIT.md) (94 temuan, semua FIXED + bukti live) |
| Red-team suite (10 serangan live) | ✅ DONE | `cmd/cerberus-redteam` — 9 BLOCKED / 1 WARN / 0 EXPOSED |
| Hardening merge R+H+S+M | ✅ DONE | commit `5d626a8`→`fe1afc8`, CI hijau |
| F3: exec wrapper + unifikasi engine + tenant quota + SSH pubkey + cluster + custom-stage | ✅ DONE | commit `d29384e`, OPA 257/257, CI hijau termasuk GHCR image pertama |
| Monte Carlo harness + run 45k sampel | 🔄 IN PROGRESS | spesifikasi: [MONTE-CARLO.md](MONTE-CARLO.md) · branch `wt/montecarlo` |
| Batch U: Owl UX (breach center, detail per-agent, policy explorer) | ⏳ QUEUED | rencana di ledger & tracker |
| F4: acceptance (quickstart fresh-VM, 10 serangan, load, soak 48h, pilot real-agent containerized) | ⏳ QUEUED | — |
| F5: release v0.1.0 + ROADMAP + soak | ⏳ QUEUED | [ROADMAP.md](ROADMAP.md) |

## Apa yang Sudah Diuji (3 lapis QA)

1. **Static audit** — 94 temuan dari 5 auditor independen → semua fixed, tiap fix ada commit + bukti live: [CHANGELOG-AUDIT.md](CHANGELOG-AUDIT.md)
2. **Red-team suite** — 10 serangan live vs engine (spoof key/host, raw-IP, burst, kill-switch hijack, injection): [BYPASS_MATRIX.md](BYPASS_MATRIX.md) · [CHAOS_MATRIX.md](CHAOS_MATRIX.md)
3. **Statistical coverage (Monte Carlo)** — ribuan sampel adversarial per stage, escape-rate target <0,1%: [MONTE-CARLO.md](MONTE-CARLO.md) *(run pertama: in-flight)*

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

Lima kelas ancaman di luar jangkauan test otomatis (social engineering, insider, host-compromised, keputusan legal, persuasion manusia) — dikelola via proses operasional, bukan test: [MONTE-CARLO.md §7](MONTE-CARLO.md).
