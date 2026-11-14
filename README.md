# Cerberus — OPA-style Policy Engine for AI Agent Gateways 🔥

[![CI](https://github.com/metabbe3/Cerberus/actions/workflows/ci.yml/badge.svg)](https://github.com/metabbe3/Cerberus/actions/workflows/ci.yml)
[![Docker Image](https://img.shields.io/badge/GHCR-cerberus%3Alatest-blue?logo=docker)](https://github.com/metabbe3/Cerberus/pkgs/container/cerberus)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **The "OPA" for the AI agent ecosystem**: a single zero-trust policy enforcement gateway for tool/command/data permissions, at-rest & in-flight masking, egress CIDR shields, and multi-team governance — evaluated with deterministic Rego rules, hot-reloaded dynamically, zero recompilation needed.

📖 **Dokumentasi Lengkap:**
- 📊 **[docs/STATUS.md](docs/STATUS.md) — Status & progress proyek: apa yang sudah diuji, bukti, dan rantai traceability. Mulai dari sini.**
- 🚀 [docs/QUICKSTART.md](docs/QUICKSTART.md) — Panduan instalasi cepat (< 5 menit), integrasi runtime agent (Claude Code, Cursor, Python), & FAQ.
- ⚙️ [docs/SETUP.md](docs/SETUP.md) — Arsitektur detail, referensi variabel lingkungan (12-factor), dan flag CLI.
- 🔒 [docs/CHANGELOG-AUDIT.md](docs/CHANGELOG-AUDIT.md) — Ledger audit append-only: semua temuan & fix dengan commit + bukti.
- 🎲 [docs/MONTE-CARLO.md](docs/qa/MONTE-CARLO.md) — Catalog skenario attack monte carlo (yang diuji & yang tidak).

---

## Quickstart (< 5 Menit) 🚀

Instalasi dan jalankan seluruh stack Cerberus (Engine, LLM Tap, Docker Proxy, Egress Proxy, SSH Bastion, Owl UI) secara otomatis:

```bash
# Satu perintah instalasi dengan kredensial 12-factor acak & verifikasi smoke
curl -fsSL https://raw.githubusercontent.com/metabbe3/Cerberus/main/scripts/get.sh | bash
```

*Jika Anda sudah mengkloning repositori:*
```bash
./scripts/get.sh
```

👉 **Lihat [docs/QUICKSTART.md](docs/QUICKSTART.md)** untuk:
- 3 jalur instalasi (Otomatis `get.sh`, Docker Compose manual 12-factor, dan build dari source).
- Panduan integrasi runtime: **Claude Code**, **Cursor IDE**, **OpenAI / Anthropic SDK**, **HTTP_PROXY**, dan **DOCKER_HOST**.
- Pemecahan masalah awal (401 token mismatch, 403 unknown agent key).

---

## Komponen Cerberus (6 Core Services)

Cerberus mengemas seluruh ekosistemnya dalam container image terpadu (`ghcr.io/metabbe3/cerberus:latest`) dan dashboard UI (`owl`):

| Komponen | Binary / App | Peran & Tanggung Jawab | Port & Jaringan |
|---|---|---|---|
| **Engine** | `cerberus` | Otak keputusan kebijakan, evaluator OPA Rego, API admin, metrik Prometheus, SQLite WAL audit | `127.0.0.1:8089` (Internal + Loopback) |
| **LLM Tap** | `cerberus-tap` | In-path LLM proxy, stream capture (SSE), masking rahasia otomatis, & fail-closed deny | `127.0.0.1:8090` (Edge) |
| **Docker Proxy** | `cerberus-proxy` | Perisai perlindungan socket daemon Docker, container isolation, pencegah container escape | `127.0.0.1:2377` (Edge) |
| **Egress Proxy** | `cerberus-proxy` | Outbound HTTP/CONNECT egress proxy penegak perisai CIDR privat & metadata cloud | `127.0.0.1:8088` (Edge) |
| **SSH Bastion** | `cerberus-ssh` | Bastion gate pemeriksa perintah SSH per-eksekusi via engine (relay & decide-only) | `127.0.0.1:2222` (Edge) |
| **Owl Dashboard** | `owl` | Web UI administratif (Next.js 15), visualisasi time-series, live SSE audit, & manajemen agen | `127.0.0.1:3000` (Edge) |

### Perangkat CLI Tambahan (Offline Tooling)
| Binary | Peran | Penggunaan |
|---|---|---|
| **`cerberus-bundle`** | Compiler Policy Bundle | Mengompilasi dan memvalidasi bundle Rego secara offline |
| **`cerberus-redteam`** | Red-Team Simulation Suite | Menjalankan simulasi serangan keamanan dan deteksi bypass |
| **`loadgen-stress`** | High-Throughput Load Generator | Alat uji beban konkurensi tinggi (~85k TPS) |

---

## Matriks Stage Penegakan Kebijakan

Cerberus menegakkan tata kelola zero-trust di seluruh siklus hidup interaksi agent:

| Stage | Cakupan Penegakan | Contoh Pencegahan | Status |
|---|---|---|---|
| **`shell` / `tool`** | Eksekusi CLI & tool calls LLM | Memblokir `rm -rf /`, `curl \| bash`, `dd of=/dev/`, dump kredensial `grep * /etc/passwd` | ✅ **Live** |
| **`http` (Egress)** | Koneksi outbound agent | Memutus akses ke subnet internal (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) & AWS metadata (`169.254.169.254`) | ✅ **Live** |
| **`docker`** | Socket API Docker | Melarang container privileged, mount direktori host sensitif (`/etc`, `/var/run`, `~/.ssh`, `.env*`), dan penghapusan container terlindungi | ✅ **Live** |
| **`ssh`** | Sesi bastion SSH | Memeriksa setiap `exec` command sebelum di-relay ke server upstream | ✅ **Live** |
| **`llm`** | Prompt & Turn LLM | Memverifikasi allowlist model (misal `claude-*`), kuota panggilan kumulatif per-agen (satuan COUNT, bukan USD — biaya metered adalah ranah LLM router seperti LiteLLM), dan deteksi prompt injection | ✅ **Live** |
| **`db`** | Query database & SQL parser | Mencegah `DROP TABLE`, `TRUNCATE`, akses tabel sensitif (mis. tabel kredensial via CTE), dan query destruktif | ✅ **Live** |
| **`k8s`** | Kubernetes API admission | Mencegah penghapusan pod critical, modifikasi ConfigMap/Secrets sensitive, dan namespace bypass | ✅ **Live** |

---

## Bukti Pengujian (Evidence-First) 🧪

Setiap klaim di repo ini punya baris ledger + commit + bukti run — lihat [docs/CHANGELOG-AUDIT.md](docs/CHANGELOG-AUDIT.md).

- **Rego Policy Suite:** 282/282 test PASS (`opa test policies/`) — regression suite per stage + fixture attack.
- **Monte Carlo Fuzzing:** 45.000 sampel / 5 stage-parallel, seed 20261114 → **0 escape** (p_ub99 = 0.000102), p99 latency 83ms total. Rantai fix: 12.353 → 3.534 → 589 → 588 → 0 escape dalam 5 run. Detail skenario: [docs/qa/MONTE-CARLO.md](docs/qa/MONTE-CARLO.md).
- **Red-Team Suite:** 10 serangan live (host-spoof, raw-IP, key-spoof, burst, kill-switch takeover, dll.) = 9 BLOCKED + 1 WARN + 0 EXPOSED.
- **Load:** engine **35.822 TPS @ 2048 conn** (image Docker resmi, err 0%, p99 274 ms) / **105.800 TPS** native; tap jalur LLM penuh ~2.500 TPS @ 200 conn — headroom ~350× vs kebutuhan MVP-60. Red-team manual 11 probe = 0 escape. Detail: [docs/qa/BENCH.md](docs/qa/BENCH.md).
- **CI:** lint + `make test` (22 paket, race) + build + GHCR image di setiap push — badge di atas.

## Konsep Inti Arsitektur

1. **Production-grade Rego Policies:** Evaluasi deterministik policy-as-code berbasis Open Policy Agent dalam skala microsecond.
2. **Policy vs. Data Split:** `authz.rego` mendefinisikan logika keputusan statis; JSON / PostgreSQL menyimpan data tim, agen, dan batas rate limit dinamis — hot-reload instan tanpa restart.
3. **Per-Key & Per-Team Governance:** Agen diidentifikasi via `key_id` (LiteLLM-compatible sha256) dengan mode fail-open (onboarding) atau fail-closed (enforcement ketat).
4. **Actual Invocation Verification:** Validasi tool calls dan argumen aktual yang dipanggil agent, bukan sekadar prompt teks.
5. **Dynamic Data Masking:** Redaksi otomatis pola sensitif (`sk-*`, token API, email, postgres DSN) pada argument tool dan log audit.
6. **Emergency Kill-Switch:** Tombol darurat pemutus akses global atau per-agen, dengan dukungan break-glass 15 menit melalui dashboard Owl.
7. **User Auth DB-First (SSO-ready):** Login Owl via user database engine (hash Argon2id, role admin/viewer, lockout 5×/15m) — `OWL_PASSWORD` kini hanya bootstrap. Lihat ADR-0005.
7. **PostgreSQL System of Record:** Opsi persistensi ganda dengan database relasional dan fallback otomatis ke file lokal (`prod.json`).

---

## Monitoring & Observability

- **`GET /v1/health/components`:** Endpoint status kesehatan seluruh sub-sistem (engine, agents, kill-switch, postgres, audit).
- **`GET /v1/audit/timeseries`:** Agregasi time-series keputusan evaluasi per interval waktu untuk visualisasi Owl / Grafana.
- **Owl Dashboard (Next.js 15):** Dashboard visual di `http://127.0.0.1:3000` dengan live streaming event SSE.
- **Daily Rotating Audit Logs:** Database SQLite harian berformat WAL dengan retensi otomatis dan fire-and-forget log shipping.
- **Breach Center:** Page `/breaches` mengklasifikasi deny jadi temuan keamanan (CRITICAL/HIGH/MEDIUM) dengan severity map, fingerprint dedup ×500, dan first-seen badge — terpisah dari deny rate-limit/policy biasa.
- **Policy Explorer:** Menjalankan 282 test Rego langsung dari dashboard (pass/fail per modul) tanpa CLI.
- **Upstream LLM Fleksibel:** Set endpoint & API key upstream (LiteLLM/z.ai/custom) dari Settings — key disimpan terenkripsi AES-256-GCM di DB engine, tak pernah dikembalikan oleh GET (hanya `key_hint` 4 char); `cerberus-tap` hot-reload atomic 30s.

---

## Admin API (Bearer CERBERUS_ADMIN_TOKEN)

| Endpoint | Method | Deskripsi |
|---|---|---|
| `/v1/admin/data` | `GET`, `PUT` | Membaca atau memperbarui data konfigurasi kebijakan (disimpan ke PG/file) |
| `/v1/admin/templates` | `GET`, `PUT`, `DELETE` | Manajemen template kebijakan server-side |
| `/v1/health/components` | `GET` | Status kesehatan estate engine dan gates |
| `/v1/audit` | `GET` | Kueri log audit keputusan dengan filter waktu dan field |
| `/v1/audit/timeseries` | `GET` | Data deret waktu keputusan evaluasi |
| `/v1/status`, `/v1/events` | `GET` | Endpoint status dan streaming event SSE real-time |
| `/v1/decide/tool`, `/v1/decide/llm`, `/v1/decide` | `POST` | Endpoint evaluasi keputusan kebijakan |
| `/v1/auth/login`, `/v1/auth/logout`, `/v1/auth/me` | `POST`/`GET` | Autentikasi user DB (Argon2id, session cookie, lockout 5×/15m) |
| `/v1/admin/users`, `/v1/admin/users/{id}/disable` | `GET`, `POST`, `PUT`, `DELETE` | Manajemen user & role (admin/viewer) — RBAC server-side |
| `/v1/audit/breaches` | `GET` | Breach Center: temuan keamanan 3-tier severity + fingerprint dedup |
| `/v1/policy/modules`, `/v1/policy/test-run` | `GET`, `POST` | Policy Explorer: 282 test suite + jalankan test dari dashboard |
| `/v1/admin/upstream`, `/v1/admin/upstream/test` | `GET`, `PUT`, `POST` | Konfigurasi LLM upstream (endpoint + key AES-256-GCM, test koneksi) |
