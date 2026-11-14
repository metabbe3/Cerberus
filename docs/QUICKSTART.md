# Cerberus Quickstart (< 5 Menit) 🚀

Cerberus adalah zero-trust policy engine & security gateway untuk AI agents. Panduan ini menuntun instalasi, verifikasi smoke test, integrasi runtime agent (Claude Code, Cursor, generic SDK, HTTP_PROXY, Docker), serta pemecahan masalah awal.

---

## 1. Tiga Jalur Instalasi

### Jalur 1: Bootstrapper Otomatis (`get.cerberus.sh`) [Direkomendasikan]
Jalur tercepat untuk server Linux atau workstation macOS (memerlukan Docker dan curl/openssl):

```bash
# Unduh dan bootstrap seluruh stack Cerberus dalam satu baris
curl -fsSL https://raw.githubusercontent.com/metabbe3/Cerberus/main/scripts/get.sh | bash
```

*Jika Anda sudah mengkloning repositori secara lokal:*
```bash
./scripts/get.sh
```

**Yang dilakukan secara otomatis oleh `get.sh`:**
1. Mengunduh manifes `docker-compose.prod.yml`, policies default, data template, dan Owl UI (menggunakan fallback git sparse-checkout jika aset rilis belum tersedia).
2. Menghasilkan file konfigurasi `.env` 12-factor dengan secret acak kriptografis (`cb_adm_...`, `cb_owl_...`, agent key + sha256).
3. Mengamankan file kredensial dengan permission `chmod 600 .env`.
4. Menjalankan seluruh stack 6 container dengan `docker compose up -d --wait`.
5. Menjalankan 2 verifikasi smoke curl (`allow` untuk `kubectl get pods`, `deny` untuk `rm -rf`).
6. Menampilkan kredensial sekali saat pembuatan pertama, kemudian mencetak environment siap pakai untuk runtime agent.

---

### Jalur 2: Docker Compose Manual (12-Factor Production)

Jika Anda ingin mengontrol setiap langkah dan memeriksa variabel environment sebelum boot:

1. **Clone repositori:**
   ```bash
   git clone https://github.com/metabbe3/Cerberus.git
   cd Cerberus
   ```

2. **Salin template konfigurasi `.env.example` ke `.env`:**
   ```bash
   cp .env.example .env
   ```

3. **Generate kredensial rahasia:**
   ```bash
   ADM_TOK="cb_adm_$(openssl rand -hex 24)"
   TAP_TOK="cb_tap_$(openssl rand -hex 24)"
   OWL_PASS="cb_owl_$(openssl rand -hex 16)"
   OWL_SEC="$(openssl rand -hex 32)"
   AGT_SEC="sk-cb-$(openssl rand -hex 24)"
   AGT_KEY=$(echo -n "${AGT_SEC}" | openssl dgst -sha256 | awk '{print $NF}')

   sed -i.bak "s|^CERBERUS_ADMIN_TOKEN=.*|CERBERUS_ADMIN_TOKEN=${ADM_TOK}|" .env
   sed -i.bak "s|^TAP_ADMIN_TOKEN=.*|TAP_ADMIN_TOKEN=${TAP_TOK}|" .env
   sed -i.bak "s|^OWL_ADMIN_PASSWORD=.*|OWL_ADMIN_PASSWORD=${OWL_PASS}|" .env
   sed -i.bak "s|^OWL_SESSION_SECRET=.*|OWL_SESSION_SECRET=${OWL_SEC}|" .env
   sed -i.bak "s|^CERBERUS_AGENT_SECRET=.*|CERBERUS_AGENT_SECRET=${AGT_SEC}|" .env
   sed -i.bak "s|^CERBERUS_AGENT_KEY=.*|CERBERUS_AGENT_KEY=${AGT_KEY}|" .env
   rm -f .env.bak
   chmod 600 .env
   ```

4. **Inisialisasi file data kebijakan:**
   ```bash
   cp data/prod.template.json data/prod.json
   ```

5. **Jalankan stack:**
   ```bash
   docker compose -f docker-compose.prod.yml up -d --wait
   ```

6. **Verifikasi status kesehatan:**
   ```bash
   curl -fsS http://127.0.0.1:8089/healthz
   # Respon: ok
   ```

---

### Jalur 3: Build dari Source (Pengembangan Native)

Untuk pengujian lokal tanpa kontainer atau kontribusi kode:

1. **Prasyarat:** Go 1.24+, Node.js 22+, Open Policy Agent (OPA) CLI 1.22+.

2. **Kompilasi biner Go:**
   ```bash
   make build
   # Menghasilkan bin/cerberus, bin/cerberus-tap, bin/cerberus-proxy, bin/cerberus-ssh
   ```

3. **Siapkan data dan jalankan Engine:**
   ```bash
   cp data/prod.template.json data/prod.json
   export CERBERUS_ADMIN_TOKEN="cb_adm_$(openssl rand -hex 24)"
   export CERBERUS_DATA_FILE="data/prod.json"
   export CERBERUS_AUDIT_DB="cerberus.db"
   ./bin/cerberus
   ```

4. **Jalankan dashboard Owl (terminal terpisah):**
   ```bash
   cd owl
   npm ci
   export CERBERUS_URL="http://localhost:8089"
   export CERBERUS_ADMIN_TOKEN="<token-dari-langkah-3>"
   export OWL_PASSWORD="admin-password"
   export OWL_SESSION_SECRET="$(openssl rand -hex 32)"
   npm run dev
   # Dashboard live di http://localhost:3000
   ```

---

## 2. Integrasi Runtime Agent

Setelah Cerberus berjalan, arahkan runtime agent Anda melalui gerbang penegakan:

```
[Agent Runtime]
  ├── LLM Calls (:8090) ──────► cerberus-tap ───► Upstream LLM (Anthropic/OpenAI)
  ├── Outbound HTTP (:8088) ──► egress-proxy  ───► Internet (Blok CIDR internal)
  ├── Docker API (:2377) ─────► docker-proxy  ───► /var/run/docker.sock
  └── Decides (:8089) ────────► cerberus-engine (Audit & Rego Evaluation)
```

### 1. Claude Code
Arahkan API base Anthropic ke LLM Tap (`:8090`):
```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8090"
export ANTHROPIC_CUSTOM_HEADERS="X-Tap-Key: k-glob"

# Jalankan Claude Code seperti biasa
claude
```
*Hasil:* Setiap turn LLM dan tool call disaring dan dicatat di SQLite audit. Pola rahasia (`sk-*`, token DB) dimasking otomatis di transit.

---

### 2. Cursor IDE
Untuk melindungi request model dari Cursor:
1. Buka **Cursor Settings** -> **Models** -> **OpenAI / Anthropic API Key**.
2. Ubah **Base URL** menjadi `http://127.0.0.1:8090/v1` (atau `http://127.0.0.1:8090`).
3. Set Header `X-Tap-Key: k-glob` (atau gunakan profil default `k-default-agent`).

---

### 3. Generic OpenAI / Anthropic Compatible Agents (Python, Node.js)

**Python (Anthropic SDK):**
```python
import os
from anthropic import Anthropic

client = Anthropic(
    base_url="http://127.0.0.1:8090",
    default_headers={"X-Tap-Key": os.environ.get("X_TAP_KEY", "k-glob")},
)
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Halo Cerberus"}],
)
```

**Python (OpenAI SDK):**
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8090/v1",
    default_headers={"X-Tap-Key": "k-glob"},
)
```

---

### 4. HTTP_PROXY Outbound Egress Shield
Cegah agent melakukan exfiltrasi data atau SSRF ke subnet internal perusahaan:
```bash
export HTTP_PROXY="http://127.0.0.1:8088"
export HTTPS_PROXY="http://127.0.0.1:8088"
export NO_PROXY="localhost,127.0.0.1"
```
*Hasil:* Panggilan agent ke IP privat (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) atau metadata cloud (`169.254.169.254`) akan langsung diputus dengan `HTTP 403 Forbidden`.

---

### 5. DOCKER_HOST Socket Isolation
Cegah agent yang mengeksekusi container dari menghapus container production atau memicu container escape:
```bash
export DOCKER_HOST="tcp://127.0.0.1:2377"

# Jalankan docker cli melalui proxy terlindungi
docker ps
```

---

## 3. Owl Dashboard

Buka antarmuka manajemen web di browser:
👉 **[http://127.0.0.1:3000](http://127.0.0.1:3000)**

- **Login:** Masukkan `OWL_ADMIN_PASSWORD` yang digenerate saat instalasi.
- **Fitur Utama:**
  - **Live Audit Stream:** Aliran event real-time (SSE) dari semua keputusan evaluasi.
  - **Timeseries:** Grafik metrik keputusan allow vs. deny per menit.
  - **Agent Governance:** Tinjau status izin agent, batas budget, dan rate limit.
  - **Policy Explorer:** Lihat rule Rego aktif dan konfigurasi stage.

---

## 4. FAQ & Pemecahan Masalah Awal

### ❓ FAQ 1: Token salah / HTTP 401 Unauthorized
* **Gejala:** Memanggil endpoint admin menghasilkan `{"error":"unauthorized"}` atau status HTTP 401.
* **Penyebab:** Header `Authorization: Bearer <token>` tidak sama dengan nilai `CERBERUS_ADMIN_TOKEN` yang dimuat pada file `.env` kontainer engine.
* **Solusi:**
  1. Periksa token aktif di file `.env`:
     ```bash
     grep CERBERUS_ADMIN_TOKEN .env
     ```
  2. Pastikan menyertakan header authorization saat melakukan request admin:
     ```bash
     curl -H "Authorization: Bearer <TOKEN_DARI_ENV>" http://127.0.0.1:8089/v1/admin/data
     ```
  3. Jika baru saja mengubah `.env`, terapkan ulang container:
     ```bash
     docker compose -f docker-compose.prod.yml up -d
     ```

---

### ❓ FAQ 2: Agent unknown / Closed-Mode (HTTP 403 Forbidden / `ai.tool.not_allowed`)
* **Gejala:** Agent menerima penolakan `{"decision":"deny","rule_id":"ai.tool.not_allowed"}`.
* **Penyebab:** Cerberus berjalan dalam mode Zero-Trust fail-closed (`bypass_unknown_keys: false`), dan identifier `key_id` agent (`X-Tap-Key`) belum didaftarkan di dalam `data/prod.json`.
* **Solusi A (Daftarkan Agent):**
  Tambahkan definisi agent ke dalam blok `agents` di `data/prod.json`:
  ```json
  "agents": {
    "k-my-new-agent": {
      "name": "My AI Agent",
      "allowed_tool_calls": ["kubernetes*", "read*", "shell*"],
      "budget_limit": 100,
      "risk_tier": "low"
    }
  }
  ```
  Lalu muat ulang kebijakan secara instan tanpa downtime:
  ```bash
  docker compose -f docker-compose.prod.yml exec engine kill -HUP 1
  ```

* **Solusi B (Mode Onboarding / Fail-Open Sementara):**
  Jika Anda sedang dalam fase evaluasi dan ingin semua agen yang belum terdaftar diizinkan sementara, setel pada `data/prod.json`:
  ```json
  "config": {
    "bypass_unknown_keys": true,
    "bypass_unknown_teams": true
  }
  ```
  Dan reload:
  ```bash
  docker compose -f docker-compose.prod.yml exec engine kill -HUP 1
  ```
