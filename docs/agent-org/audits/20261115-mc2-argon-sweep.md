# Monte-Carlo Round-2 Adversarial Security Sweep (Argon Fresh-Eyes Audit)

**Tanggal:** 2026-11-15  
**Target:** Cerberus 3-Layer Policy Gateway (`Engine :8089`, `Egress :8094`, `Tap :8090`, `Docker Proxy`, `cerberus-exec`, `Owl Web :3006`, `SDK Python/Go`)  
**Metodologi:** Deterministic Read-Only Static Code Analysis & Execution Path Tracing (Zero Code Mutation, Exclude Round-1 Items)

---

## I. Ringkasan Eksekutif

Audit deterministik putaran kedua (*fresh eyes*) dilakukan secara menyeluruh terhadap **8 area arsitektur baru** di luar 16 temuan Round-1 (`docs/CHANGELOG-AUDIT.md`). Dari **28 kelas pengujian keamanan dan konkurensi** yang dievaluasi:

- **Total Temuan Baru:** **17 Temuan**
  - **P0 (Critical — Bypass Kebijakan Langsung / Eksekusi Tanpa Otorisasi / Kebocoran Kredensial Utama):** **4 Temuan** (`MC2-01` s/d `MC2-04`)
  - **P1 (High — Evasion Filter, CSRF Admin, Starvasi Audit, Bypass Lockout, Kolisi DB):** **9 Temuan** (`MC2-05` s/d `MC2-13`)
  - **P2 (Medium — Inkonistensi Snapshot Antar-Tahap, Open Redirect, Blindspot Forensik, Lost-Update):** **4 Temuan** (`MC2-14` s/d `MC2-17`)
  - **P3 (Low):** **0 Temuan**
- **Kelas Terbukti Tertutup (`CLOSED`):** **11 Kelas**

---

## II. Tabel Temuan (`MC2-01` s/d `MC2-17`)

| ID | Sev | File:Baris | Temuan | Skenario | Fix (1 Kalimat) | Effort |
|---|:---:|---|---|---|---|---|
| **MC2-01** | **P0** | [policies/stages/docker.rego:84-100](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L84-L100) | Regex `mount_host_root` menggunakan anchor akhir `(:|$)` dan `$`, serta melewatkan direktori sensitif (`/root`, `/proc`, `/sys`, `/dev`, `/home`), sehingga mount sub-path seperti `/etc/shadow` atau `/etc/` lolos evaluasi. | 1) Request `stage: "docker"` masuk dengan `args.binds: ["/etc/shadow:/mnt:ro"]` atau `args.mounts: [{"source": "/etc/pam.d"}]`. 2) Rego mengevaluasi regex `(?i)^(/\|/Users\|/private\|/var\|/etc\|/bin\|/sbin\|/usr)(:\|$)`. 3) Karakter `/` setelah `/etc` menggagalkan pencocokan anchor `(:|$)` sehingga `mount_host_root` bernilai `false` dan menghasilkan `docker.allow`. | Ubah regex `mount_host_root` agar mencocokkan sub-path (`(/.*)?(:|$)`) setelah normalisasi path dan tambahkan `/root`, `/home`, `/proc`, `/sys`, serta `/dev` ke daftar prefix terlarang. | **S** |
| **MC2-02** | **P0** | [internal/proxy/docker.go:217-227](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/proxy/docker.go#L217-L227)<br>[internal/proxy/docker.go:295-346](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/proxy/docker.go#L295-L346)<br>[policies/stages/docker.rego:159-165](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L159-L165) | `DockerProxy` membaca field JSON secara case-sensitive (`"Image"`, `"HostConfig"`, `"Privileged"`, `"Binds"`) dan tidak mengekstrak `PidMode`, `NetworkMode`, maupun `IpcMode` dari `HostConfig`. | 1) Klien mengirim request pembuatan container ke `DockerProxy` dengan key huruf kecil (`"image"`, `"hostconfig"`) atau menyertakan `HostConfig.PidMode = "host"`. 2) Lookup `bodyMap["Image"]` dan `body["HostConfig"]` di Go gagal menemukan key tersebut sehingga `resource` kosong (`""`) dan `args` tidak memuat flag privileged/binds/pid. 3) Di `docker.rego:160`, syarat `image != ""` bernilai `false` sehingga `image_not_allowed` dan `host_namespace_forbidden` dilewati, sementara daemon Docker upstream meng-unmarshal JSON secara case-insensitive. | Unmarshal payload request Docker API ke struct Go bertipe kuat (case-insensitive), wajibkan `image != ""` pada aksi `create`/`run` di `docker.rego`, dan ekstrak `PidMode`, `NetworkMode`, `IpcMode`, `Devices`, serta `SecurityOpt` ke dalam `args`. | **M** |
| **MC2-03** | **P0** | [cmd/cerberus-exec/main.go:181-230](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-exec/main.go#L181-L230)<br>[cmd/cerberus-exec/main.go:262-326](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-exec/main.go#L262-L326)<br>[cmd/cerberus-exec/main.go:361-395](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-exec/main.go#L361-L395) | Parser CLI `cerberus-exec` menimpa variabel `sql`/`manifest` saat ada multi-flag (`-c`, `-e`, `-f`), mengabaikan `-h` pada DB dan manifest K8s >64KB, serta melewatkan opsi eksekusi lokal `-o`/`-F`/`-J`/`-p<port>` pada SSH. | 1) Pemanggil menjalankan `cerberus-exec` dengan dua flag `-c` pada `psql` (atau dua `-f` pada `kubectl`, atau `-oProxyCommand` / `-J` pada `ssh`). 2) Loop parser di `buildDBPayload`/`buildK8sPayload` menimpa variabel `sql`/`manifest` dengan argumen terakhir yang jinak, sedangkan `buildSSHPayload` melompati `-o` tanpa memeriksa `ProxyCommand`. 3) Engine mengizinkan payload berdasarkan argumen terakhir, lalu `syscall.Exec` menjalankan biner asli yang mengeksekusi seluruh argumen dari awal. | Gabungkan atau evaluasi seluruh argumen `-c`/`-e`/`-f` (serta tolak manifest >64KB dan validasi `-h`), blokir opsi berbahaya (`-o ProxyCommand`, `-o LocalCommand`, `-F`, `-J`) di `buildSSHPayload`, dan tangani flag pendek yang menempel (`-p`, `-l`, `-c`, `-e`, `-f`). | **M** |
| **MC2-04** | **P0** | [internal/server/middleware.go:118-137](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/middleware.go#L118-L137)<br>[internal/server/upstream_handlers.go:123-272](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/upstream_handlers.go#L123-L272)<br>[internal/server/admin.go:42-50](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/admin.go#L42-L50)<br>[internal/server/admin.go:1357-1440](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/admin.go#L1357-L1440) | Akun dengan `role: "viewer"` diizinkan oleh middleware `s.admin` mengakses `GET /v1/internal/upstream` (plaintext API key LLM), `GET /v1/admin/data` (data mentah tanpa masking), `POST /v1/query`, dan `POST /v1/admin/upstream/test` (SSRF internal). | 1) Pengguna ber-role `viewer` mengirim request dengan session token ke endpoint read/test yang dibungkus `s.admin`. 2) `isMutatingAdminRequest` mengembalikan `false` untuk semua metode `GET` serta mengecualikan `/v1/query` dan `/v1/admin/upstream/test`. 3) Handler `handleGetInternalUpstream` mendekripsi AES-GCM dan mengembalikan `api_key` plaintext, `getData` mengembalikan `snap.Data` tanpa `redactSecretKeys`, dan `handleTestUpstream` melakukan request HTTP server-side ke URL target tanpa filter IP prod/link-local. | Batasi `/v1/internal/upstream` hanya untuk `isMasterAdmin` (`CERBERUS_ADMIN_TOKEN`), wajibkan `auth.RoleAdmin` pada `/v1/admin/upstream/test` dan `/v1/query` (disertai validasi IP egress), serta terapkan `redactSecretKeys` pada `GET /v1/admin/data`. | **S** |
| **MC2-05** | **P1** | [internal/ratelimit/limiter.go:152-166](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/ratelimit/limiter.go#L152-L166)<br>[internal/ratelimit/limiter.go:279-286](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/ratelimit/limiter.go#L279-L286)<br>[internal/ratelimit/limiter.go:444-498](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/ratelimit/limiter.go#L444-L498)<br>[internal/server/decide.go:192,259](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L192-L259) | Callback `store.OnSwap` memanggil `l.Reset(snap.Epoch)` yang menghapus seluruh bucket rate-limit dan akumulasi `spendUSD` di memori, sementara `Limiter.Allow` menambah `dailyCount` sebelum `Engine.Decide` dieksekusi. | 1) Saat terjadi update policy, rotasi key, atau toggle capture flag, `OnSwap` mengosongkan map `l.keys` dan `l.teams` sehingga seluruh pemakaian RPM, tool per jam, dan budget USD harian ter-reset ke nol. 2) Sebaliknya, pada alur `/v1/decide`, `s.limiter.Allow` dijalankan di baris 192 sebelum `Engine.Decide` di baris 259, sehingga request tool yang ditolak oleh policy (`deny`) tetap mengurangi jatah kuota harian `dailyCount` agen dan tim. 3) Selain itu, saat `dailyChecked` bernilai `false`, pembacaan `countToolCallsToday` berjalan di luar mutex dan berpacu dengan flush asinkron SQLite 200ms. | Pertahankan state token bucket dan `spendUSD` lintas epoch pada `OnSwap` (hanya perbarui parameter limit), sinkronkan inisialisasi kuota SQLite di dalam lock, dan hanya inkremen kuota tool harian setelah `Engine.Decide` menghasilkan `allow`. | **M** |
| **MC2-06** | **P1** | [internal/audit/logger.go:85-87](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/logger.go#L85-L87)<br>[internal/audit/logger.go:154-168](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/logger.go#L154-L168)<br>[internal/server/decide.go:205-216](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L205-L216) | Setiap penolakan rate-limit HTTP 429 memanggil `Audit.Emit` ke channel tunggal non-blocking `l.ch` (kapasitas 4.096) yang baru di-flush ke SQLite setiap 200ms, sehingga banjir request 429 membuat event audit kritis terbuang (`Dropped.Inc()`). | 1) Klien yang terkena rate-limit terus mengirim request cepat ke `/v1/decide` (ditolak di memori dalam hitungan nanodetik pada `decide.go:192`). 2) Baris 206 memanggil `s.deps.Audit.Emit` untuk setiap respons 429 hingga memenuhi buffer `l.ch` (4.096 item) sebelum ticker 200ms (`flushLoop`) sempat mengurasnya ke SQLite. 3) Cabang `default:` pada `select` di `logger.go:164` membuang seluruh event berikutnya secara diam-diam, termasuk event `admin.*`, `ops.break_glass`, dan pencatatan tool `allow` di SQLite. | Terapkan throttling/sampling per-key untuk emisi event audit `ops.rate_limited` (429) dan pisahkan jalur antrean prioritas non-drop untuk event `admin.*`, `auth.*`, serta `ops.break_glass`. | **M** |
| **MC2-07** | **P1** | [policies/stages/docker.rego:13,159-180](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L159-L180)<br>[policies/gateway/authz.rego:68-82](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/gateway/authz.rego#L68-L82)<br>[internal/proxy/docker.go:228-253](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/proxy/docker.go#L228-L253) | Allowlist `allowed_images` menggunakan `glob.match` dengan delimiter kosong `[]` sehingga ter-bypass oleh sintaks `tag@sha256:digest`, sementara `DockerProxy` mengirim ID container sebagai `image` pada aksi non-create yang memicu false-deny 100%. | 1) Bila `allowed_images` berisi `"nginx:*"`, referensi `"nginx:latest@sha256:<digest_lain>"` cocok karena `*` dengan delimiter `[]` melintasi karakter `@` dan `:`, padahal Docker daemon mengutamakan digest `@sha256:` dan mengabaikan tag `:latest`. 2) Sebaliknya, pada `internal/proxy/docker.go:229`, aksi `start`, `stop`, `exec_create`, dan `logs` mengisi `input.Resource` (`image`) dengan ID/nama container (mis. `"a1b2c3d4"`). 3) Di `docker.rego:160`, aksi `start`/`exec_create`/`logs` tidak dikecualikan dari `image_not_allowed`, sehingga ID container gagal cocok dengan `allowed_images` dan selalu ditolak. | Pisahkan komponen repositori, tag, dan digest `@sha256:` dengan delimiter `["/", ":", "@"]` saat memvalidasi `allowed_images`, serta batasi aturan `image_not_allowed` hanya pada aksi berbasis image (`create`, `run`, `pull`, `build`). | **M** |
| **MC2-08** | **P1** | [owl/lib/session.ts:70-115](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/session.ts#L70-L115)<br>[owl/lib/engine.ts:218-226](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/engine.ts#L218-L226)<br>[internal/server/middleware.go:82-98,145-149](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/middleware.go#L82-L98)<br>[internal/server/break_glass.go:38-40,119-136](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/break_glass.go#L119-L136) | Fallback secret statis pada `OWL_SESSION_SECRET`, eskalasi token master pada `/api/events`, dan ketiadaan proteksi CSRF pada endpoint admin berbasis cookie di Owl maupun Engine (termasuk aktivasi global break-glass via body kosong). | 1) Jika `OWL_SESSION_SECRET` tidak diset, `session.ts:114` memakai string publik `"owl-session-secret-cerberus-production-grade-32b"`, dan `openEventStream` (`engine.ts:218`) mem-proxy `/v1/events` menggunakan master `CERBERUS_ADMIN_TOKEN` tanpa memverifikasi sesi DB pemanggil. 2) Di `internal/server/middleware.go:89`, `needsJSONBody` melewati pengecekan `Content-Type: application/json` jika `ContentLength == 0`, dan `s.admin` menerima autentikasi dari cookie `owl_session`. 3) Request POST lintas-origin tanpa body (`Content-Length: 0`) ke `/v1/admin/break-glass` (atau POST form ke `/api/admin/*` di Owl yang tidak memeriksa `Content-Type` / `Origin`) langsung mengaktifkan global break-glass (`req.KeyID == ""` -> `bg.globalUntil`) selama 15 menit. | Wajibkan `OWL_SESSION_SECRET` non-default saat startup, gunakan `getActiveAuthToken` pada `openEventStream`, dan validasi header `Origin` serta `Content-Type: application/json` pada seluruh endpoint mutasi (termasuk saat `ContentLength == 0`). | **M** |
| **MC2-09** | **P1** | [internal/server/decide.go:119-172](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L119-L172)<br>[internal/server/break_glass.go:31-46,60-70](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/break_glass.go#L31-L46) | Saat `breakGlassActive` bernilai `true`, `/v1/decide` langsung mengembalikan `allow` sebelum rate-limiter dan `Engine.Decide`, sehingga mem-bypass `kill_switch`, `chain.tainted_exfil`, `shellguard`, secret masking, dan `prod_shield`, serta membuka jendela 15 menit tanpa autentikasi. | 1) Admin mengaktifkan break-glass (atau mengirim satu request `/v1/decide` dengan header `X-Break-Glass`, yang otomatis memanggil `s.breakGlass.Activate(in.KeyID, 15*time.Minute, ...)` di baris 140 dan menimpa TTL pendek yang sudah ada). 2) Selama 15 menit berikutnya, `s.breakGlass.IsActive(in.KeyID)` di baris 127 bernilai `true` untuk semua request tanpa memerlukan token admin (dan tanpa `X-Agent-Key` jika global break-glass aktif atau key tidak memiliki `api_key_sha256`). 3) Karena fungsi melakukan `return` di baris 171 sebelum `Engine.Decide`, proteksi `kill_switch`, blokir IP metadata `169.254.169.254`, `shellguard`, dan penyensoran `MaskedArgs` ikut mati total. | Tetap jalankan pemeriksaan `kill_switch`, blokir IP link-local/loopback, dan secret masking saat break-glass aktif, wajibkan autentikasi agen/admin yang valid pada setiap request break-glass, dan jangan perpanjang TTL otomatis dari header `/v1/decide`. | **M** |
| **MC2-10** | **P1** | [cmd/cerberus-exec/main.go:118-170,467-496](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-exec/main.go#L118-L170)<br>[internal/engine/engine.go:683-798](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/engine/engine.go#L683-L798)<br>[policies/gateway/authz.rego:34-37](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/gateway/authz.rego#L34-L37) | Pemanggilan `cerberus-exec` dengan path biner (`/usr/bin/kubectl`), traversal glob (`git/../../bin/sh`), atau symlink (`git -> /bin/sh`) menurunkan stage ke `generic` dan melewati `shellguard` karena argumen dikirim di `args.args` alih-alih `args.cmd`. | 1) `detectMode` (`main.go:136`) mencocokkan `sub` tanpa `filepath.Base`, sehingga `/usr/bin/kubectl` masuk ke mode `generic` (`stage: "tool"`), dan `buildPayload` (`main.go:167`) menaruh argumen di `args["args"]` (`[]string`), menyebabkan `checkShellGuard` (`engine.go:723`) melihat `args["cmd"] == ""` dan melewatkan pemeriksaan AST. 2) Di `authz.rego:35`, `glob.match(lower(pattern), [], lower(name))` memakai delimiter kosong `[]` sehingga pattern `git*` meloloskan `git/../../bin/sh`, yang kemudian di-join oleh `findRealBinary` (`main.go:477`) menjadi `/bin/sh`. 3) Selain itu, `findRealBinary` (`main.go:486`) hanya memanggil `EvalSymlinks` untuk mengecek `selfReal`, tanpa memverifikasi apakah symlink tujuan memiliki nama biner yang sama dengan `target`. | Normalisasi `sub` dengan `filepath.Base` serta tolak separator path/`..` pada nama tool, pastikan `filepath.Base(realCandidate) == target` pasca-`EvalSymlinks`, kirim string perintah gabungan ke `args.cmd` pada mode `generic`, dan gunakan delimiter `["/"]` pada `call_matches_pattern`. | **M** |
| **MC2-11** | **P1** | [internal/server/auth_handlers.go:30-48,72-73](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/auth_handlers.go#L30-L48)<br>[owl/app/api/auth/login/route.ts:9-12](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/app/api/auth/login/route.ts#L9-L12)<br>[internal/auth/lockout.go:35-40,70-93](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/auth/lockout.go#L70-L93) | Endpoint `/v1/auth/login` mempercayai header `X-Forwarded-For` / `X-Real-IP` tanpa validasi proxy tepercaya untuk kunci lockout `username@ip`, tidak membatasi ukuran map `attempts`, dan menjalankan Argon2id (64 MiB/req) tanpa batas konkurensi. | 1) `clientIP` (`auth_handlers.go:31`) mengambil elemen pertama `X-Forwarded-For` secara langsung untuk membentuk kunci lockout `username + "@" + ip`. 2) Klien yang merotasi nilai `X-Forwarded-For` pada setiap percobaan login tidak pernah mencapai ambang `maxAttempts` (5), memicu alokasi memori Argon2id 64 MiB secara paralel tanpa rate-limit dan menambah entri baru terus-menerus ke map `LockoutManager.attempts`. 3) Sebaliknya, pada Owl tanpa reverse proxy, `route.ts:11` memberi default `ip = "127.0.0.1"`, sehingga 5 percobaan gagal tanpa header `X-Forwarded-For` mengunci `"admin@127.0.0.1"` bagi seluruh pengguna Owl selama 15 menit. | Hanya percayai `X-Forwarded-For`/`X-Real-IP` jika `r.RemoteAddr` berasal dari CIDR proxy tepercaya, terapkan kunci lockout per-username disertai batas kapasitas LRU dan semaphore konkurensi sebelum verifikasi Argon2id. | **S** |
| **MC2-12** | **P1** | [internal/audit/logger.go:109,125,159-161,374-377](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/logger.go#L109-L125)<br>[internal/audit/sqlite.go:30-31,381-407](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/sqlite.go#L381-L407)<br>[cmd/cerberus-egress/main.go:52,122](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-egress/main.go#L52-L122) | Penomoran `ev.ID` menggunakan counter atomik in-memory `l.seq` yang di-seed satu kali saat startup (`SELECT MAX(id)`), sehingga dua proses yang menulis ke DB SQLite yang sama mengalami kolisi `PRIMARY KEY` dan kehilangan seluruh batch 256 event. | 1) Saat `cerberus` dan `cerberus-egress`/`cerberus-proxy` (mode `--standalone` dengan default `cerberus.db` yang sama) berjalan bersamaan, keduanya membaca `maxID` yang sama dari `audit-YYYYMMDD.db` saat inisialisasi `l.seq`. 2) Ketika kedua proses memanggil `Emit`, masing-masing menaikkan `l.seq.Add(1)` di memori lokal dan menghasilkan `ev.ID` yang identik. 3) Saat proses kedua menjalankan transaksi `insertBatchWithStmt` (`INSERT INTO events (id, ...) VALUES (?, ...)`), SQLite menolak transaksi karena `UNIQUE constraint failed: events.id`, dan `flush()` (`logger.go:374`) membuang seluruh slice `batch` (hingga 256 event) secara permanen. | Biarkan SQLite mengisi kolom `id INTEGER PRIMARY KEY` secara otomatis saat `INSERT` (atau gunakan `INSERT OR REPLACE` / UUID) alih-alih menetapkan `id` dari counter in-memory `l.seq` lintas proses. | **S** |
| **MC2-13** | **P1** | [sdk/python/cerberus_sdk/client.py:120-137,171-206,233-237](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/python/cerberus_sdk/client.py#L171-L206)<br>[sdk/go/client.go:106,145-160,190-195,279-286](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/go/client.go#L145-L160) | Cache keputusan lokal 60 detik di SDK Python & Go (`GuardedExecutor`) tidak menyertakan `key_id` atau `epoch` engine, mengembalikan referensi `masked_args` tanpa deep-copy, dan Python SDK tidak mendukung header `X-Agent-Key`. | 1) `CerberusClient` menyimpan hasil `allow` selama 60 detik dengan kunci `sha256(tool + "\x00" + json(args))` tanpa `key_id` dan tanpa mengecek perubahan `epoch` di server, sehingga aktivasi `kill_switch` atau pencabutan izin tidak berlaku pada panggilan tool yang sama selama 60 detik. 2) Cache mengembalikan pointer map `masked_args` yang sama ke fungsi tool; bila fungsi tool memodifikasi map argumen tersebut, isi cache berubah untuk pemanggilan berikutnya. 3) Selain itu, `CerberusClient` di Python (`client.py:120-137`) tidak memiliki parameter `agent_key` (`X-Agent-Key`), sehingga selalu ditolak 401/403 saat `CERBERUS_REQUIRE_AGENT_KEYS=true` atau `api_key_sha256` diaktifkan. | Matikan cache `allow` sisi klien secara default (atau sertakan `key_id` dalam kunci cache serta lakukan deep-copy pada `masked_args`), dan tambahkan dukungan header `X-Agent-Key` pada Python SDK. | **S** |
| **MC2-14** | **P2** | [internal/server/decide.go:66,70,87,149,176,197](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L66-L197)<br>[internal/ratelimit/limiter.go:173,232](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/ratelimit/limiter.go#L173-L232)<br>[internal/engine/engine.go:231](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/engine/engine.go#L231) | Handler `s.decide` memanggil `Store.Current()` hingga 7 kali secara terpisah dalam satu siklus request HTTP, sehingga reload policy di tengah request menyebabkan *snapshot tear* antara tahap autentikasi, rate-limit, dan evaluasi Rego. | 1) Request `/v1/decide` masuk pada Epoch $N$ dan melewati pengecekan `isElevatedKey`, `isExemptKey`, serta verifikasi `api_key_sha256` (`decide.go:66-116`). 2) Sebelum eksekusi mencapai `s.limiter.Allow` (baris 192) dan `Engine.Decide` (baris 259), admin memperbarui policy ke Epoch $N+1$ melalui `PUT /v1/admin/data`. 3) Request yang sama dievaluasi menggunakan atribut autentikasi dari Epoch $N$, kuota rate-limit dari Epoch $N+1$, dan aturan Rego dari Epoch $N+1$. | Ambil satu referensi `snap := s.deps.Store.Current()` di awal `s.decide` dan teruskan pointer snapshot tersebut ke seluruh fungsi autentikasi, rate-limiter, dan `Engine.Decide`. | **S** |
| **MC2-15** | **P2** | [owl/lib/session.ts:104-109](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/session.ts#L104-L109)<br>[owl/app/login/page.tsx:38](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/app/login/page.tsx#L38) | Fungsi `safeNext` di Owl hanya memeriksa prefix string `!next.startsWith("//")` dan `!next.startsWith("/\\")`, sehingga dapat di-bypass menggunakan karakter kontrol ASCII (`/%09/domain`) yang dihapus oleh parser URL browser saat redirect. | 1) Pengguna membuka halaman login Owl dengan parameter query `?next=/%09/evil.example` (di mana `%09` adalah karakter tab `\t`). 2) `safeNext` (`session.ts:104`) melihat string diawali `"/"`, bukan `"//"`, dan bukan `"/\\"`, sehingga mengembalikan string `"/\t/evil.example"`. 3) Setelah login berhasil, `login/page.tsx:38` menetapkan `window.location.href = next`; sesuai spesifikasi WHATWG URL di browser, karakter tab `\t` dihapus sebelum resolusi path sehingga browser menafsirkannya sebagai `//evil.example` (protocol-relative redirect ke domain eksternal). | Bersihkan karakter kontrol ASCII (`[\x00-\x1f\x7f]`) dan validasi menggunakan konstruktor `new URL(next, "http://localhost")` bahwa `url.origin === "http://localhost"` sebelum mengizinkan redirect di `safeNext`. | **S** |
| **MC2-16** | **P2** | [internal/server/decide.go:158-169](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L158-L169)<br>[internal/server/break_glass.go:144-153,169-173](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/break_glass.go#L144-L173) | Event audit saat break-glass aktif mengosongkan `Args` (`nil`) dan mengisi `Subject` hanya dengan `in.ToolCall` (kosong untuk stage `http`, `ssh`, `docker`, `db`, `llm`), serta tidak mencatat identitas admin maupun event deaktivasi. | 1) Saat break-glass aktif dan agen mengeksekusi query DB, koneksi SSH, container Docker, atau request HTTP, `decide.go:162` mencatat `Subject: in.ToolCall` (bernilai `""`) dan tidak menyertakan field `Args`. 2) Di `postBreakGlass` (`break_glass.go:147`), field `KeyID` diisi dengan target `req.KeyID` tanpa mencatat `UserFromContext(r.Context()).Username` yang mengaktifkannya. 3) Saat admin mematikan break-glass melalui `DELETE /v1/admin/break-glass` (`break_glass.go:169-173`), handler `deleteBreakGlass` tidak memanggil `Audit.Emit` sama sekali. | Gunakan helper `subject(in)` dan `auditArgsFor(in, d)` pada emisi audit break-glass di `s.decide`, serta catat username admin yang terautentikasi baik saat aktivasi (`POST`) maupun deaktivasi (`DELETE`) break-glass. | **S** |
| **MC2-17** | **P2** | [internal/server/admin.go:42-98,331-334,655-745,930-933,1107-1110](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/admin.go#L42-L98)<br>[internal/server/upstream_handlers.go:317-395](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/upstream_handlers.go#L317-L395) | Endpoint mutasi policy (`PUT /v1/admin/data`, `rotateKey`, `handleToggleAgentCapture`) tidak memeriksa versi epoch (`If-Match` / `X-Cerberus-Epoch`) dan melakukan read-modify-write di luar lock, serta mempercayai header `X-Admin-User` untuk atribusi revisi. | 1) Admin A dan Admin B membaca `GET /v1/admin/data` pada Epoch 10, atau `rotateKey` (`admin.go:697`) mengkloning `Store.Current().Data` di luar `Store.mu` bersamaan dengan admin lain yang mengaktifkan `kill_switch`. 2) Pemanggilan `ReplaceData` yang terakhir selesai akan menimpa seluruh objek `data.json` tanpa pengecekan epoch, menghapus perubahan yang baru saja disimpan. 3) Selain itu, `putData`, `rollbackData`, `rotateKey`, dan `rollbackBundle` mengambil nama penulis revisi dari header `r.Header.Get("X-Admin-User")` tanpa mencocokkannya dengan sesi `UserFromContext`. | Terapkan validasi optimistic concurrency (`If-Match` / `X-Cerberus-Epoch`) di dalam `Store.mu` untuk seluruh mutasi data policy dan selalu ambil identitas `author` dari `UserFromContext(r.Context()).Username`. | **S** |

---

## III. Jawaban Bernomor per 8 Area Audit

### Area 1: Race & Concurrency (`internal/policy`, `internal/engine`, `internal/ratelimit`, `internal/audit`, `internal/server/decide.go`)

1. **Atomisitas Snapshot & In-Flight Decide di dalam `Engine.Decide`**:
   - **CLOSED by `snap := e.store.Current()` atomic pointer load & `cacheKey(snap.Epoch, in)`** pada [internal/policy/store.go:22, 125](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/policy/store.go#L22-L125) dan [internal/engine/engine.go:231, 265](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/engine/engine.go#L231-L265). Begitu `s.ptr.Store(snap)` dieksekusi, setiap pemanggilan `Engine.Decide` baru membaca pointer `*Snapshot` baru yang bersifat immutable dan menyertakan `snap.Epoch` ke dalam hash kunci cache LRU sehingga hasil `allow` dari epoch lama tidak pernah dipakai ulang pada epoch baru.

2. **Temuan `MC2-14` (P2) — Inkonistensi Multi-Load Snapshot (*Snapshot Tear*) di Handler HTTP `s.decide`**:
   - **Lokasi:** [internal/server/decide.go:66, 70, 87, 149, 176, 197](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L66-L197), [internal/ratelimit/limiter.go:173, 232](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/ratelimit/limiter.go#L173-L232), dan [internal/engine/engine.go:231](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/engine/engine.go#L231).
   - **Kutipan Kode:**
     ```go
     // internal/server/decide.go:66, 70, 87
     func (s *Server) isElevatedKey(keyID string) bool {
         snap := s.deps.Store.Current()
     ...
     func (s *Server) isExemptKey(keyID string) bool {
         snap := s.deps.Store.Current()
     ...
     if snap := s.deps.Store.Current(); snap != nil {
         expectedHash = lookupAgentKeySHA256(snap.Data, in.KeyID)
     }
     ```
   - **Skenario Step-by-Step:**
     1. Sebuah request `POST /v1/decide` masuk pada saat policy berada di Epoch $N$.
     2. Handler `s.decide` memanggil `s.deps.Store.Current()` secara terpisah pada baris 66 (`isElevatedKey`), baris 70 (`isExemptKey`), dan baris 87 (`lookupAgentKeySHA256`) menggunakan data Epoch $N$.
     3. Tepat sebelum baris 192 (`s.limiter.Allow`) dan baris 259 (`s.deps.Engine.Decide`), admin melakukan push policy baru (Epoch $N+1$) yang mengubah status autentikasi key atau konfigurasi tim.
     4. `s.limiter.Allow` dan `Engine.Decide` memanggil `Store.Current()` lagi dan mendapatkan snapshot Epoch $N+1$, sehingga satu request dievaluasi dengan kombinasi aturan autentikasi Epoch $N$ dan aturan policy Epoch $N+1$.
   - **Fix (1 Kalimat):** Ambil satu referensi `snap := s.deps.Store.Current()` di awal `s.decide` dan teruskan pointer snapshot tersebut ke seluruh fungsi autentikasi, rate-limiter, dan `Engine.Decide`.

3. **Temuan `MC2-05` (P1) — Wipe Total State Rate-Limiter saat Policy Swap & Pengurangan Kuota oleh Request yang Ditolak**:
   - **Lokasi:** [internal/ratelimit/limiter.go:152-166, 279-286, 444-498](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/ratelimit/limiter.go#L152-L166) dan [internal/server/decide.go:192, 259](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L192-L259).
   - **Kutipan Kode:**
     ```go
     // internal/ratelimit/limiter.go:152-155, 281-285
     l.cancelSwap = store.OnSwap(func(snap *policy.Snapshot) {
         l.Reset(snap.Epoch)
     })
     ...
     func (l *Limiter) Reset(newEpoch uint64) {
         l.mu.Lock()
         defer l.mu.Unlock()
         l.keys = make(map[string]*keyLimiter)
         l.teams = make(map[string]*teamLimiter)
         l.epoch = newEpoch
     }
     ```
   - **Skenario Step-by-Step:**
     1. Setiap kali terjadi reload policy (`POST /v1/admin/reload`), update data (`PUT /v1/admin/data`), rotasi key, atau sekadar toggle flag capture privasi agen (`POST /v1/admin/agents/{keyId}/capture`), callback `store.OnSwap` mengeksekusi `l.Reset(snap.Epoch)`.
     2. `l.Reset` mengalokasikan ulang map `l.keys` dan `l.teams` menjadi kosong, sehingga seluruh bucket RPM (`reqBucket`), bucket tool per jam (`toolBucket`), dan akumulasi pemakaian anggaran USD harian (`spendUSD`) kembali ke nol.
     3. Sebaliknya, pada [internal/server/decide.go:192](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L192), `s.limiter.Allow` dipanggil **sebelum** `s.deps.Engine.Decide` (baris 259), dan di dalam `limiter.go:488, 496` langsung mengeksekusi `kl.dailyCount++` serta `tl.dailyCount++`. Akibatnya, request tool yang akhirnya ditolak (`deny`) oleh policy Rego tetap menghabiskan jatah kuota harian di memori.
     4. Selain itu, saat `dailyChecked` bernilai `false` (pasca-`Reset` atau pergantian hari), goroutine konkuren melepas mutex untuk memanggil `l.countToolCallsToday` ke SQLite (yang memiliki jeda flush 200ms) lalu menimpa `kl.dailyCount = count` (`limiter.go:462`), sehingga burst panggilan konkuren pada awal epoch tidak terhitung secara akurat.
   - **Fix (1 Kalimat):** Pertahankan state token bucket dan `spendUSD` lintas epoch pada `OnSwap` (hanya perbarui parameter limit), sinkronkan inisialisasi kuota SQLite di dalam lock, dan hanya inkremen kuota tool harian setelah `Engine.Decide` menghasilkan `allow`.

4. **Temuan `MC2-06` (P1) — Starvasi & Kehilangan Event Audit Akibat Banjir Emisi 429 pada Channel Non-Blocking**:
   - **Lokasi:** [internal/audit/logger.go:85-87, 154-168](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/logger.go#L154-L168) dan [internal/server/decide.go:205-216](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L205-L216).
   - **Kutipan Kode:**
     ```go
     // internal/audit/logger.go:85-87, 161-166
     const (
         chanCapacity = 4096
         flushTick    = 200 * time.Millisecond
     )
     ...
     select {
     case l.ch <- ev:
     default:
         Dropped.Inc()
     }
     ```
   - **Skenario Step-by-Step:**
     1. Ketika sebuah agen mencapai batas rate-limit, setiap request berikutnya ditolak di memori pada `decide.go:192` dan langsung memanggil `s.deps.Audit.Emit` dengan `RuleID: "ops.rate_limited"` pada `decide.go:206`.
     2. Karena penolakan di memori berlangsung dalam hitungan nanodetik sedangkan worker SQLite (`flushLoop`) menguras `l.ch` per batch 256 event atau setiap 200ms, lebih dari 4.096 respons 429 dalam satu jendela 200ms akan memenuhi `l.ch`.
     3. Begitu `l.ch` penuh, cabang `default:` di `logger.go:164` membuang seluruh event baru yang masuk ke `Emit`, termasuk event administratif (`admin.*`), aktivasi `ops.break_glass`, maupun event `allow` yang dibutuhkan SQLite untuk menghitung kuota harian.
   - **Fix (1 Kalimat):** Terapkan throttling/sampling per-key untuk emisi event audit `ops.rate_limited` (429) dan pisahkan jalur antrean prioritas non-drop untuk event `admin.*`, `auth.*`, serta `ops.break_glass`.

---

### Area 2: Docker Stage (`policies/stages/docker.rego` + `internal/proxy/docker.go`)

1. **Pemeriksaan Flag `privileged` & `cap_add: ["ALL"]` pada Input Rego Langsung**:
   - **CLOSED in Rego direct input by `privileged_container` (`args.privileged == true` / `"true"` / `1` & `upper(cap) == "ALL"`)** pada [policies/stages/docker.rego:134-156](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L134-L156) (namun **TERBUKA pada layer `DockerProxy`** — lihat `MC2-02` di bawah).

2. **Temuan `MC2-01` (P0) — Bypass `mount_host_root` melalui Sub-Path (`/etc/shadow`, `/etc/`), Path Traversal, & Direktori Host yang Absen**:
   - **Lokasi:** [policies/stages/docker.rego:84-100](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L84-L100).
   - **Kutipan Kode:**
     ```rego
     mount_host_root if {
         some mount in args.binds
         is_string(mount)
         regex.match(`(?i)^(/|/Users|/private|/var|/etc|/bin|/sbin|/usr)(:|$)`, mount)
     }

     mount_host_root if {
         some mount in args.mounts
         is_object(mount)
         regex.match("(?i)^(/|/Users|/private|/var|/etc|/bin|/sbin|/usr)$", object.get(mount, "source", ""))
     }
     ```
   - **Skenario Step-by-Step:**
     1. Pemanggil mengirim request evaluasi `stage: "docker"` dengan `args.binds: ["/etc/shadow:/mnt:ro"]`, `["/etc/:/mnt"]`, atau `["/Users/admin/.ssh:/mnt"]` (atau melalui objek `args.mounts` dengan `"source": "/etc/sudoers"`).
     2. Rego mengevaluasi regex `^(...)(:|$)` pada `args.binds` dan `^(...)$` pada `args.mounts[].source`.
     3. Karena terdapat karakter `/` dan nama sub-direktori/berkas setelah `/etc` atau `/Users` sebelum tanda `:`, anchor `(:|$)` dan `$` gagal cocok.
     4. Selain itu, direktori host sensitif seperti `/root`, `/home`, `/proc`, `/sys`, dan `/dev` tidak tercantum sama sekali di dalam daftar alternatif regex, sehingga mount direktori tersebut langsung diizinkan (`docker.allow`).
   - **Fix (1 Kalimat):** Ubah regex `mount_host_root` agar mencocokkan sub-path (`(/.*)?(:|$)`) setelah normalisasi path dan tambahkan `/root`, `/home`, `/proc`, `/sys`, serta `/dev` ke daftar prefix terlarang.

3. **Temuan `MC2-02` (P0) — Bypass Pemeriksaan Image, Privileged, Binds, dan Host Namespace (`--pid=host`) pada `DockerProxy`**:
   - **Lokasi:** [internal/proxy/docker.go:217-227, 295-346](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/proxy/docker.go#L217-L346) dan [policies/stages/docker.rego:159-165](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L159-L165).
   - **Kutipan Kode:**
     ```go
     // internal/proxy/docker.go:220-226, 296-339
     if img, ok := bodyMap["Image"].(string); ok {
         resource = img
     }
     p.extractHostConfig(bodyMap, args)
     ...
     if hc, ok := body["HostConfig"].(map[string]any); ok {
         if binds, ok := hc["Binds"].([]any); ok { ... }
         if mounts, ok := hc["Mounts"].([]any); ok { ... }
         if capAdd, ok := hc["CapAdd"].([]any); ok { ... }
         if priv, ok := hc["Privileged"].(bool); ok { ... }
     }
     ```
   - **Skenario Step-by-Step:**
     1. Klien mengirim `POST /v1.43/containers/create` ke `DockerProxy` dengan field `HostConfig` berisi `"PidMode": "host"`, `"NetworkMode": "host"`, atau `"IpcMode": "host"`.
     2. Fungsi `extractHostConfig` di [internal/proxy/docker.go:295-346](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/proxy/docker.go#L295-L346) hanya mengekstrak `Binds`, `Mounts`, `CapAdd`, dan `Privileged`, serta mengabaikan `PidMode`, `NetworkMode`, dan `IpcMode`. Akibatnya, aturan `host_namespace_forbidden` di `docker.rego:108-131` tidak pernah terpicu.
     3. Lebih jauh lagi, apabila klien mengirim key JSON dengan huruf kecil seperti `"image": "untrusted:latest"` dan `"hostconfig": {"privileged": true, "binds": ["/:/host"]}`, lookup map Go yang case-sensitive pada `bodyMap["Image"]` dan `body["HostConfig"]` menghasilkan nilai kosong.
     4. Karena `resource` (`image`) bernilai `""`, kondisi `image != ""` pada `image_not_allowed` ([policies/stages/docker.rego:160](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L160)) bernilai `false` (skip allowlist), sementara daemon Docker upstream (`encoding/json` ke struct Go) mem-parsing key `"image"` dan `"hostconfig"` secara case-insensitive dan membuat container privileged tersebut.
   - **Fix (1 Kalimat):** Unmarshal payload request Docker API ke struct Go bertipe kuat (case-insensitive), wajibkan `image != ""` pada aksi `create`/`run` di `docker.rego`, dan ekstrak `PidMode`, `NetworkMode`, `IpcMode`, `Devices`, serta `SecurityOpt` ke dalam `args`.

4. **Temuan `MC2-07` (P1) — Kebingungan Sintaks `tag@sha256:digest` pada `allowed_images` & False-Deny 100% Aksi Container Non-Create di `DockerProxy`**:
   - **Lokasi:** [policies/stages/docker.rego:13, 159-180](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L159-L180), [policies/gateway/authz.rego:68-82](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/gateway/authz.rego#L68-L82), dan [internal/proxy/docker.go:228-253](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/proxy/docker.go#L228-L253).
   - **Kutipan Kode:**
     ```rego
     // policies/stages/docker.rego:159-165
     image_not_allowed if {
         image != ""
         not action in ["rm", "rmi", "delete", "down", "stop", "kill"]
         image_allowlist_configured
         not image_allowed
     }
     ```
     ```go
     // internal/proxy/docker.go:228-235
     case len(segments) >= 3 && segments[0] == "containers":
         containerID := segments[1]
         resource = containerID
         switch subAction {
         case "start": action = "start"
     ```
   - **Skenario Step-by-Step:**
     1. Ketika policy mendefinisikan `allowed_images: ["nginx:*"]`, fungsi `authz.pattern_matches` memanggil `glob.match("nginx:*", [], lower(target))` dengan slice delimiter kosong `[]`.
     2. Input image berupa `"nginx:latest@sha256:<digest_image_berbeda>"` dinyatakan cocok oleh wildcard `*`, padahal spesifikasi OCI/Docker Engine menginstruksikan daemon untuk mengabaikan tag `:latest` dan menjalankan image berdasarkan `@sha256:<digest>` apabila keduanya disertakan.
     3. Sebaliknya, untuk operasi manajemen container yang sedang berjalan (`start`, `restart`, `exec_create`, `logs`, `inspect`), `DockerProxy` mengisi `resource` (`image`) dengan `containerID` (misal `"c8f92d1a..."`).
     4. Karena `docker.rego:161` hanya mengecualikan `["rm", "rmi", "delete", "down", "stop", "kill"]`, aksi `start`, `restart`, `exec_create`, dan `logs` dievaluasi terhadap `allowed_images`, sehingga ID container gagal cocok dengan pattern image dan menghasilkan false-deny `docker.image_not_allowed`.
   - **Fix (1 Kalimat):** Pisahkan komponen repositori, tag, dan digest `@sha256:` dengan delimiter `["/", ":", "@"]` saat memvalidasi `allowed_images`, serta batasi aturan `image_not_allowed` hanya pada aksi berbasis image (`create`, `run`, `pull`, `build`).

---

### Area 3: OWL Web (`owl/middleware.ts`, `owl/lib/session.ts`, `owl/lib/engine.ts`, `owl/app/api/*`)

1. **Timing Attack & Padding/Signature Oracle pada Verifikasi HMAC Cookie**:
   - **CLOSED for timing/oracle by `crypto.subtle.verify("HMAC", ...)` & SHA-256 digest comparison** pada [owl/lib/session.ts:76, 84, 90-100](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/session.ts#L76-L100) serta `subtle.ConstantTimeCompare` pada [internal/server/middleware.go:258](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/middleware.go#L258) (namun kerentanan muncul pada secret default dan ketiadaan validasi sesi di `openEventStream` — lihat `MC2-08`).

2. **Temuan `MC2-08` (P1) — Hardcoded Default `OWL_SESSION_SECRET`, Eskalasi Token Master pada `/api/events`, & CSRF pada Endpoint Admin Cookie (Termasuk Global Break-Glass)**:
   - **Lokasi:** [owl/lib/session.ts:70-115](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/session.ts#L70-L115), [owl/lib/engine.ts:53-67, 218-226](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/engine.ts#L218-L226), [owl/app/api/admin/break-glass/route.ts:16-24](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/app/api/admin/break-glass/route.ts#L16-L24), [internal/server/middleware.go:82-98, 145-149](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/middleware.go#L82-L98), dan [internal/server/break_glass.go:38-40, 119-136](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/break_glass.go#L119-L136).
   - **Kutipan Kode:**
     ```ts
     // owl/lib/session.ts:113-115
     function getSessionSecret(): string {
       const secret = process.env.OWL_SESSION_SECRET || "owl-session-secret-cerberus-production-grade-32b";
       return secret;
     }
     ```
     ```ts
     // owl/lib/engine.ts:218-226
     export async function openEventStream(lastEventId?: string | null): Promise<Response> {
       const { url, token } = engineEnv();
       ...
       res = await fetch(`${url}/v1/events`, {
         headers: { Authorization: `Bearer ${token}` },
     ```
     ```go
     // internal/server/middleware.go:86-90
     func needsJSONBody(r *http.Request) bool {
         if r.URL.Path == "/v1/admin/bundle" { return false }
         return (r.Method == http.MethodPost || r.Method == http.MethodPut) && r.ContentLength != 0
     }
     ```
   - **Skenario Step-by-Step:**
     1. **Default Secret & Replay Sesi Tercabut di `/api/events`:** Bila `OWL_SESSION_SECRET` tidak dikonfigurasi di environment, Owl menggunakan string hardcoded `"owl-session-secret-cerberus-production-grade-32b"`. Karena `owl/middleware.ts` hanya memeriksa tanda tangan HMAC cookie dan `openEventStream` (`owl/lib/engine.ts:218`) memanggil `/v1/events` menggunakan master `CERBERUS_ADMIN_TOKEN` (bukan `getActiveAuthToken()`), cookie hasil tanda tangan secret default — atau cookie yang sesinya sudah dicabut via logout/disable di DB sebelum masa aktif 12 jam habis — tetap dapat membuka stream live audit SSE `/api/events`.
     2. **CSRF pada Owl `/api/admin/*`:** Route mutasi di Owl (`POST /api/admin/break-glass`, `POST /api/admin/rollback`, `POST /api/admin/bundle/rollback`, `POST /api/policy/reload`, `POST /api/admin/keys/[keyId]/rotate`) tidak memvalidasi header `Origin`/`Referer` maupun token CSRF, dan memanggil `await req.json()` tanpa memeriksa `Content-Type: application/json`.
     3. **CSRF Aktivasi Global Break-Glass pada Engine `:8089`:** Middleware `s.admin` di Engine menerima cookie `owl_session` (`middleware.go:145`), dan fungsi `needsJSONBody` (`middleware.go:89`) melewati pemeriksaan `Content-Type: application/json` apabila `r.ContentLength == 0`. Jika request `POST /v1/admin/break-glass` dikirim tanpa body (`Content-Length: 0`), `postBreakGlass` (`break_glass.go:125`) melewati dekode JSON dengan `req.KeyID == ""` dan `req.TTLSeconds == 0`, yang oleh `Activate` (`break_glass.go:38`) diterjemahkan sebagai **aktivasi global break-glass untuk seluruh agen selama 15 menit**.
   - **Fix (1 Kalimat):** Wajibkan `OWL_SESSION_SECRET` non-default saat startup, gunakan `getActiveAuthToken` pada `openEventStream`, dan validasi header `Origin` serta `Content-Type: application/json` pada seluruh endpoint mutasi (termasuk saat `ContentLength == 0`).

3. **Temuan `MC2-15` (P2) — Open Redirect melalui Karakter Kontrol (`/%09/domain`) pada `safeNext`**:
   - **Lokasi:** [owl/lib/session.ts:104-109](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/session.ts#L104-L109) dan [owl/app/login/page.tsx:38](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/app/login/page.tsx#L38).
   - **Kutipan Kode:**
     ```ts
     // owl/lib/session.ts:104-109
     export function safeNext(next: string | null | undefined): string {
       if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\") || next === "/") {
         return "/overview";
       }
       return next;
     }
     ```
   - **Skenario Step-by-Step:**
     1. Parameter query `next` pada `/login?next=/%09/evil.example` didekode menjadi string `"/\t/evil.example"`.
     2. Fungsi `safeNext` memeriksa `!next.startsWith("//")` dan `!next.startsWith("/\\")` yang keduanya bernilai `true` karena karakter kedua adalah `\t` (`0x09`).
     3. Setelah autentikasi berhasil, `login/page.tsx:38` mengeksekusi `window.location.href = next`; parser URL browser menghapus karakter tab ASCII sesuai standar WHATWG sehingga `"/\t/evil.example"` menjadi `"//evil.example"` dan mengalihkan browser ke domain eksternal `evil.example`.
   - **Fix (1 Kalimat):** Bersihkan karakter kontrol ASCII (`[\x00-\x1f\x7f]`) dan validasi menggunakan konstruktor `new URL(next, "http://localhost")` bahwa `url.origin === "http://localhost"` sebelum mengizinkan redirect di `safeNext`.

---

### Area 4: Break-Glass (`internal/server/break_glass.go` & `internal/server/decide.go`)

1. **Temuan `MC2-09` (P1) — Break-Glass Mem-bypass `kill_switch`, `tainted_exfil`, `shellguard`, Secret Masking, dan Seluruh `prod_shield` + Jendela 15 Menit Tanpa Autentikasi**:
   - **Lokasi:** [internal/server/decide.go:119-172](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L119-L172) dan [internal/server/break_glass.go:31-46, 60-70](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/break_glass.go#L31-L70).
   - **Kutipan Kode:**
     ```go
     // internal/server/decide.go:127-147
     if s.breakGlass != nil && s.breakGlass.IsActive(in.KeyID) {
         breakGlassActive = true
         breakGlassReason = s.breakGlass.Reason(in.KeyID)
     } else if bgHeader != "" && s.hasValidAdminToken(r) {
         breakGlassActive = true
         ...
         if s.breakGlass != nil {
             s.breakGlass.Activate(in.KeyID, 15*time.Minute, breakGlassReason)
         }
     }
     if breakGlassActive {
         ...
         d := engine.Decision{
             Decision: "allow",
             RuleID:   "ops.break_glass",
             Reason:   "BREAK-GLASS EMERGENCY BYPASS: " + breakGlassReason,
             Epoch:    epoch,
         }
         ...
         writeJSON(w, http.StatusOK, d)
         return
     }
     ```
   - **Skenario Step-by-Step:**
     1. Karena blok `if breakGlassActive` di `decide.go:147-172` langsung melakukan `return` sebelum `s.limiter.Allow` dan `s.deps.Engine.Decide`, mode break-glass mematikan **seluruh** lapisan evaluasi engine: tidak hanya aturan stage dan `prod_shield` (termasuk blokir IP metadata `169.254.169.254` dan loopback di `http.rego`), tetapi juga **`kill_switch`**, **`chain.tainted_exfil`**, **`shellguard`**, serta **penyensoran rahasia (`MaskedArgs` dan `MaskedPrompt` bernilai `nil`)**.
     2. Apabila satu request dikirim dengan header `X-Break-Glass` dan token admin, baris 140 otomatis memanggil `s.breakGlass.Activate(in.KeyID, 15*time.Minute, ...)` yang membuka jendela bypass stateful selama 15 menit (dan bahkan menimpa TTL yang lebih pendek jika sebelumnya diatur via API admin).
     3. Selama jendela 15 menit tersebut, `s.breakGlass.IsActive(in.KeyID)` pada baris 127 bernilai `true` terlebih dahulu tanpa memeriksa `hasValidAdminToken(r)`. Jika global break-glass aktif (`*` atau `""`) atau `in.KeyID` merupakan key non-elevated yang tidak memiliki `api_key_sha256`, pemanggil tanpa kredensial header apa pun pada `/v1/decide` otomatis memperoleh `allow`.
   - **Fix (1 Kalimat):** Tetap jalankan pemeriksaan `kill_switch`, blokir IP link-local/loopback, dan secret masking saat break-glass aktif, wajibkan autentikasi agen/admin yang valid pada setiap request break-glass, dan jangan perpanjang TTL otomatis dari header `/v1/decide`.

2. **Temuan `MC2-16` (P2) — Blindspot Forensik Audit pada Event Break-Glass**:
   - **Lokasi:** [internal/server/decide.go:158-169](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/decide.go#L158-L169) dan [internal/server/break_glass.go:144-153, 169-173](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/break_glass.go#L144-L173).
   - **Kutipan Kode:**
     ```go
     // internal/server/decide.go:158-169
     s.deps.Audit.Emit(audit.Event{
         Time:     time.Now(),
         Stage:    in.Stage,
         KeyID:    in.KeyID,
         Subject:  in.ToolCall,
         Decision: "allow",
         RuleID:   "ops.break_glass",
         Reason:   d.Reason,
         Epoch:    epoch,
         Latency:  time.Since(start),
     })
     ```
   - **Skenario Step-by-Step:**
     1. Saat break-glass menghasilkan keputusan `allow` di `decide.go:158-169`, `Subject` diisi secara statis dengan `in.ToolCall` (yang bernilai string kosong `""` untuk stage `http`, `ssh`, `docker`, `db`, dan `llm`) dan field `Args` dikosongkan (`nil`), sehingga log audit tidak merekam URL, host SSH, image Docker, maupun query SQL yang dieksekusi selama masa darurat.
     2. Pada `postBreakGlass` (`break_glass.go:144-153`), event `admin.break_glass` hanya mencatat target `KeyID: req.KeyID` tanpa merekam identitas akun admin (`UserFromContext`) yang memicunya.
     3. Pada `deleteBreakGlass` (`break_glass.go:169-173`), pencabutan status break-glass tidak memanggil `Audit.Emit` sama sekali.
   - **Fix (1 Kalimat):** Gunakan helper `subject(in)` dan `auditArgsFor(in, d)` pada emisi audit break-glass di `s.decide`, serta catat username admin yang terautentikasi baik saat aktivasi (`POST`) maupun deaktivasi (`DELETE`) break-glass.

---

### Area 5: `cerberus-exec` Tool Path (`cmd/cerberus-exec/main.go`, `internal/engine/engine.go`, `pkg/shellguard`)

1. **Injeksi `LD_PRELOAD` / `BASH_ENV` melalui String Perintah yang Masuk ke `shellguard`**:
   - **CLOSED inside `shellguard` AST parser by `dangerousEnvVars` & `checkNode` (`ast.CallExpr.Assigns`)** pada [pkg/shellguard/ast_guard.go:25-32, 130-137](file:///Users/nicholasandriansurjadi/Documents/cerberus/pkg/shellguard/ast_guard.go#L25-L32) untuk perintah yang dievaluasi oleh `shellguard` (namun `shellguard` sendiri ter-bypass pada mode `generic` di `cerberus-exec` — lihat `MC2-10`).

2. **Temuan `MC2-03` (P0) — Bypass Parser Flag & Multi-Argumen pada `cerberus-exec` (`psql`, `mysql`, `kubectl`, `ssh`)**:
   - **Lokasi:** [cmd/cerberus-exec/main.go:181-230, 262-326, 361-395](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-exec/main.go#L181-L395).
   - **Kutipan Kode:**
     ```go
     // cmd/cerberus-exec/main.go:286-290 (buildDBPayload)
     case arg == "-c" || arg == "--command":
         if i+1 < len(args) {
             i++
             sql = args[i]
         }
     ```
     ```go
     // cmd/cerberus-exec/main.go:376-379 (buildSSHPayload)
     case strings.HasPrefix(arg, "-"):
         if arg == "-i" || arg == "-o" || arg == "-F" {
             i++
         }
     ```
   - **Skenario Step-by-Step:**
     1. **Database (`psql` / `mysql`):** Dalam `buildDBPayload` (`main.go:286-318`), setiap kemunculan flag `-c`, `-f`, atau `-e` menimpa variabel tunggal `sql = args[i]`, dan flag `-h`/`--host` diabaikan seluruhnya. Apabila `psql` dipanggil dengan dua flag `-c` (perintah pertama destruktif, perintah kedua `SELECT 1 LIMIT 1`), hanya argumen `-c` terakhir yang dikirim ke `/v1/decide` dan diizinkan oleh engine, sementara biner `psql` asli mengeksekusi kedua argumen `-c` secara berurutan.
     2. **Kubernetes (`kubectl`):** Dalam `buildK8sPayload` (`main.go:220-230`), beberapa flag `-f` juga saling menimpa variabel `manifest`, dan jika ukuran berkas manifest melebihi 64KB (`len(data) <= 64*1024`), isi berkas tidak dibaca sehingga `manifest` hanya berisi nama berkas dan melewati pemeriksaan `k8s.privilege_escalation` di `k8s.rego`.
     3. **SSH (`ssh`):** Dalam `buildSSHPayload` (`main.go:361-395`), flag `-o` dan `-F` hanya dilompati tanpa memeriksa opsi eksekusi perintah lokal seperti `ProxyCommand` atau `LocalCommand`; flag yang menempel tanpa spasi (`-p2222`, `-lroot`) tidak dikenali sehingga port tetap dianggap 22; dan flag berargumen seperti `-J` (`ProxyJump`) tidak mengonsumsi argumen berikutnya sehingga argumen jump-host dianggap sebagai `host` tujuan sedangkan target sebenarnya dianggap sebagai remote command.
   - **Fix (1 Kalimat):** Gabungkan atau evaluasi seluruh argumen `-c`/`-e`/`-f` (serta tolak manifest >64KB dan validasi `-h`), blokir opsi berbahaya (`-o ProxyCommand`, `-o LocalCommand`, `-F`, `-J`) di `buildSSHPayload`, dan tangani flag pendek yang menempel (`-p`, `-l`, `-c`, `-e`, `-f`).

3. **Temuan `MC2-10` (P1) — Downgrade Stage via Path Biner, Pengabaian `shellguard` pada Mode Generic, Traversal Glob `allowed_tool_calls`, & Symlink Spoofing**:
   - **Lokasi:** [cmd/cerberus-exec/main.go:118-170, 467-496](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-exec/main.go#L118-L170), [internal/engine/engine.go:683-798](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/engine/engine.go#L683-L798), dan [policies/gateway/authz.rego:34-37](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/gateway/authz.rego#L34-L37).
   - **Kutipan Kode:**
     ```go
     // cmd/cerberus-exec/main.go:136-149, 162-169
     switch sub {
     case "kubectl", "cerberus-kubectl":
         return "k8s", "kubectl", remaining
     ...
     default:
         return "generic", sub, remaining
     }
     ...
     return map[string]any{
         "stage":     "tool",
         "key_id":    keyID,
         "tool_call": tool,
         "args":      map[string]any{"args": args},
     }
     ```
     ```rego
     // policies/gateway/authz.rego:34-37
     call_matches_pattern(pattern, name) if {
         contains(pattern, "*")
         glob.match(lower(pattern), [], lower(name))
     }
     ```
   - **Skenario Step-by-Step:**
     1. **Downgrade Stage & Bypass `shellguard`:** `detectMode` (`main.go:136`) mencocokkan `sub` secara literal tanpa `filepath.Base(sub)`. Pemanggilan dengan path seperti `/usr/bin/kubectl` atau `/bin/sh` jatuh ke mode `generic` (`stage: "tool"`). Selanjutnya, `buildPayload` (`main.go:167`) menaruh daftar argumen di dalam `args["args"]` (`[]string`), sementara `Engine.checkShellGuard` (`engine.go:723-733`) hanya mencari string pada key `cmd`, `command`, `script`, `code`, `bash`, `sh`, atau `exec`. Akibatnya, `cmdStr` bernilai `""` dan `shellguard` tidak pernah dijalankan untuk tool generic maupun argumen berbahaya seperti `git -c core.pager=sh`.
     2. **Path Traversal pada Glob `allowed_tool_calls`:** Pada `authz.rego:36`, `glob.match` dipanggil dengan delimiter kosong `[]` sehingga `*` cocok dengan `/`. Jika agen memiliki `allowed_tool_calls: ["git*"]`, nama tool `"git/../../bin/sh"` lolos evaluasi Rego, lalu `findRealBinary` (`main.go:477`) mengeksekusi `filepath.Join(dir, "git/../../bin/sh")` yang diselesaikan oleh OS menjadi `/bin/sh`.
     3. **Symlink Target Spoofing:** Pada `findRealBinary` (`main.go:486-490`), `filepath.EvalSymlinks(candidate)` hanya dipakai untuk memastikan target bukan biner `cerberus-exec` itu sendiri (`realCandidate == selfReal`), tanpa memeriksa apakah `filepath.Base(realCandidate)` masih sesuai dengan `target` yang diizinkan policy.
   - **Fix (1 Kalimat):** Normalisasi `sub` dengan `filepath.Base` serta tolak separator path/`..` pada nama tool, pastikan `filepath.Base(realCandidate) == target` pasca-`EvalSymlinks`, kirim string perintah gabungan ke `args.cmd` pada mode `generic`, dan gunakan delimiter `["/"]` pada `call_matches_pattern`.

---

### Area 6: Engine Admin API (`internal/server/*`, `internal/auth/*`)

1. **Temuan `MC2-04` (P0) — Eskalasi Privilege `role: "viewer"` ke Plaintext Upstream LLM API Key, Data Mentah Tanpa Masking, & SSRF Internal**:
   - **Lokasi:** [internal/server/middleware.go:118-137, 184-189](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/middleware.go#L118-L137), [internal/server/upstream_handlers.go:123-272](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/upstream_handlers.go#L123-L272), dan [internal/server/admin.go:42-50, 1357-1440](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/admin.go#L42-L50).
   - **Kutipan Kode:**
     ```go
     // internal/server/middleware.go:118-136, 184-188
     func isMutatingAdminRequest(r *http.Request) bool {
         if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
             return false
         }
         path := r.URL.Path
         if path == "/v1/query" ||
             path == "/v1/admin/policy/test" ||
             path == "/v1/admin/decisions/explain" ||
             path == "/v1/admin/upstream/test" {
             return false
         }
         return true
     }
     ```
     ```go
     // internal/server/upstream_handlers.go:268-271
     writeJSON(w, http.StatusOK, map[string]any{
         "provider": cfg.Provider,
         "base_url": cfg.BaseURL,
         "api_key":  cfg.APIKey,
     })
     ```
   - **Skenario Step-by-Step:**
     1. Middleware `s.admin` mengizinkan pengguna dengan `role: "viewer"` mengakses seluruh endpoint yang dianggap non-mutasi oleh `isMutatingAdminRequest`.
     2. Pengguna `viewer` yang memanggil `GET /v1/internal/upstream` akan dilayani oleh `handleGetInternalUpstream` (`upstream_handlers.go:240-272`) yang mendekripsi kunci AES-GCM dari SQLite dan mengembalikan plaintext `api_key` LLM upstream.
     3. Pengguna `viewer` yang memanggil `GET /v1/admin/data` (`admin.go:42-50`, yang juga di-proxy oleh `GET /api/data` di Owl) menerima seluruh struktur `snap.Data` mentah tanpa penyensoran `redactSecretKeys` maupun `apiDataMaskRules`, atau dapat mengekstraknya melalui `POST /v1/query` (`admin.go:1357`).
     4. Pengguna `viewer` yang memanggil `POST /v1/admin/upstream/test` (`upstream_handlers.go:123-224`) dapat memasukkan `base_url` internal (seperti `http://169.254.169.254/latest/meta-data/` atau `http://127.0.0.1:8090/tap/turns`) untuk memicu request HTTP GET dari server engine tanpa melewati proteksi IP `cerberus-egress`.
   - **Fix (1 Kalimat):** Batasi `/v1/internal/upstream` hanya untuk `isMasterAdmin` (`CERBERUS_ADMIN_TOKEN`), wajibkan `auth.RoleAdmin` pada `/v1/admin/upstream/test` dan `/v1/query` (disertai validasi IP egress), serta terapkan `redactSecretKeys` pada `GET /v1/admin/data`.

2. **Temuan `MC2-11` (P1) — Bypass Lockout `/v1/auth/login`, DoS Lockout Pengguna Owl, & Exhaustion Memori/CPU Argon2id via Spoofing `X-Forwarded-For`**:
   - **Lokasi:** [internal/server/auth_handlers.go:30-48, 72-73](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/auth_handlers.go#L30-L48), [owl/app/api/auth/login/route.ts:9-12](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/app/api/auth/login/route.ts#L9-L12), dan [internal/auth/lockout.go:35-40, 70-93](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/auth/lockout.go#L70-L93).
   - **Kutipan Kode:**
     ```go
     // internal/server/auth_handlers.go:30-39, 72
     func clientIP(r *http.Request) string {
         if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
             parts := strings.Split(xff, ",")
             if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
                 return strings.TrimSpace(parts[0])
             }
         }
     ...
     lockKey := req.Username + "@" + ip
     ```
   - **Skenario Step-by-Step:**
     1. Fungsi `clientIP` di Engine maupun Owl mempercayai nilai pertama dari header `X-Forwarded-For` yang dikirim klien untuk membentuk kunci `lockKey := req.Username + "@" + ip`.
     2. Dengan mengganti nilai header `X-Forwarded-For` pada setiap request `POST /v1/auth/login`, batas 5 percobaan pada `LockoutManager` tidak pernah tercapai, map `LockoutManager.attempts` tumbuh tanpa batas kapasitas (memory leak), dan setiap request memicu komputasi paralel `VerifyPassword` Argon2id (alokasi memori 64 MiB per request di `internal/auth/store.go:31`).
     3. Sebaliknya, pada deployment Owl tanpa reverse proxy di depannya, `owl/app/api/auth/login/route.ts:11` memberikan nilai fallback `ip = "127.0.0.1"` dan meneruskannya ke Engine sebagai `X-Forwarded-For: 127.0.0.1`. Akibatnya, 5 percobaan gagal tanpa header `X-Forwarded-For` akan mengunci kunci `"admin@127.0.0.1"` dan memblokir seluruh pengguna sah Owl selama 15 menit.
   - **Fix (1 Kalimat):** Hanya percayai `X-Forwarded-For`/`X-Real-IP` jika `r.RemoteAddr` berasal dari CIDR proxy tepercaya, terapkan kunci lockout per-username disertai batas kapasitas LRU dan semaphore konkurensi sebelum verifikasi Argon2id.

3. **Temuan `MC2-17` (P2) — Race Condition *Lost-Update* pada `PUT /v1/admin/data` & Pemalsuan Atribusi Penulis via `X-Admin-User`**:
   - **Lokasi:** [internal/server/admin.go:42-98, 331-334, 655-745, 930-933, 1107-1110](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/admin.go#L42-L98).
   - **Kutipan Kode:**
     ```go
     // internal/server/admin.go:63-74
     oldSnap := s.deps.Store.Current()
     snap, err := s.deps.Store.ReplaceData(r.Context(), body)
     ...
     author := r.Header.Get("X-Admin-User")
     if author == "" {
         author = "admin"
     }
     ```
   - **Skenario Step-by-Step:**
     1. Handler `putData` (`admin.go:53-98`), `rotateKey` (`admin.go:697-736`), dan `handleToggleAgentCapture` (`upstream_handlers.go:349-388`) membaca `Store.Current().Data` di luar mutex `Store.mu` lalu memanggil `ReplaceData` tanpa memverifikasi kecocokan epoch (`If-Match` / `X-Cerberus-Epoch`).
     2. Jika dua admin menyimpan perubahan secara bersamaan (atau rotasi key terjadi bersamaan dengan pengaktifan `kill_switch`), operasi yang selesai belakangan akan menimpa perubahan pertama secara diam-diam.
     3. Selain itu, atribusi `author` pada riwayat revisi diambil dari header bebas `X-Admin-User` alih-alih `UserFromContext(r.Context()).Username`.
   - **Fix (1 Kalimat):** Terapkan validasi optimistic concurrency (`If-Match` / `X-Cerberus-Epoch`) di dalam `Store.mu` untuk seluruh mutasi data policy dan selalu ambil identitas `author` dari `UserFromContext(r.Context()).Username`.

---

### Area 7: Audit DB (`internal/audit/sqlite.go`, `internal/audit/logger.go`, `cmd/cerberus*`)

1. **Konfigurasi SQLite WAL Mode & Arsitektur Unified Mode**:
   - **CLOSED in Unified Mode by `PRAGMA journal_mode=WAL`, `busy_timeout(2000)`, & HTTP `/v1/decide` delegation** pada [internal/audit/sqlite.go:192](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/sqlite.go#L192), [cmd/cerberus-egress/main.go:140-145](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-egress/main.go#L140-L145), dan [cmd/cerberus-proxy/main.go:153-158](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-proxy/main.go#L153-L158) (pada mode default unified, `cerberus-egress` dan `cerberus-proxy` tidak membuka file SQLite melainkan meneruskan keputusan ke proses tunggal `cerberus`).

2. **Temuan `MC2-12` (P1) — Kolisi `PRIMARY KEY (id)` & Kehilangan Batch 256 Event Saat Multi-Proses Menulis ke Direktori `auditDB` yang Sama (Mode Standalone)**:
   - **Lokasi:** [internal/audit/logger.go:109, 125, 159-161, 374-377](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/logger.go#L109-L161), [internal/audit/sqlite.go:30-31, 381-407](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/sqlite.go#L381-L407), dan [cmd/cerberus-egress/main.go:52, 122](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-egress/main.go#L52-L122).
   - **Kutipan Kode:**
     ```go
     // internal/audit/logger.go:109, 125, 159-161, 374-377
     maxID, err := mgr.maxID(context.Background())
     ...
     l.seq.Store(maxID)
     ...
     if ev.ID <= 0 {
         ev.ID = l.seq.Add(1)
     }
     ...
     if err := l.sqlite.insertBatch(ctx, batch); err != nil {
         slog.Error("audit: sqlite batch insert failed", "err", err, "count", len(batch))
     }
     ```
   - **Skenario Step-by-Step:**
     1. Baik `cerberus`, `cerberus-egress`, maupun `cerberus-proxy` memiliki nilai default flag `auditDB = "cerberus.db"`, yang oleh `newSQLitePartitionManager` diarahkan ke file partisi harian yang sama (`audit-YYYYMMDD.db`).
     2. Saat `cerberus` dan `cerberus-egress --standalone` dijalankan pada host/volume yang sama, kedua proses membaca nilai `SELECT COALESCE(MAX(id), 0) FROM events` yang identik saat startup dan menyimpannya ke counter in-memory masing-masing (`l.seq`).
     3. Ketika kedua proses menerima trafik dan memanggil `Emit`, masing-masing menetapkan `ev.ID = l.seq.Add(1)` secara independen sehingga menghasilkan angka `id` yang berbenturan.
     4. Saat fungsi `insertBatchWithStmt` (`sqlite.go:381-407`) mengeksekusi `INSERT INTO events (id, ...) VALUES (?, ...)` untuk 256 event dalam satu transaksi, SQLite membatalkan seluruh transaksi karena pelanggaran `UNIQUE constraint failed: events.id`, dan `flush()` (`logger.go:374`) membuang seluruh batch 256 event tersebut tanpa retry.
   - **Fix (1 Kalimat):** Biarkan SQLite mengisi kolom `id INTEGER PRIMARY KEY` secara otomatis saat `INSERT` (atau gunakan `INSERT OR REPLACE` / UUID) alih-alih menetapkan `id` dari counter in-memory `l.seq` lintas proses.

---

### Area 8: SDK (`sdk/python` & `sdk/go`)

1. **Kebocoran Secret Key (`X-Agent-Key`) pada Log atau Pesan Error SDK**:
   - **CLOSED by header omission in error formatting & `repr()`** pada [sdk/go/client.go:200-259](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/go/client.go#L200-L259) dan [sdk/python/cerberus_sdk/client.py:241-297](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/python/cerberus_sdk/client.py#L241-L297) (nilai `AgentKey` hanya disisipkan ke header request HTTP dan tidak pernah dicetak ke dalam pesan exception/error).

2. **Retry Storm Otomatis pada Respons Rate-Limit HTTP 429 di dalam Loop HTTP Client**:
   - **CLOSED for single-call retry by `status >= 500` filter** pada [sdk/python/cerberus_sdk/client.py:267-272](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/python/cerberus_sdk/client.py#L267-L272) dan [sdk/go/client.go:233-249](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/go/client.go#L233-L249) (`_do_with_retry` / `doWithRetry` hanya melakukan retry otomatis pada status `>= 500` atau kegagalan jaringan, sehingga status `429` langsung dikembalikan ke pemanggil tanpa retry berulang).

3. **Temuan `MC2-13` (P1) — Cache Lokal 60 Detik di SDK Mengabaikan `epoch` / `kill_switch` & `key_id`, Merujuk `masked_args` Secara Mutable, serta Absennya `X-Agent-Key` di Python SDK**:
   - **Lokasi:** [sdk/python/cerberus_sdk/client.py:120-137, 171-206, 233-237](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/python/cerberus_sdk/client.py#L171-L206), [sdk/python/cerberus_sdk/guard.py:23-34](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/python/cerberus_sdk/guard.py#L23-L34), dan [sdk/go/client.go:106, 145-160, 190-195, 279-286](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/go/client.go#L145-L160).
   - **Kutipan Kode:**
     ```python
     # sdk/python/cerberus_sdk/client.py:171-189, 233-237
     cache_key = self._hash_tool_call(tool, args_map)
     if self._cache_ttl > 0:
         entry = self._cache.get(cache_key)
         if entry is not None:
             if now < entry.expires_at:
                 return Decision(
                     ...
                     masked_args=entry.decision.masked_args,
                 )
     ...
     def _hash_tool_call(tool: str, args: dict[str, Any]) -> str:
         canonical = json.dumps(args, sort_keys=True, separators=(",", ":"))
         raw = f"{tool}\x00{canonical}"
         return hashlib.sha256(raw.encode("utf-8")).hexdigest()
     ```
   - **Skenario Step-by-Step:**
     1. Secara default (`cache_ttl = 60.0` di Python dan `DefaultCacheTTL = 60 * time.Second` di Go), `CerberusClient` menyimpan setiap keputusan `allow` di memori lokal selama 60 detik dengan kunci `sha256(tool + "\x00" + json(args))` tanpa menyertakan `key_id` dan tanpa mengecek perubahan `epoch` di server.
     2. Jika admin mengaktifkan `kill_switch` atau mencabut izin tool di Cerberus Engine, `GuardedExecutor` tetap mengeksekusi tool yang ter-cache di sisi klien selama hingga 60 detik tanpa menghubungi `/v1/decide` (dan juga melewati pencatatan kuota rate-limit per menit/harian di server).
     3. Selain itu, `entry.decision.masked_args` (`cv.decision.MaskedArgs`) dikembalikan ke pemanggil tanpa *deep copy*, sehingga mutasi dictionary `args` di dalam fungsi tool yang dibungkus `GuardedExecutor` akan mengubah objek di dalam cache untuk pemanggilan berikutnya; dan `CerberusClient` pada Python SDK (`client.py:120-137`) belum menyediakan opsi header `X-Agent-Key`, sehingga gagal melakukan autentikasi ketika `api_key_sha256` atau `CERBERUS_REQUIRE_AGENT_KEYS=true` diaktifkan.
   - **Fix (1 Kalimat):** Matikan cache `allow` sisi klien secara default (atau sertakan `key_id` dalam kunci cache serta lakukan deep-copy pada `masked_args`), dan tambahkan dukungan header `X-Agent-Key` pada Python SDK.

---

## IV. Skor Akhir: Kelas Tertutup vs Terbuka

Dari **28 sub-kelas pengujian keamanan deterministik** yang dievaluasi pada 8 area target Round-2:

```
[========================================] 100.0% Total Kelas Uji Round-2 (28)
[################                        ]  39.3% CLOSED / AMAN           (11)
[########################                ]  60.7% TERBUKA / TEMUAN BARU   (17)
```

### Ringkasan Kelas yang Terbukti TERTUTUP (`CLOSED` — 11 Kelas):
1. **Imutabilitas Snapshot & Invalidasi Cache LRU saat Reload di `Engine.Decide`**: **CLOSED by `s.ptr.Store(snap)` & `cacheKey(snap.Epoch, in)`** di [internal/policy/store.go:125](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/policy/store.go#L125) dan [internal/engine/engine.go:265](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/engine/engine.go#L265).
2. **Deteksi `privileged: true` & `cap_add: ["ALL"]` pada Input Rego Langsung**: **CLOSED by `privileged_container`** di [policies/stages/docker.rego:134-156](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L134-L156).
3. **Deteksi Mount Docker Socket (`/var/run/docker.sock`) pada Input Rego Langsung**: **CLOSED by `mount_docker_socket`** di [policies/stages/docker.rego:67-82](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/docker.rego#L67-L82).
4. **Timing Attack / Signature Oracle pada Verifikasi Cookie `owl_session`**: **CLOSED by `crypto.subtle.verify("HMAC", ...)` & `subtle.ConstantTimeCompare`** di [owl/lib/session.ts:76-100](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/lib/session.ts#L76-L100) dan [internal/server/middleware.go:258](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/middleware.go#L258).
5. **Sinkronisasi TTL Cookie Owl (12 Jam) vs TTL Sesi DB Engine (12 Jam)**: **CLOSED by matching `12 * 60 * 60` (`12 * time.Hour`) TTL** di [owl/app/api/auth/login/route.ts:69](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/app/api/auth/login/route.ts#L69) dan [internal/auth/store.go:46](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/auth/store.go#L46).
6. **Pencegahan Self-Execution Loop pada `cerberus-exec`**: **CLOSED by `realCandidate == selfReal` check** di [cmd/cerberus-exec/main.go:487-489](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus-exec/main.go#L487-L489).
7. **Blokir Assignment `LD_PRELOAD` / `BASH_ENV` pada AST `shellguard`**: **CLOSED by `dangerousEnvVars` check on `cmd.Assigns`** di [pkg/shellguard/ast_guard.go:25-32, 130-137](file:///Users/nicholasandriansurjadi/Documents/cerberus/pkg/shellguard/ast_guard.go#L25-L32).
8. **Enkripsi Istirahat (`At-Rest`) API Key Upstream LLM di SQLite**: **CLOSED by AES-256-GCM encryption (`encryptSecret`)** di [internal/server/upstream_handlers.go:404-431](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/server/upstream_handlers.go#L404-L431).
9. **Mode WAL, Busy Timeout, & Partisi Harian pada SQLite Audit DB (Mode Unified)**: **CLOSED by `PRAGMA journal_mode=WAL` & `busy_timeout(2000)`** di [internal/audit/sqlite.go:192](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/audit/sqlite.go#L192).
10. **Pencegahan Kebocoran `X-Agent-Key` pada Log/Error SDK Python & Go**: **CLOSED by omitting headers from error strings and `repr()`** di [sdk/go/client.go:200-259](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/go/client.go#L200-L259) dan [sdk/python/cerberus_sdk/client.py:241-297](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/python/cerberus_sdk/client.py#L241-L297).
11. **Pencegahan Retry Storm Otomatis saat HTTP 429 di SDK Python & Go**: **CLOSED by retrying only on `status >= 500` or network errors** di [sdk/python/cerberus_sdk/client.py:267-272](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/python/cerberus_sdk/client.py#L267-L272) dan [sdk/go/client.go:233-249](file:///Users/nicholasandriansurjadi/Documents/cerberus/sdk/go/client.go#L233-L249).

---
*Laporan audit deterministik Round-2 ini disusun secara read-only tanpa modifikasi kode sumber, tanpa proses build, dan tanpa panggilan jaringan.*
