# ADR-0001: High-Traffic Concurrent Architecture

**Status**: Accepted · **Date**: 2026-11-10 · **Owner**: Nicholas

## Context

Semua agent (teknikal-agent, AegisGo, cron agents, web Uhu) akan memanggil Cerberus
pada saat yang sama — setiap LLM call (pre) dan setiap tool call (pre-exec).
Target: latency tambahan <5ms p99 di hot path, ribuan QPS, tanpa bottleneck tunggal.

## Decision

### 1. OPA eval di-process, BUKAN sidecar HTTP
Embed `open-policy-agent/opa` sebagai **library Go** (`rego.PreparedEvalQuery`).
- Prepared query di-compile SEKALI saat load policy → eval per request = mikrodetik-ms,
  bukan HTTP hop + JSON serialize ke sidecar (itu +0.5-2ms per call + failure mode jaringan).

### 2. Prepared-query pool + copy-on-write store
- Hot path: `preparedQuery.Eval(ctx, rego.EvalInput(input))` — thread-safe untuk concurrent eval.
- Reload policy/data = bangun prepared query BARU dulu (compile di background),
  lalu atomic.Pointer swap — request in-flight selesai dengan snapshot lama,
  request baru langsung pakai snapshot baru. Tidak pernah ada lock di hot path.

### 3. Eval cache (deterministic, bounded)
- Key: SHA-256(input yang memengaruhi keputusan: key_id, stage, model/tool, args-hash)
  + versi policy snapshot (epoch counter bertambah tiap reload).
- Bounded LRU (default 10k entries) + singleflight: N agent minta keputusan identik
  bersamaan → satu eval, sisanya tunggu hasilnya.
- Hit = ~100ns. Miss tetap cepat karena prepared query.
- Cache INVALIDASI otomatis saat reload (epoch naik).

### 4. Server: goroutine-per-request, zero-allocation hot path
- stdlib `net/http` + `http.MaxBytesReader`; tidak perlu framework.
- gRPC di port kedua (protobuf `DecideRequest/DecideResponse`) untuk SDK Go internal.
- JSON encode dengan `sync.Pool` untuk buffer.
- Tiap request: parse → hash → cache LRU → (miss) eval → audit channel (async, non-blocking).

### 5. Audit: channel + batcher, bukan sync write
- Decision dikirim ke buffered channel (drop-count saat penuh, tidak pernah blok hot path).
- Single writer goroutine batch-insert ke SQLite (WAL mode) — pola single-writer
  yang sudah terbukti di AegisGo/teknikal-agent.
- SSE dashboard membaca dari ring buffer in-memory + poll fallback SQLite.

### 6. Masking: pre-compiled regex + transform di Rego/data
- Pattern masking di-compile sekali per reload; transform (redact/mask/hash) dieksekusi
  di Go atas args yang di-serialize — hasil masked dikembalikan ke caller.

### 7. SLO & overload
- `/healthz` (plain) + `/readyz` (policy loaded, cache warm) + `/metrics` Prometheus.
- Load shedding: bila eval p99 > threshold atau channel audit penuh → masih serve
  (eval cepat), tapi audit jadi sampled — policy decision tidak pernah ditolak.
- Timeout eval per request (default 10ms budget): melebihi → DENY fail-closed + counter.

## Consequences

- Binary tunggal, kecil, static; deploy = satu proses.
- Latency tambahan p99 <5ms achievable (in-process eval + cache).
- Reload policy zero-downtime (atomic swap), tanpa restart agent.
- Trade-off: policy logic hidup di dalam binary Go — upgrade Rego major = deploy baru
  (data/kebijakan TIDAK — itu hot-reload).

## Benchmark target (sebelum merge server)

`go test -bench` dengan 8 worker goroutine × 10k eval: p99 < 1ms (cache miss),
p99 < 0.1ms (cache hit), 0 race (`-race`).
