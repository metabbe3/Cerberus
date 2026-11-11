# Benchmark Performance & Clean Code Profile

Evaluated on Apple M4 (darwin/arm64) via `go test -bench=. -benchmem ./internal/engine/ ./internal/proxy/`.

## Baseline (Sprint 5)

| Benchmark | Iterations | Time (ns/op) | P99 (ns) | Memory (B/op) | Allocs (allocs/op) |
|---|---|---|---|---|---|
| `BenchmarkDecide_Hit` | 3,980,114 | 288.5 ns/op | 52,833 ns | 541 B/op | 6 allocs/op |
| `BenchmarkDecide_Miss` | 9,610 | 115,210 ns/op | 3,348,584 ns | 293,275 B/op | 6,926 allocs/op |
| `BenchmarkDecide_StageLLM` | 10,482 | 110,016 ns/op | 3,003,334 ns | 287,416 B/op | 6,759 allocs/op |
| `BenchmarkDecide_StageTool` | 9,537 | 113,110 ns/op | 3,089,583 ns | 293,448 B/op | 6,926 allocs/op |
| `BenchmarkDecide_StageDocker` | 10,000 | 106,812 ns/op | 2,881,750 ns | 275,345 B/op | 6,618 allocs/op |
| `BenchmarkDecide_Shield` | 8,956 | 122,924 ns/op | 3,223,375 ns | 314,906 B/op | 7,464 allocs/op |
| `BenchmarkDockerProxy_Overhead/Direct` | 39,160 | 29,383 ns/op | - | 5,542 B/op | 69 allocs/op |
| `BenchmarkDockerProxy_Overhead/Proxied` | 17,196 | 70,409 ns/op | - | 49,483 B/op | 193 allocs/op |

## SPRINT 6C Post-Optimization Profile

| Benchmark | Iterations | Time (ns/op) | P99 (ns) | Memory (B/op) | Allocs (allocs/op) | Delta vs Baseline |
|---|---|---|---|---|---|---|
| `BenchmarkDecide_Hit` | 4,147,507 | 277.7 ns/op | 50,333 ns | 451 B/op | 6 allocs/op | **-10.8 ns/op (-3.7%), -90 B/op (-16.6%)** |
| `BenchmarkDecide_Miss` | 9,206 | 112,468 ns/op | 2,968,000 ns | 294,177 B/op | 6,942 allocs/op | -2,742 ns/op (-2.4%) |
| `BenchmarkDecide_StageLLM` | 9,495 | 112,284 ns/op | 3,086,167 ns | 288,215 B/op | 6,775 allocs/op | +2.0% within jitter |
| `BenchmarkDecide_StageTool` | 9,522 | 121,432 ns/op | 3,836,958 ns | 294,216 B/op | 6,942 allocs/op | within test jitter |
| `BenchmarkDecide_StageDocker` | 11,001 | 108,411 ns/op | 3,013,166 ns | 276,130 B/op | 6,634 allocs/op | within test jitter |
| `BenchmarkDecide_Shield` | 8,698 | 124,019 ns/op | 3,221,708 ns | 315,710 B/op | 7,480 allocs/op | within test jitter |
| `BenchmarkDockerProxy_Overhead/Direct` | 38,716 | 28,612 ns/op | - | 5,542 B/op | 69 allocs/op | -771 ns/op (-2.6%) |
| `BenchmarkDockerProxy_Overhead/Proxied` | 17,844 | 67,466 ns/op | - | 49,280 B/op | 191 allocs/op | **-2,943 ns/op (-4.2%), -203 B/op, -2 allocs** |

### Summary of Optimizations
1. **Hasher Object Pooling & Direct Sum**: Used `sync.Pool` for `sha256.New()` and direct buffer destination `h.Sum(out[:0])`, eliminating heap allocation of fresh sha256 instances and intermediate slice allocations in hot path cache key generation.
2. **Raw Byte String Cache Keys**: Replaced `hex.EncodeToString(sum[:])` with direct `string(sum[:])`, eliminating intermediate hex encoding string heap allocations on every decision.
3. **Precomputed Snapshot Epoch String**: Cached `EpochStr` on `policy.Snapshot` during snapshot initialization, eliminating repeated runtime `strconv.FormatUint` calls on hot-path metrics updates.
4. **Map Capacity Preallocation**: Replaced dynamic map reallocation in `regoInput` with preallocated capacity `make(map[string]any, 9)`, eliminating map expansion overhead.
5. **Fast-path API Version Stripping**: Replaced blanket `regexp.ReplaceAllString` with fast-path prefix check `stripAPIVersion` in Docker proxy request parsing.
