# Cerberus Audit-Fix Batch C Sprint Report

**Date:** 2026-11-14  
**Target Repository:** `github.com/metabbe3/Cerberus`  
**Scope:** Batch C — 2 HIGH (tap / shellguard) + 4 P2 (tap, proxy, egress, engine)

---

## 1. Executive Summary

Batch C addresses 6 verified security and correctness audit findings across Cerberus enforcer proxy, tap inspector, AST shellguard, and policy evaluation engine.

All 6 items (C1 to C6) have been resolved with fail-closed security invariants, zero external dependencies added, zero hardcoded secrets, and accompanying unit tests with race detection (`-race -count=1`).

---

## 2. Itemized Fix Summary

### C1 (HIGH) Tool-Gate Bypass in Tap Non-SSE Response Path
- **Vulnerability:** In `cmd/cerberus-tap/main.go` `ServeHTTP`, the LLM tool-use gate (`askToolEngine`) was only invoked on the streaming SSE code path (`proxySSE`). Upstream non-streaming responses containing Anthropic `tool_use` blocks (`stream: false`) were forwarded directly to the client without verification, bypassing tool enforcement completely.
- **Resolution:**
  - In `ServeHTTP`, after reading the non-SSE response body, if `Content-Type` is `application/json`, the response is parsed for Anthropic content blocks.
  - Every block with `type == "tool_use"` triggers `s.askToolEngine(keyID, modelOf(raw), block.Name, inputJSON)`.
  - If any tool call is denied:
    - HTTP response code 502 (Bad Gateway) is returned with JSON body `{"error":"cerberus_tool_blocked","message":...}`.
    - Zero bytes of upstream payload are forwarded/leaked to the client.
    - An audit turn with `kind: "tool_blocked"` and status 502 is recorded in the tap store.
  - Non-Anthropic JSON, non-JSON upstream, or unmarshalable bodies are forwarded intact so non-Anthropic backends are never broken.
- **Verification Tests:**
  - `TestToolUseNonSSEEnforcement`: Verifies fake upstream non-SSE response with denied tool call returns 502 with `cerberus_tool_blocked`, leaks no secret parameters, and logs audit turn.
  - `TestToolUseNonSSEAllowed`: Verifies allowed tool call passes through intact with 200.
  - `TestNonAnthropicUpstreamForwarded`: Verifies non-Anthropic payload passes through unchanged.

### C2 (HIGH) Shellguard: Assignment Prefix Bypass
- **Vulnerability:** In `pkg/shellguard/ast_guard.go` `validateCall`, `call.Assigns` was unpoliced. Prefix variable assignments such as `PATH=/tmp/evil grep x` or `LD_PRELOAD=/evil.so cmd` extracted `grep` as a benign binary while subverting the execution environment.
- **Resolution:**
  - In `validateCall`, commands with `len(call.Assigns) > 0` are immediately rejected with fail-closed error `command has assignment prefix (assignment_prefix, fail-closed)`.
- **Verification Tests:**
  - `TestAssignmentPrefixRejected`: Confirms `PATH=/tmp/evil grep x`, `A=1 B=2 ls`, and `LD_PRELOAD=/evil.so grep x` are rejected with `assignment_prefix`, while bare benign command `grep x` extracts cleanly.

### C3 (P2) Tap Admin Endpoints Fail-Open on Empty Token
- **Vulnerability:** In `cmd/cerberus-tap/main.go` `handleTap`, authentication was guarded by `if s.adminTok != ""`. When `CERBERUS_ADMIN_TOKEN` was unset (default empty string), `/tap/turns`, `/tap/stats`, and `/tap/kill` were left exposed unauthenticated.
- **Resolution:**
  - In `handleTap`, if `s.adminTok == ""`, all endpoints except `/tap/healthz` immediately return HTTP 503 (Service Unavailable) with message `"admin token not configured"` (refuse-to-serve).
  - `/tap/healthz` remains accessible without authentication (returns 200 `"ok"`).
- **Verification Tests:**
  - `TestTapAdminUnconfiguredToken`: Confirms `/tap/turns` and `/tap/stats` return 503 with `"admin token not configured"`, while `/tap/healthz` returns 200 `"ok"`.
  - `TestTapEndpointsRequireAuth`: Confirms authenticated behavior when token is configured (401 without/wrong token, 200 with valid token).

### C4 (P2) Proxy: Admin Token Read Then Discarded
- **Vulnerability:** In `cmd/cerberus-proxy/main.go`, `adminToken := os.Getenv("CERBERUS_ADMIN_TOKEN"); _ = adminToken` silently discarded the token. Both the Docker API proxy and HTTP egress proxy ran completely unauthenticated.
- **Resolution:**
  - Added CLI flag `--admin-token` alongside `CERBERUS_ADMIN_TOKEN` env var.
  - Implemented `requireAdminAuth(token string, next http.Handler) http.Handler`:
    - When token is set, all incoming requests must supply `Authorization: Bearer <token>` or receive 401 Unauthorized with `{"error":"unauthorized"}`.
    - When token is unset/empty, startup logs a warning: `UNAUTHENTICATED mode: CERBERUS_ADMIN_TOKEN not set, proxy requests are unauthenticated`, and proxy remains open for local development to avoid breaking existing Docker Compose setups.
  - Wrapped both Docker proxy (`dp`) and Egress proxy (`ep`) servers with `requireAdminAuth`.
- **Verification Tests:**
  - `TestRequireAdminAuth`: Tests 401 without header, 401 with wrong token, 200 with valid token, and 200 without token configured.
  - `TestStartupUnauthenticatedModeWarnLog`: Asserts warning log generation in unauthenticated mode.
  - `TestSubprocessUnauthenticatedWarning`: End-to-end process execution verifying stdout/stderr contains `"UNAUTHENTICATED mode"`.
- **Note for Orchestrator:** Existing `docker-compose.yml` should be updated to provide `CERBERUS_ADMIN_TOKEN` in production environments.

### C5 (P2) Egress Port Validation: String Without Normalization
- **Vulnerability:** In `internal/util/httputil.go` `ExtractHost` and `internal/proxy/egress.go`, ports were parsed without digit or range validation. Non-numeric port strings like `"http"` or leading-zero ports like `"080"` bypassed port checks or caused `/etc/services` lookups during dial.
- **Resolution:**
  - `ExtractHost(raw string) (host string, port string, err error)`:
    - If port is missing in raw host, defaults to `"443"`, `err = nil`.
    - If port is supplied, strictly validates that port contains ASCII digits only, parses with `strconv.Atoi`, normalizes leading zeros (`strconv.Itoa`), and validates range `1 <= portNum <= 65535`.
    - Non-digit characters, out-of-range ports, or empty ports return an explicit error.
  - In `internal/proxy/egress.go` (`handleConnect`, dial target, and `handleHTTP`), invalid host or port immediately terminates with HTTP 400 Bad Request.
  - Added host normalization in `handleConnect` to handle RFC 7230 authority parsing.
- **Verification Tests:**
  - `TestExtractHost`: Unit tests for `host:http` (error), `host:080` ("80"), `host:99999` (error), `host:443` ("443"), `host:0` (error), `example.com` ("443").
  - `TestEgressProxy_InvalidPortReturns400`: Verifies HTTP 400 Bad Request on both CONNECT and plain HTTP requests with invalid ports.

### C6 (P2) engine.cacheKey: Marshal Error Kunci Kolaps
- **Vulnerability:** In `internal/engine/engine.go` `cacheKey`, if `json.Marshal(in)` failed (e.g. unmarshalable types like `chan`), `b` was set to `nil`, hashing `epoch ‖ nil`. All unmarshalable inputs collapsed to a single cache key, causing decision cross-contamination across different requests.
- **Resolution:**
  - Updated `cacheKey(epoch uint64, in Input) (string, bool)` to return a `(key, ok)` sentinel.
  - If `json.Marshal(in)` fails, `cacheKey` returns `("", false)`.
  - In `Decide`:
    - When `!ok`, cache lookup and singleflight are completely bypassed.
    - Evaluates directly via `e.eval(...)` without caching (`e.cache.Add` is never called).
- **Verification Tests:**
  - `TestCacheKey_UnmarshalableInputBypassesCache`:
    - Verifies `cacheKey` returns `("", false)` for inputs containing `chan`.
    - Pre-seeds the cache with a poisoned entry at the legacy collapsed key (`sha256(epoch ‖ nil)`).
    - Verifies two different unmarshalable inputs evaluate independently, yield different rule IDs (`internal.timeout` vs `internal.eval_error`), neither is cached (`Cached == false`), and neither is contaminated by the poisoned cache key.

---

## 3. Verification Gates

| Check | Command | Result |
|---|---|---|
| Build | `go build ./...` | **PASS (0 errors)** |
| Race Tests | `go test -race -count=1 ./...` | **PASS (all packages green)** |
| Linter | `golangci-lint run` | **PASS (0 issues)** |
| Formatting | `gofmt -l cmd/ pkg/ internal/` | **PASS (clean)** |

---

## 4. Modified Files

- `cmd/cerberus-tap/main.go`
- `cmd/cerberus-tap/main_test.go`
- `pkg/shellguard/ast_guard.go`
- `pkg/shellguard/ast_guard_test.go`
- `cmd/cerberus-proxy/main.go`
- `cmd/cerberus-proxy/main_test.go`
- `internal/util/httputil.go`
- `internal/util/util_test.go`
- `internal/proxy/egress.go`
- `internal/proxy/egress_test.go`
- `internal/engine/engine.go`
- `internal/engine/engine_test.go`
- `SPRINT-AUDITFIX-C-REPORT.md` (new)
