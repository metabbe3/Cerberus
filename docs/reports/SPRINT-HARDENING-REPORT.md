# SPRINT HARDENING REPORT: Cerberus Security Hardening Pass

**Repository:** `github.com/metabbe3/cerberus`  
**Date:** 2026-11-13  
**Status:** Completed (All 6 Items verified green)

---

## 1. Item-by-Item Breakdown

### Item 1 (P0): Wire Bundle Signature Verification in cmd/cerberus
- **Problem:** `internal/policy/store.go` had `SetVerificationKey(ed25519.PublicKey)`, but `cmd/cerberus` never configured it, accepting unsigned bundles via `POST /v1/admin/bundle`.
- **Changes:**
  - [internal/config/config.go:37](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/config/config.go#L37): Added `BundlePubKey string` to `Config` struct.
  - [internal/config/config.go:68](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/config/config.go#L68): Read `CERBERUS_BUNDLE_PUBKEY` in `config.Load`.
  - [internal/config/config.go:79](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/config/config.go#L79): Added `-bundle-pubkey` CLI flag.
  - [cmd/cerberus/main.go:88-90](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus/main.go#L88-L90): Invoked `setupVerificationKey(store, cfg.BundlePubKey)` after `policy.NewStore`.
  - [cmd/cerberus/main.go:217-234](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus/main.go#L217-L234): Implemented `setupVerificationKey`: parses key with `policy.ParsePublicKey` (fail-closed with fatal error if invalid); sets verification key on store when present; warns when empty.
  - [internal/config/config_test.go:96-126](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/config/config_test.go#L96-L126): Unit test `TestLoad_BundlePubKey` verifying env and flag override.
  - [cmd/cerberus/main_test.go:60-96](file:///Users/nicholasandriansurjadi/Documents/cerberus/cmd/cerberus/main_test.go#L60-L96): Unit tests `TestSetupVerificationKey_ValidBase64`, `TestSetupVerificationKey_CorruptedKeyReturnsError`, `TestSetupVerificationKey_EmptyKeyOmitted`.
- **Gate Proof:** `go test -v ./internal/config ./cmd/cerberus` passed with 0 failures.

---

### Item 2 (P0): Rego Test Gap for llm.rego & tool.rego
- **Problem:** `policies/stages/llm.rego` and `policies/stages/tool.rego` dispatch to `stages.ai.decision`, but lacked direct stage and gateway integration tests matching the live API contracts.
- **Changes:**
  - [policies/stages/llm_test.rego:1-127](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/llm_test.rego#L1-L127): Test suite for stage `llm` (contract `{key_id, model, messages:[...]}`):
    - Happy path allow (`test_llm_allow_happy`)
    - Direct stage adapter verification (`test_llm_stage_adapter_allow`)
    - Disallowed model deny (`test_llm_model_not_allowed`)
    - Blocked pattern in messages array deep scan (`test_llm_blocked_pattern_in_messages`)
    - Unregistered stranger key under `bypass_unknown_keys=true` (`test_llm_unknown_key_bypass_allowed`)
    - Blocked pattern denied even under bypass (`test_llm_unknown_key_blocked_pattern_denied`)
    - Unknown key fail-closed under `bypass_unknown_keys=false` (`test_llm_unknown_key_bypass_false_denied`)
  - [policies/stages/tool_test.rego:1-136](file:///Users/nicholasandriansurjadi/Documents/cerberus/policies/stages/tool_test.rego#L1-L136): Test suite for stage `tool` (contract `{key_id, tool_call, args}`):
    - Happy path allow (`test_tool_allow_happy`)
    - Direct stage adapter verification (`test_tool_stage_adapter_allow`)
    - Restricted tool call deny (`test_tool_restricted_denied`)
    - Allowlist absence deny (`test_tool_not_allowed_denied`)
    - Argument constraint violation deny (`test_tool_arg_violation_denied`)
    - Stranger key bypass under `bypass_unknown_keys=true` (`test_tool_unknown_key_bypass_allowed`)
    - Dangerous command caught by shield under bypass (`test_tool_unknown_key_dangerous_cmd_denied`)
    - Stranger key fail-closed under `bypass_unknown_keys=false` (`test_tool_unknown_key_bypass_false_denied`)
- **Gate Proof:** `opa test policies/ -v` passed 173/173 tests (+15 tests added), `opa check --strict policies/` clean.

---

### Item 3 (P1): Filter AppleDouble and Hidden Files in Loader & Bundle
- **Problem:** macOS AppleDouble (`._*`) and dotfiles (`.*`) could accidentally be loaded by OPA loaders or included in bundle rego collections.
- **Changes:**
  - [internal/policy/loader.go:51](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/policy/loader.go#L51): Switched file loader invocation from `.All()` to `.Filtered([]string{policyDir}, bundleFilter)` to ensure the filter callback is actively enforced.
  - [internal/policy/loader.go:96-98](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/policy/loader.go#L96-L98): `bundleFilter` explicitly returns `true` (skip) if `strings.HasPrefix(name, ".") || strings.HasPrefix(name, "._")`.
  - [internal/policy/bundle.go:95-99](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/policy/bundle.go#L95-L99): `ReadBundle` skips rego entries if `strings.HasPrefix(name, ".") || strings.HasPrefix(name, "._")` or if basename starts with `.` or `._`.
  - [internal/policy/loader_test.go:119-143](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/policy/loader_test.go#L119-L143): Added `TestLoad_AppleDoubleAndHiddenRegoSkipped` proving `._evil.rego` and `.hidden.rego` with syntax errors are excluded from snapshot compilation.
  - [internal/policy/bundle_test.go:630-649](file:///Users/nicholasandriansurjadi/Documents/cerberus/internal/policy/bundle_test.go#L630-L649): Added `TestReadBundle_AppleDoubleRegoSkipped` proving AppleDouble files in bundle tarballs are omitted from `RegoFiles`.
  - Makefile: Checked for archive/tar targets; none exist, so Makefile modification skipped per instructions.
- **Gate Proof:** `go test -v -run 'TestLoad_AppleDouble|TestReadBundle_AppleDouble' ./internal/policy` passed with 0 errors.

---

### Item 4 (P1): data/prod.json → Template + Untrack
- **Problem:** Production configuration and sensitive operational identifiers were tracked in git.
- **Changes:**
  - Executed `git mv data/prod.json data/prod.template.json`.
  - Sanitized [data/prod.template.json](file:///Users/nicholasandriansurjadi/Documents/cerberus/data/prod.template.json):
    - Replaced `agentd-prod` description and team ID (`t-example`).
    - Replaced `egress-dial-guard` description with placeholder.
    - Sanitized `prod_shield.cidrs` from `103.22.201.0/24` to RFC 5737 documentation CIDR `203.0.113.0/24`.
    - Sanitized `protected_containers` to `["example-db-1"]`.
    - Sanitized `protected_paths` to generic paths (`["/etc", "/var/lib", "~/.ssh", "/app/.env*"]`).
    - Sanitized SSH `allow_hosts` and `deny_hosts` to `*.example.internal`.
    - Retained test fixture agent structures (`k-open`, `k-exact`, `k-glob`, `k-case`, `k-owner`, etc.).
  - Preserved original `data/prod.json` on disk intact for live runtime compatibility.
  - [`.gitignore`](file:///Users/nicholasandriansurjadi/Documents/cerberus/.gitignore#L9-L10): Added `data/prod.json` and `.superpowers/`.
  - Removed `.superpowers/` and `data/prod.json` from git index (`git rm -r --cached`).
- **Operational Runtime Note:** The live engine process on the host reads configuration directly from the filesystem disk path (`data/prod.json`), not from git commits. Git untracking has zero impact on host runtime operations, and disk files remain completely intact.

---

### Item 5 (P2): Deploy Units for tap & ssh
- **Problem:** Systemd service units and macOS launchd plists were missing for `cerberus-tap` and `cerberus-ssh`.
- **Changes:**
  - [`deploy/systemd/cerberus-tap.service`](file:///Users/nicholasandriansurjadi/Documents/cerberus/deploy/systemd/cerberus-tap.service): Added systemd unit following `cerberus-proxy.service` standards (`EnvironmentFile=-/etc/cerberus/cerberus-tap.env`, `Restart=always`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`, `ReadWritePaths=/var/lib/cerberus-tap`, `ExecStart=/usr/local/bin/cerberus-tap -listen 0.0.0.0:8090 -upstream $UPSTREAM -engine-url http://127.0.0.1:8089 -data-dir /var/lib/cerberus-tap -strict`).
  - [`deploy/systemd/cerberus-ssh.service`](file:///Users/nicholasandriansurjadi/Documents/cerberus/deploy/systemd/cerberus-ssh.service): Added systemd unit (`EnvironmentFile=-/etc/cerberus/cerberus-ssh.env`, `Restart=always`, hardening, `ReadWritePaths=/var/lib/cerberus-ssh`, `ExecStart=/usr/local/bin/cerberus-ssh -listen 0.0.0.0:2222 -engine-url http://127.0.0.1:8089 -hostkey-file /var/lib/cerberus-ssh/hostkey`).
  - [`deploy/launchd/com.cerberus.tap.plist`](file:///Users/nicholasandriansurjadi/Documents/cerberus/deploy/launchd/com.cerberus.tap.plist): Added launchd plist matching existing launchd conventions.
  - [`deploy/launchd/com.cerberus.ssh.plist`](file:///Users/nicholasandriansurjadi/Documents/cerberus/deploy/launchd/com.cerberus.ssh.plist): Added launchd plist matching existing launchd conventions.
- **Gate Proof:** `plutil -lint deploy/launchd/com.cerberus.tap.plist deploy/launchd/com.cerberus.ssh.plist` returned `OK`.

---

### Item 6 (P2): Owl Duplicate /policy vs /policies Cleanup
- **Problem:** Owl had duplicate routes `/policy` (old 141-line single-file view) and `/policies` (complete 426-line multi-file, engine status, and coverage view).
- **Changes:**
  - Inspected both pages; determined `/policies` is the authoritative multi-file dashboard.
  - [owl/app/(dash)/policy/page.tsx:1-5](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/app/(dash)/policy/page.tsx#L1-L5): Replaced duplicate page with standard Next.js server redirect: `import { redirect } from "next/navigation"; export default function PolicyRedirectPage() { redirect("/policies"); }`.
  - [owl/components/nav.tsx:17](file:///Users/nicholasandriansurjadi/Documents/cerberus/owl/components/nav.tsx#L17): Verified navigation links already target `/policies`.
- **Gate Proof:** `cd owl && npx tsc --noEmit` passed with 0 errors.

---

## 2. Hardening Pass Verification Gates

| Gate | Command | Result |
| :--- | :--- | :--- |
| **Go Build** | `go build ./...` | **PASS** (Exit 0) |
| **Go Tests** | `go test -count=1 ./...` | **PASS** (Exit 0, all packages green) |
| **Go Linter** | `golangci-lint run` | **PASS** (0 issues) |
| **Go Format** | `gofmt -l cmd/ pkg/ internal/` | **PASS** (Clean, 0 unformatted files) |
| **Owl Typecheck** | `cd owl && npx tsc --noEmit` | **PASS** (Exit 0, 0 type errors) |
| **OPA Tests** | `opa test policies/ -v` | **PASS** (173/173 tests passed) |
| **OPA Strict Check** | `opa check --strict policies/` | **PASS** (Exit 0) |
| **Launchd Plist** | `plutil -lint deploy/launchd/*.plist` | **PASS** (OK) |
