# Cerberus Guide — Phase 1

Run the engine, point your AI agents at it, and every LLM call / tool execution
is decided by Rego policy in a few milliseconds. Everything below works with
just `make build` and a token.

## Quickstart

```sh
make build                                            # → bin/cerberus
export CERBERUS_ADMIN_TOKEN=change-me                 # required; admin API auth
CERBERUS_DATA_FILE=data/prod.json ./bin/cerberus      # listens on :8089
```

Env vars (a `-flag` of the same lower-kebab name overrides):

| Env | Default | Meaning |
|---|---|---|
| `CERBERUS_ADDR` | `:8089` | listen address |
| `CERBERUS_POLICY_DIR` | `policies` | Rego bundle directory |
| `CERBERUS_DATA_FILE` | `data/prod.json` | policy data (hot-reloadable) |
| `CERBERUS_AUDIT_DB` | `cerberus.db` | audit SQLite (WAL) |
| `CERBERUS_ADMIN_TOKEN` | — | **required**; empty token refuses to start |
| `CERBERUS_CACHE_SIZE` | `10000` | LRU decision cache entries |
| `CERBERUS_EVAL_TIMEOUT` | `10ms` | per-eval budget; timeout → deny `internal.timeout` |
| `CERBERUS_LOG_LEVEL` | `info` | `debug\|info\|warn\|error` |

Health: `GET /healthz` (always ok), `GET /readyz` (200 once a policy snapshot
is live).

## The decide API

Every decision is one POST with the input contract and returns the golden
shape — there is no error path: unknown stages, bad keys, and timeouts are all
**denies** with a stable `rule_id`.

```sh
# LLM pre-call: model allowlist, budget, blocked patterns
curl -s -X POST localhost:8089/v1/decide/llm -H 'Content-Type: application/json' -d '{
  "key_id": "k-glob", "model": "m1", "prompt": "summarize this",
  "context": {"spend_usd": 0.02}
}'

# Tool pre-exec: allow/restricted lists + argument constraints + masking
curl -s -X POST localhost:8089/v1/decide/tool -H 'Content-Type: application/json' -d '{
  "key_id": "k-glob", "tool_call": "kubernetes_get_pods",
  "args": {"cmd": "kubectl get pods --token sk-abc123"}
}'
# → {"decision":"allow","rule_id":"ai.tool.allow","reason":"…",
#    "masked_args":{"cmd":"kubectl get pods --token [REDACTED]"},
#    "epoch":1,"cached":false}
```

Response contract: `{"decision":"allow|deny","rule_id":"<domain>.<subject>.<verdict>",
"reason":"…","masked_args":{...}|null,"epoch":N,"cached":bool}`.
`masked_args` is null when no masking rule touched a string; when non-null,
**execute the masked args, not the originals**.

## LiteLLM pre-call hook

```python
# litellm config: extralitellm custom logger that gates every call on Cerberus.
import httpx
from litellm.integrations.custom_logger import CustomLogger

class Cerberus(CustomLogger):
    def __init__(self):
        self.http = httpx.Client(base_url="http://localhost:8089")

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        r = self.http.post("/v1/decide/llm", json={
            "key_id": user_api_key_dict.get("key_id", ""),
            "model": data.get("model", ""),
            "prompt": " ".join(str(m.get("content", "")) for m in data.get("messages", [])),
            "context": {"spend_usd": user_api_key_dict.get("spend", 0)},
        })
        r.raise_for_status()
        verdict = r.json()
        if verdict["decision"] == "deny":
            raise HTTPException(status_code=403, detail={
                "error": "blocked by policy", "rule_id": verdict["rule_id"],
                "reason": verdict["reason"]})
        return data
```

## Agent tool pre-exec gate

Wrap every tool execution; when `masked_args` comes back non-null, run the
masked values instead of the originals:

```python
def guard(key_id: str, tool_call: str, args: dict) -> dict:
    r = httpx.post("http://localhost:8089/v1/decide/tool",
                   json={"key_id": key_id, "tool_call": tool_call, "args": args})
    r.raise_for_status()
    verdict = r.json()
    if verdict["decision"] == "deny":
        raise PermissionError(f"{verdict['rule_id']}: {verdict['reason']}")
    return verdict["masked_args"] if verdict["masked_args"] is not None else args

# kwargs = guard("k-glob", "kubernetes_get_pods", {"cmd": "kubectl get pods --token sk-abc123"})
# run_tool(tool_call, **kwargs)
```

## Data schema cheatsheet

`data/prod.json` — hot-reloadable without recompile (see
[data.template.json](../data.template.json)):

- `config.bypass_unknown_keys` / `bypass_unknown_teams` — fail-open for
  onboarding (`true` → unknown keys allowed with rule `config.bypass_unknown_keys`);
  set `false` in production → deny `config.unknown_key_closed`.
- `teams[id]`: `name`, `allowed_models[]`, `allowed_tools[]` (exact,
  case-sensitive), `budget_limit`.
- `agents[key_id]`: `name`, `team_id` (optional; a registered key with an
  unregistered team is governed by key only), `allowed_tool_calls[]` /
  `restricted_tool_calls[]` (glob: ending `*` = case-insensitive prefix,
  otherwise substring), `allowed_tools[]` / `restricted_tools[]` (exact),
  `tool_argument_constraints[tool][arg]` (bare array, `{type:"allowlist"}`,
  `{type:"regex_allow","patterns"[]}`, `{type:"range","min","max"}`),
  `budget_limit`, `masking[{pattern, transform: redact|mask|hash, scope}]`.
  `restricted` always wins over `allowed`.
- `blocked_patterns[]`: substrings denied at the llm stage.

Masking transforms (exact): `redact` → `[REDACTED]`; `mask` → first 2 + last 2
chars kept, middle `*`; `hash` → `sha256:<16 hex>`. Strings anywhere in `args`
are transformed; non-strings pass through.

## Admin API

Bearer `Authorization: Bearer $CERBERUS_ADMIN_TOKEN` on all of these:

- `GET /v1/admin/data` — live data document (`X-Cerberus-Epoch` header).
- `PUT /v1/admin/data` — install new data (epoch +1, written atomically to
  disk); invalid JSON/Rego → `422`, old snapshot stays live.
- `POST /v1/admin/reload` — recompile policies + data from disk (epoch +1).
- `POST /v1/admin/policy/validate` — `{"rego": "..."}` → `{ok, errors[]}`
  without touching the live snapshot.
- `GET /v1/audit?key_id&stage&rule_id&since&limit` — query decisions.
- `GET /v1/events` — SSE stream of live decisions.

## Adding a stage (3 touches)

Example for the future `docker` stage:

1. `policies/stages/docker.rego` — package `stages.docker`, expose `decision`
   returning exactly `{decision, rule_id, reason}` (no `default`; core denies).
2. One dispatch line in the core gate (`policies/` core file):
   `decision := stages.docker.decision if input.stage == "docker"`.
3. `policies/stages/docker_test.rego` + a `domains.docker` section in the data
   document. The HTTP route `POST /v1/decide/docker` follows the existing
   `s.decide("docker")` pattern in `internal/server`.

## Ops

- **Metrics** (`GET /metrics`): `cerberus_decisions_total{stage,decision,rule_id}`,
  `cerberus_cache_hits_total`, `cerberus_cache_misses_total`,
  `cerberus_eval_duration_seconds`, `cerberus_eval_timeouts_total`,
  `cerberus_policy_epoch`, `cerberus_audit_dropped_total`.
- **Reload on deploy**: `kill -HUP $(pidof cerberus)` recompiles from disk;
  a broken file keeps the previous snapshot live and logs the error.
- **Backup**: copy `cerberus.db` (plus `-wal`/`-shm` or after a checkpoint) —
  it is a plain SQLite file in WAL mode; batched writes land at most 200ms late.
- **Docker**: `docker build -f deploy/Dockerfile -t cerberus:dev .` then
  `CERBERUS_ADMIN_TOKEN=… docker compose -f deploy/docker-compose.yml up`
  (data/ mounted at `/data`, audit DB in the `cerberus-db` volume).
