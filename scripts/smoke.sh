#!/usr/bin/env bash
# End-to-end smoke test: boots bin/cerberus against the testdata fixture and
# curls the public contract (decide, masking, admin auth, hot reload,
# metrics). Run via `make smoke` after `make build`.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=bin/cerberus
if [ ! -x "$BIN" ]; then
	echo "smoke: $BIN missing; run make build first" >&2
	exit 1
fi

# Free port + scratch dir. The data file is a temp COPY of the fixture so the
# PUT /v1/admin/data check (which writes the data file back to disk) never
# mutates a tracked file.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
TMPD=$(mktemp -d)
cp policies/testdata/data.json "$TMPD/data.json"

PID=""
cleanup() {
	if [ -n "$PID" ]; then
		kill "$PID" 2>/dev/null || true
	fi
	rm -rf "$TMPD"
}
trap cleanup EXIT

fail() {
	echo "smoke: FAILED: $1" >&2
	tail -20 "$TMPD/cerberus.log" >&2 || true
	exit 1
}

CERBERUS_ADDR="127.0.0.1:$PORT" \
	CERBERUS_DATA_FILE="$TMPD/data.json" \
	CERBERUS_ADMIN_TOKEN=smoke \
	CERBERUS_AUDIT_DB="$TMPD/audit.db" \
	"$BIN" >"$TMPD/cerberus.log" 2>&1 &
PID=$!

BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 50); do
	curl -fsS "$BASE/readyz" >/dev/null 2>&1 && break
	sleep 0.1
done
curl -fsS "$BASE/readyz" >/dev/null 2>&1 || fail "not ready after 5s"

# 1. tool allow: k-glob's kubernetes* glob matches kubernetes_get_pods.
resp=$(curl -fsS -H 'Content-Type: application/json' \
	-d '{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_get_pods"}' \
	"$BASE/v1/decide/tool") || fail "decide allow request"
echo "$resp" | grep -q '"rule_id":"ai.tool.allow"' || fail "tool allow: $resp"

# 2. tool deny: restricted_tool_calls ["delete"] substring-matches.
resp=$(curl -fsS -H 'Content-Type: application/json' \
	-d '{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_delete_pod"}' \
	"$BASE/v1/decide/tool") || fail "decide deny request"
echo "$resp" | grep -q '"rule_id":"ai.tool.restricted"' || fail "tool deny: $resp"

# 3. masking: sk-… in args.cmd is redacted before the response leaves.
resp=$(curl -fsS -H 'Content-Type: application/json' \
	-d '{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"kubectl get pods --token sk-abc123"}}' \
	"$BASE/v1/decide/tool") || fail "masked decide request"
echo "$resp" | grep -q '\[REDACTED\]' || fail "masking: $resp"

# 4. admin without token → 401.
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/admin/data")
[ "$code" = "401" ] || fail "admin without token: want 401, got $code"

# 5. PUT data with token → epoch 2.
resp=$(curl -fsS -X PUT -H 'Authorization: Bearer smoke' -H 'Content-Type: application/json' \
	--data-binary @data/prod.json "$BASE/v1/admin/data") || fail "PUT /v1/admin/data"
echo "$resp" | grep -q '"epoch":2' || fail "put epoch: $resp"

# 6. SIGHUP → reload from disk → header epoch 3.
kill -HUP "$PID"
epoch=""
for _ in $(seq 1 50); do
	epoch=$(curl -fsS -D - -o /dev/null -H 'Authorization: Bearer smoke' "$BASE/v1/admin/data" |
		grep -i '^X-Cerberus-Epoch:' | tr -d '\r' | awk '{print $2}' || true)
	[ "$epoch" = "3" ] && break
	sleep 0.1
done
[ "$epoch" = "3" ] || fail "epoch after SIGHUP: want 3, got $epoch"

# 7. Prometheus metrics expose the decision counter.
curl -fsS "$BASE/metrics" | grep -q 'cerberus_decisions_total' ||
	fail "metrics missing cerberus_decisions_total"

echo "smoke: OK (7/7 checks passed)"
