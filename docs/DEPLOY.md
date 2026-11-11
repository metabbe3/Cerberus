# Deploying Cerberus (All Platforms)

Cerberus ships as two static binaries (CGO_ENABLED=0): `cerberus` (engine) and `cerberus-proxy` (Docker socket-proxy + HTTP egress enforcer). Build for any OS with `make build-all` (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 → `dist/`).

## Environment Variables

| Variable | Engine | Proxy | Notes |
|---|---|---|---|
| `CERBERUS_ADDR` | ✅ | | listen address (default 127.0.0.1:8089) |
| `CERBERUS_POLICY_DIR` | ✅ | ✅ | dir with `stages/*.rego` |
| `CERBERUS_DATA_FILE` | ✅ | ✅ | data JSON (config/teams/agents/ssh/prod_shield) |
| `CERBERUS_AUDIT_DB` | ✅ | ✅ | SQLite audit path (enforced 0640) |
| `CERBERUS_ADMIN_TOKEN` | ✅ | ✅ | admin bearer token |
| `CERBERUS_PROXY_LISTEN` | | ✅ | docker proxy listen (e.g. 127.0.0.1:2377) |
| `CERBERUS_PROXY_DOCKER_HOST` | | ✅ | upstream docker socket |
| `CERBERUS_PROXY_EGRESS_ADDR` | | ✅ | HTTP egress listen (e.g. 127.0.0.1:8088) |
| `CERBERUS_PROXY_DEFAULT_KEY` | | ✅ | key_id for unauthenticated callers |

## Per-OS

| OS | Mechanism | Files |
|---|---|---|
| Linux | systemd | `deploy/systemd/cerberus-engine.service`, `cerberus-proxy.service` (Restart=always, ProtectSystem=strict, NoNewPrivileges, PrivateTmp, EnvironmentFile=/etc/cerberus/cerberus.env) |
| macOS | launchd | `deploy/launchd/com.cerberus.engine.plist`, `com.cerberus.proxy.plist` (KeepAlive, RunAtLoad) — load: `launchctl load ~/Library/LaunchAgents/com.cerberus.engine.plist` |
| Any | Docker | `deploy/Dockerfile` (distroless/static nonroot) + `deploy/docker-compose.yml` |
| Windows | manual/NSSM | run `cerberus.exe -addr ...`; register with `nssm install Cerberus cerberus.exe` |

## Verify After Deploy

1. `curl http://127.0.0.1:8089/healthz` → `ok`
2. Run the QA suite: `cerberus-redteam -engine-url http://127.0.0.1:8089 ...` → expect `OVERALL: PASS`
3. Proxy: `DOCKER_HOST=tcp://127.0.0.1:2377 docker ps` → 200
4. Egress: `curl -x http://127.0.0.1:8088 http://10.0.0.1/` → 403 (fail-closed against prod CIDRs)

## Integration (agents)

Set `HTTP_PROXY`/`HTTPS_PROXY=http://host:8088` (+ `NO_PROXY=localhost,127.0.0.1`) for any agent runtime (n8n env block, Python requests, Node, agentd). Docker clients: `DOCKER_HOST=tcp://host:2377`. See `docs/BYPASS_MATRIX.md` for the enforcement levels.
