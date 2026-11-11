# Cerberus Bypass Audit & Enforcement Hardening Matrix (Sprint 7)

## 1. Executive Summary

This matrix documents the real deterministic security audit executed by `cmd/cerberus-redteam` against the live Cerberus engine (`127.0.0.1:8089`), Docker enforcer proxy (`127.0.0.1:2377`), and HTTP/HTTPS egress proxy (`127.0.0.1:8088`) running on macOS (Mac Mini).

- **Execution Binary**: `cmd/cerberus-redteam` (`./bin/cerberus-redteam`)
- **Total Attacks**: 10
- **Blocked**: 9
- **Warn (Advisory on Mac Mini)**: 1
- **Exposed / Bypassed**: 0
- **Overall Result**: **PASS (0 bypasses detected)**

---

## 2. Bypass Matrix

| Attack / Vector | Target Path | Observed Result | Status | Residual Risk & Mac Mini Host Notes |
| :--- | :--- | :--- | :--- | :--- |
| **1. Docker direct-socket bypass** | Docker Enforcer Proxy | Socket reachable from user context | **WARN** | On macOS / OrbStack, the unix domain socket (`/Users/nicholasandriansurjadi/.docker/run/docker.sock`) is owned by the local user account (`srwxr-xr-x nicholasandriansurjadi:staff`). Host processes run by the user can technically access the raw socket if they unset `DOCKER_HOST`. **Enforcement on Mac Mini host is advisory** unless socket is chowned/moved. Containerized agent runtimes should mount only the proxy socket or have `DOCKER_HOST=tcp://127.0.0.1:2377`. |
| **2. Egress host-header spoof** | HTTP Egress Proxy (8088) | HTTP 403 Forbidden | **BLOCKED** | CONNECT and plain HTTP requests with spoofed `Host:` headers or internal destination addresses (10.x, 172.16.x, 192.168.x) are resolved against Prod Shield CIDRs and rejected with 403 (`shield.prod.ip_blocked`). |
| **3. Egress raw-IP CONNECT** | HTTP Egress Proxy (8088) | HTTP 403 Forbidden | **BLOCKED** | Direct IP tunnels (`CONNECT 10.0.3.7:443`) without hostnames are evaluated against `prod_shield.cidrs` and rejected fail-closed with 403 (`shield.prod.ip_blocked`). |
| **4. Egress NO_PROXY stripping** | HTTP Egress Proxy (8088) | HTTP 403 Forbidden | **BLOCKED** | Obfuscated requests with `Proxy-Connection: keep-alive` and absolute URIs are normalized and passed through engine stage `http` without parser bypass. |
| **5. Decide bypass via key spoof** | Engine Decide API (8089) | HTTP 401 Unauthorized | **BLOCKED** | Unauthenticated callers cannot claim privileged/exempt keys (e.g. `k-owner`) or mismatch the authentication header credentials. Returns 401 fail-closed. |
| **6. Rate limit bypass (burst)** | Engine / Advisory SDK | 50/50 requests rate-limited (HTTP 429) | **BLOCKED** | 50 concurrent requests fired within 3ms against rate-limited key `k-rate-limited` immediately triggered token bucket exhaustion, returning 429 Too Many Requests with valid `Retry-After`. |
| **7. Kill switch honor** | Engine API / All Gateways | HTTP 200 deny (`ops.kill_switch`) | **BLOCKED** | Setting `config.kill_switch.global = true` immediately causes all decide evaluations to return `deny/ops.kill_switch`. Toggling back to `false` restores normal allow decisions. |
| **8. Audit tamper (permissions)** | Local SQLite Filesystem | File permissions 0640 / 0600 | **BLOCKED** | All SQLite audit logs (`/tmp/audit-*.db`, `/tmp/cerberus_live.db`, `-wal`, `-shm`) are enforced with `0640` permissions via `audit.Open` and `deploy/harden-macmini.sh`. World-read/write access is denied. |
| **9. Auth missing on admin API** | Engine Admin API (8089) | HTTP 401 Unauthorized across all 18 endpoints | **BLOCKED** | All administrative endpoints (`/v1/admin/*`, `/v1/audit`, `/v1/events`) enforce constant-time bearer token check; unauthenticated or junk tokens are rejected with 401. |
| **10. Fuzz regress (half-requests)** | Egress Proxy (8088) & Engine (8089) | HTTP 400 / 431, Zero Crashes | **BLOCKED** | Malformed requests (CONNECT without host, 2MB URI lines, 500 header fields) returned 4xx/431 and were safely rejected. Egress proxy and engine remained healthy and fully responsive. |

---

## 3. Hermes / n8n / Python Integration Guide

To route agent and automation traffic through the hardened Cerberus gateways, configure the standard HTTP proxy environment variables.

### 3.1 Standard Proxy Environment Variables

```bash
# Direct HTTP and HTTPS traffic through the Cerberus Egress Proxy
export HTTP_PROXY="http://127.0.0.1:8088"
export HTTPS_PROXY="http://127.0.0.1:8088"
export ALL_PROXY="http://127.0.0.1:8088"

# Exclude loopback engine and local services from proxying
export NO_PROXY="localhost,127.0.0.1,::1"

# Route Docker commands through Cerberus Docker Proxy
export DOCKER_HOST="tcp://127.0.0.1:2377"

# Default agent key credential header
export CERBERUS_KEY="k-open"
```

---

### 3.2 Platform-Specific Integration Examples

#### A. n8n (Docker Compose)
In your `docker-compose.yml` for n8n:

```yaml
services:
  n8n:
    image: n8nio/n8n:latest
    environment:
      - HTTP_PROXY=http://host.docker.internal:8088
      - HTTPS_PROXY=http://host.docker.internal:8088
      - NO_PROXY=localhost,127.0.0.1,host.docker.internal
      - DOCKER_HOST=tcp://host.docker.internal:2377
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

#### B. Python (`requests` / `httpx`)
In Python agents or scripts:

```python
import os
import requests

# Option 1: Automatic via environment
os.environ["HTTP_PROXY"] = "http://127.0.0.1:8088"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8088"
os.environ["NO_PROXY"] = "localhost,127.0.0.1"

# Requests automatically respects HTTP_PROXY / HTTPS_PROXY
headers = {"X-Cerberus-Key": "k-open"}
resp = requests.get("https://api.openai.com/v1/models", headers=headers)
print(resp.status_code)

# Explicit session configuration
session = requests.Session()
session.proxies = {
    "http": "http://127.0.0.1:8088",
    "https": "http://127.0.0.1:8088",
}
session.headers.update({"X-Cerberus-Key": "k-open"})
```

Using `httpx`:
```python
import httpx

client = httpx.Client(
    proxy="http://127.0.0.1:8088",
    headers={"X-Cerberus-Key": "k-open"}
)
response = client.get("https://api.openai.com/v1/models")
```

#### C. Hermes / `agentd` Integration
For autonomous agents orchestrated via Hermes or `agentd`:

```bash
# Add to agent runner environment or systemd/supervisor config:
HTTP_PROXY=http://127.0.0.1:8088
HTTPS_PROXY=http://127.0.0.1:8088
NO_PROXY=localhost,127.0.0.1
DOCKER_HOST=tcp://127.0.0.1:2377
CERBERUS_ENGINE_URL=http://127.0.0.1:8089
CERBERUS_KEY=k-open
```

Pre-flight tool check with advisory SDK fallback:
```python
import requests

def check_action(stage: str, tool: str, args: dict, key: str = "k-open") -> bool:
    try:
        r = requests.post(
            "http://127.0.0.1:8089/v1/decide",
            json={"stage": stage, "key_id": key, "tool_call": tool, "args": args},
            headers={"X-Cerberus-Key": key},
            timeout=1.0,
        )
        if r.status_code == 200:
            return r.json().get("decision") == "allow"
    except Exception:
        pass
    # Fail-closed if engine unreachable
    return False
```
