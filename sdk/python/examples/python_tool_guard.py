#!/usr/bin/env python3
"""Example: Guarding tool calls with Cerberus Python SDK.

Mirrors the Go demo in /tmp/cerb-demo/main.go:
- Grep aman: ALLOWED
- SSH root ke host asing: BLOCKED
- Shell rm -rf /: BLOCKED
- Grep wildcard /etc/passwd: BLOCKED
"""

import os
import sys
from pathlib import Path

# Add sdk/python to sys.path if running directly from repo root
sdk_path = Path(__file__).resolve().parent.parent / "sdk" / "python"
if str(sdk_path) not in sys.path:
    sys.path.insert(0, str(sdk_path))

from cerberus_sdk import CerberusClient, ErrDenied, GuardedExecutor


def main():
    base_url = os.environ.get("CERBERUS_URL", "http://127.0.0.1:8089")
    key_id = os.environ.get("CERBERUS_KEY", "k-open")

    client = CerberusClient(base_url=base_url, key_id=key_id)
    guard = GuardedExecutor(client)

    runs = [
        {"tool": "grep", "desc": "grep aman (log aplikasi)", "args": {"cmd": "grep ERROR /var/log/app.log"}},
        {"tool": "ssh", "desc": "ssh root ke host asing", "args": {"host": "evil.example.com", "user": "root"}},
        {"tool": "shell", "desc": "rm -rf / (dangerous pattern)", "args": {"cmd": "rm -rf /"}},
        {"tool": "grep", "desc": "grep wildcard /etc/passwd", "args": {"cmd": "grep * /etc/passwd"}},
    ]

    print(f"Connecting to Cerberus at {base_url} (key_id: {key_id})...\n")

    for r in runs:
        try:
            out = guard.execute(
                r["tool"],
                r["args"],
                lambda args: "TOOL BERJALAN",  # Di engine aslimu: fungsi tool sebenarnya
            )
            print(f"[ALLOWED] {r['desc']:<28} -> {out}")
        except ErrDenied as e:
            print(f"[BLOCKED] {r['desc']:<28} -> {e}")
        except Exception as e:
            print(f"[ERROR]   {r['desc']:<28} -> {e}")


if __name__ == "__main__":
    main()
