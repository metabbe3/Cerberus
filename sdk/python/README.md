# Cerberus Python SDK (`cerberus-sdk`)

Lightweight, zero-dependency Python client SDK for enforcing Cerberus policies on AI agent tool execution.

## Installation

```bash
pip install -e sdk/python
```

## Quickstart

```python
from cerberus_sdk import CerberusClient, GuardedExecutor, ErrDenied

client = CerberusClient(base_url="http://127.0.0.1:8089", key_id="k-agent-1")
guard = GuardedExecutor(client)

def run_bash(args):
    return f"Executed: {args.get('cmd')}"

try:
    result = guard.execute("bash", {"cmd": "ls -la"}, run_bash)
    print("Allowed:", result)
except ErrDenied as e:
    print(f"Blocked by rule {e.rule_id}: {e.reason}")
```
