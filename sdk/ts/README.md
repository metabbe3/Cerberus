# Cerberus TypeScript SDK (`cerberus-sdk`)

Lightweight, zero-dependency TypeScript/JavaScript client SDK for enforcing Cerberus policies on AI agent tool execution.

## Installation

```bash
npm install ./sdk/ts
```

## Quickstart

```typescript
import { CerberusClient, GuardedExecutor, ErrDenied } from "cerberus-sdk";

const client = new CerberusClient({
  baseUrl: "http://127.0.0.1:8089",
  keyId: "k-agent-1",
});

const guard = new GuardedExecutor(client);

async function runBash(args: { cmd: string }) {
  return `Executed: ${args.cmd}`;
}

try {
  const result = await guard.execute("bash", { cmd: "ls -la" }, runBash);
  console.log("Allowed:", result);
} catch (err) {
  if (err instanceof ErrDenied) {
    console.error(`Blocked by rule ${err.rule_id}: ${err.reason}`);
  }
}
```
