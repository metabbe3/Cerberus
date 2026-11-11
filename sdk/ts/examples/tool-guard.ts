/**
 * Example: Guarding tool calls with Cerberus TypeScript SDK.
 * Mirrors the Go demo in /tmp/cerb-demo/main.go.
 */

import { CerberusClient, ErrDenied, GuardedExecutor } from "../dist/index.js";

async function main() {
  const baseUrl = process.env.CERBERUS_URL || "http://127.0.0.1:8089";
  const keyId = process.env.CERBERUS_KEY || "k-open";

  const client = new CerberusClient({ baseUrl, keyId });
  const guard = new GuardedExecutor(client);

  const runs = [
    { tool: "grep", desc: "grep aman (log aplikasi)", args: { cmd: "grep ERROR /var/log/app.log" } },
    { tool: "ssh", desc: "ssh root ke host asing", args: { host: "evil.example.com", user: "root" } },
    { tool: "shell", desc: "rm -rf / (dangerous pattern)", args: { cmd: "rm -rf /" } },
    { tool: "grep", desc: "grep wildcard /etc/passwd", args: { cmd: "grep * /etc/passwd" } },
  ];

  console.log(`Connecting to Cerberus at ${baseUrl} (keyId: ${keyId})...\n`);

  for (const r of runs) {
    try {
      const out = await guard.execute(r.tool, r.args, async (args) => {
        return "TOOL BERJALAN"; // Di engine asli: fungsi tool sebenarnya
      });
      console.log(`[ALLOWED] ${r.desc.padEnd(28)} -> ${out}`);
    } catch (err: any) {
      if (err instanceof ErrDenied) {
        console.log(`[BLOCKED] ${r.desc.padEnd(28)} -> ${err.message}`);
      } else {
        console.log(`[ERROR]   ${r.desc.padEnd(28)} -> ${err.message}`);
      }
    }
  }
}

main().catch(console.error);
