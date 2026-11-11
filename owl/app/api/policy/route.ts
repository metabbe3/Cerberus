import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Read-only Rego source for the viewer. The engine has no "read policy"
// endpoint, so Owl reads the policy dir from its own filesystem — in compose
// both containers share the policies volume (see deploy/docker-compose.yml).
// ponytail: reads every *.rego under OWL_POLICY_DIR (default ../policies);
// a remote engine needs an engine-side policy read API first.
async function walk(dir: string, base = ""): Promise<{ path: string; content: string }[]> {
  const out: { path: string; content: string }[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name.startsWith("_")) continue;
    const rel = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...(await walk(path.join(dir, entry.name), rel)));
    } else if (entry.name.endsWith(".rego") && !entry.name.endsWith("_test.rego")) {
      out.push({ path: rel, content: await readFile(path.join(dir, entry.name), "utf8") });
    }
  }
  return out;
}

export async function GET() {
  try {
    const dir = process.env.OWL_POLICY_DIR ?? path.resolve(process.cwd(), "../policies");
    return Response.json({ files: await walk(dir) });
  } catch (e) {
    return toErrorResponse(e);
  }
}
