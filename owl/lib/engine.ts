import "server-only";
import { NextResponse } from "next/server";
import { ZodError, z } from "zod";
import { AuditEventSchema, type AuditEvent } from "./schema";

// Server-side client for the Cerberus engine's admin API. All state lives in
// the engine — Owl is a stateless proxy. CERBERUS_ADMIN_TOKEN never leaves
// this module; the browser only ever talks to Owl's /api/* routes.

export class EngineError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "EngineError";
  }
}

// Error-message mapping, pinned by engine.test.ts: a 422 (or any JSON error
// body) carries the engine's validation message verbatim; 401 is always a
// token problem; other statuses hide their body behind a generic line.
export function engineMessage(status: number, body: string): string {
  if (status === 401) return "Unauthorized: check CERBERUS_ADMIN_TOKEN";
  try {
    const parsed = JSON.parse(body) as { error?: unknown };
    if (typeof parsed.error === "string" && parsed.error) return parsed.error;
  } catch {
    // not JSON
  }
  if (status === 422) return body.trim() || "Policy rejected";
  return `Engine request failed (HTTP ${status})`;
}

function engineEnv(): { url: string; token: string } {
  const token = process.env.CERBERUS_ADMIN_TOKEN;
  if (!token) {
    throw new EngineError(500, "CERBERUS_ADMIN_TOKEN is not set");
  }
  return { url: process.env.CERBERUS_URL ?? "http://localhost:8089", token };
}

async function engineFetch(path: string, init?: RequestInit): Promise<Response> {
  const { url, token } = engineEnv();
  let res: Response;
  try {
    res = await fetch(`${url}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        ...init?.headers,
      },
      cache: "no-store",
    });
  } catch {
    throw new EngineError(502, "Engine unreachable");
  }
  if (!res.ok) {
    throw new EngineError(res.status, engineMessage(res.status, await res.text()));
  }
  return res;
}

export async function getData(): Promise<{ data: unknown; epoch: number }> {
  const res = await engineFetch("/v1/admin/data");
  const epoch = Number(res.headers.get("X-Cerberus-Epoch") ?? 0);
  return { data: await res.json(), epoch: Number.isNaN(epoch) ? 0 : epoch };
}

export async function putData(data: unknown): Promise<{ epoch: number }> {
  const res = await engineFetch("/v1/admin/data", {
    method: "PUT",
    body: JSON.stringify(data),
  });
  return (await res.json()) as { epoch: number };
}

export async function validatePolicy(
  rego: string,
): Promise<{ ok: boolean; errors?: string[] }> {
  try {
    await engineFetch("/v1/admin/policy/validate", {
      method: "POST",
      body: JSON.stringify({ rego }),
    });
    return { ok: true };
  } catch (e) {
    // A 422 here is a validation verdict, not a fault — surface the errors.
    if (e instanceof EngineError && e.status === 422) {
      const parsed = JSON.parse(e.message) as { ok?: boolean; errors?: string[] };
      return { ok: false, errors: parsed.errors };
    }
    throw e;
  }
}

export async function reloadPolicy(): Promise<{ epoch: number }> {
  const res = await engineFetch("/v1/admin/reload", {
    method: "POST",
  });
  return (await res.json()) as { epoch: number };
}

export interface EngineStatus {
  bundle_epoch: number;
  revision: string;
  active_revision: string;
  policies_loaded_at: string;
  snapshot_age: string;
  last_reload: string;
  cache_hit_rate?: number;
  audit_queue_depth?: number;
}

export async function getStatus(): Promise<EngineStatus> {
  const res = await engineFetch("/v1/admin/status");
  return (await res.json()) as EngineStatus;
}

export async function postBreakGlass(data: {
  key_id?: string;
  duration_minutes?: number;
  reason?: string;
}): Promise<unknown> {
  const res = await engineFetch("/v1/admin/break-glass", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return await res.json();
}

// Raw upstream response for the SSE proxy — the route streams res.body
// straight to the client (no buffering layer of our own). The caller's
// abort signal (the browser disconnect) must reach the upstream fetch, or
// every disconnected client leaves a live subscriber on the engine.
export async function openEventStream(signal?: AbortSignal): Promise<Response> {
  const { url, token } = engineEnv();
  let res: Response;
  try {
    res = await fetch(`${url}/v1/events`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      signal,
    });
  } catch {
    throw new EngineError(502, "Engine unreachable");
  }
  if (!res.ok) {
    throw new EngineError(res.status, engineMessage(res.status, await res.text()));
  }
  return res;
}

// Query params pass through verbatim (key_id, stage, decision, rule_id,
// since RFC3339, limit) — Owl is not a second query language.
export async function queryAudit(params: URLSearchParams): Promise<AuditEvent[]> {
  const res = await engineFetch(`/v1/audit?${params.toString()}`);
  return AuditEventSchema.array().parse(await res.json());
}

export interface RegexTestResult {
  valid: boolean;
  error?: string;
  matches: boolean;
}

export async function testRegex(regex: string, testString?: string): Promise<RegexTestResult> {
  const res = await engineFetch("/v1/admin/regex/test", {
    method: "POST",
    body: JSON.stringify({ regex, test_string: testString ?? "" }),
  });
  return (await res.json()) as RegexTestResult;
}

export interface RevisionItem {
  id: number;
  time: string;
  author: string;
  summary: string;
  data_json?: string;
}

export async function getRevisions(limit = 50): Promise<RevisionItem[]> {
  const res = await engineFetch(`/v1/admin/revisions?limit=${limit}`);
  return (await res.json()) as RevisionItem[];
}

export async function rollbackData(revisionId?: number): Promise<{ ok: boolean; epoch: number; revision_id: number }> {
  const res = await engineFetch("/v1/admin/rollback", {
    method: "POST",
    body: JSON.stringify({ revision_id: revisionId ?? 0 }),
  });
  return (await res.json()) as { ok: boolean; epoch: number; revision_id: number };
}

// One error mapper for every /api route: EngineError carries its status and
// message (422 validation messages pass through verbatim), a malformed body
// or schema failure is the client's to fix (400), anything else is ours.
export function toErrorResponse(e: unknown): NextResponse {
  if (e instanceof EngineError) {
    return NextResponse.json({ error: e.message }, { status: e.status });
  }
  if (e instanceof ZodError) {
    return NextResponse.json(
      { error: "invalid data document", details: z.treeifyError(e) },
      { status: 400 },
    );
  }  console.error("owl: unhandled api error", e);
  return NextResponse.json({ error: "internal error" }, { status: 500 });
}
