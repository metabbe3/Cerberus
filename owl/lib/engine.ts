import "server-only";
import { NextResponse } from "next/server";
import { ZodError, z } from "zod";
import { SESSION_COOKIE, extractSessionToken } from "./session";
import {
  AuditEventSchema,
  type AuditEvent,
  type UpstreamConfig,
  type BreachResult,
  type AgentSummary,
  type RotateKeyResult,
  type PolicyModuleItem,
  type TestRunResponse,
} from "./schema";

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

async function getActiveAuthToken(defaultToken: string): Promise<string> {
  try {
    const { cookies } = await import("next/headers");
    const cookieStore = await cookies();
    const cookieVal = cookieStore.get(SESSION_COOKIE)?.value;
    if (cookieVal) {
      const extracted = extractSessionToken(cookieVal);
      if (extracted) return extracted;
      return cookieVal;
    }
  } catch {
    // Outside request context (e.g. static site generation or build time)
  }
  return defaultToken;
}

async function engineFetch(path: string, init?: RequestInit): Promise<Response> {
  const { url, token: adminToken } = engineEnv();
  const bearerToken = await getActiveAuthToken(adminToken);
  let res: Response;
  try {
    res = await fetch(`${url}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${bearerToken}`,
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
  top_denies_24h?: Array<{ rule_id: string; count: number }>;
  deny_24h_top10?: Array<{ rule_id: string; count: number }>;
  latency_p50_us?: number;
  latency_p95_us?: number;
  latency_p99_us?: number;
  latency_sparkline?: number[];
  fail_closed_count?: number;
  fail_closed_rate?: number;
}

export async function getStatus(): Promise<EngineStatus> {
  const res = await engineFetch("/v1/admin/status");
  return (await res.json()) as EngineStatus;
}

export interface BreakGlassStatus {
  active: boolean;
  reason: string;
  global_expires_at?: string;
  key_expires_at?: string;
}

export async function getBreakGlass(keyId?: string): Promise<BreakGlassStatus> {
  const q = keyId ? `?key_id=${encodeURIComponent(keyId)}` : "";
  const res = await engineFetch(`/v1/admin/break-glass${q}`);
  return (await res.json()) as BreakGlassStatus;
}

export async function deleteBreakGlass(keyId?: string): Promise<{ status: string; key_id?: string }> {
  const q = keyId ? `?key_id=${encodeURIComponent(keyId)}` : "";
  const res = await engineFetch(`/v1/admin/break-glass${q}`, { method: "DELETE" });
  return (await res.json()) as { status: string; key_id?: string };
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

export async function getUpstream(): Promise<UpstreamConfig> {
  const res = await engineFetch("/v1/admin/upstream");
  return (await res.json()) as UpstreamConfig;
}

export async function putUpstream(payload: {
  endpoint: string;
  api_key?: string;
}): Promise<UpstreamConfig> {
  const res = await engineFetch("/v1/admin/upstream", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  return (await res.json()) as UpstreamConfig;
}

export async function testUpstream(payload: {
  endpoint: string;
  api_key?: string;
}): Promise<{ ok: boolean; latency_ms?: number; error?: string }> {
  const res = await engineFetch("/v1/admin/upstream/test", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return (await res.json()) as { ok: boolean; latency_ms?: number; error?: string };
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

export async function rollbackBundle(): Promise<{ ok: boolean; epoch: number; revision: string }> {
  const res = await engineFetch("/v1/admin/bundle/rollback", {
    method: "POST",
  });
  return (await res.json()) as { ok: boolean; epoch: number; revision: string };
}

export async function getActiveBundle(): Promise<Response> {
  return engineFetch("/v1/admin/bundle");
}

export interface TraceEntry {
  op: string;
  rule?: string;
  location?: string;
  result?: string;
}

export interface ExplainResult {
  decision: string;
  rule_id: string;
  reason: string;
  epoch: number;
  trace: TraceEntry[];
  pretty_trace?: string;
}

export async function explainDecision(input: unknown): Promise<ExplainResult> {
  const res = await engineFetch("/v1/admin/explain", {
    method: "POST",
    body: JSON.stringify(input),
  });
  return (await res.json()) as ExplainResult;
}

export async function eraseDecision(id: number): Promise<{ ok: boolean; erased: number }> {
  const res = await engineFetch("/v1/admin/decisions/erase", {
    method: "POST",
    body: JSON.stringify({ id }),
  });
  return (await res.json()) as { ok: boolean; erased: number };
}

export interface FileCoverage {
  coverage: number;
  covered_lines: number;
  not_covered_lines: number;
}

export interface CoverageReport {
  coverage: number;
  covered_lines: number;
  not_covered_lines: number;
  total_lines: number;
  files: Record<string, FileCoverage>;
}

export async function getCoverage(): Promise<CoverageReport> {
  const res = await engineFetch("/v1/admin/coverage");
  return (await res.json()) as CoverageReport;
}

export interface ReplayDiff {
  event_id: number;
  time: string;
  stage: string;
  key_id: string;
  subject: string;
  old_decision: string;
  new_decision: string;
  old_rule_id: string;
  new_rule_id: string;
  old_reason: string;
  new_reason: string;
  shift: "stricter" | "looser" | "rule_changed";
}

export interface ReplayReport {
  total_evaluated: number;
  unchanged_count: number;
  diff_count: number;
  stricter_count: number;
  looser_count: number;
  rule_changed_count: number;
  diffs: ReplayDiff[];
}

export async function replayAudit(limit = 500, data?: unknown): Promise<ReplayReport> {
  const body: Record<string, unknown> = { limit };
  if (data !== undefined) {
    body.data = data;
  }
  const res = await engineFetch("/v1/admin/replay", {
    method: "POST",
    body: JSON.stringify(body),
  });
  return (await res.json()) as ReplayReport;
}

export async function getBreaches(params: URLSearchParams): Promise<BreachResult> {
  const res = await engineFetch(`/v1/audit/breaches?${params.toString()}`);
  return (await res.json()) as BreachResult;
}

export async function getAgentsSummary(since?: string): Promise<AgentSummary[]> {
  const query = since ? `?since=${encodeURIComponent(since)}` : "";
  const res = await engineFetch(`/v1/audit/agents-summary${query}`);
  return (await res.json()) as AgentSummary[];
}

export async function rotateKey(
  keyId: string,
  options?: { revoke_old?: boolean; suffix?: string; new_key_id?: string },
): Promise<RotateKeyResult> {
  const res = await engineFetch(`/v1/admin/keys/${encodeURIComponent(keyId)}/rotate`, {
    method: "POST",
    body: JSON.stringify(options ?? {}),
  });
  return (await res.json()) as RotateKeyResult;
}

export async function getPolicyModules(): Promise<PolicyModuleItem[]> {
  const res = await engineFetch("/v1/policy/modules");
  return (await res.json()) as PolicyModuleItem[];
}

export async function runPolicyTests(): Promise<TestRunResponse> {
  const res = await engineFetch("/v1/policy/test-run", {
    method: "POST",
  });
  return (await res.json()) as TestRunResponse;
}

export interface UserItem {
  id: number;
  username: string;
  role: "admin" | "viewer";
  disabled: boolean;
  created_at: string;
  last_login_at?: string;
}

export async function getCurrentUser(): Promise<UserItem | null> {
  try {
    const res = await engineFetch("/v1/auth/me");
    const body = (await res.json()) as { user?: UserItem };
    return body.user ?? null;
  } catch {
    return null;
  }
}

export async function getUsers(): Promise<UserItem[]> {
  const res = await engineFetch("/v1/admin/users");
  return (await res.json()) as UserItem[];
}

export async function createUser(data: {
  username: string;
  role: string;
  password: string;
}): Promise<UserItem> {
  const res = await engineFetch("/v1/admin/users", {
    method: "POST",
    body: JSON.stringify(data),
  });
  const body = (await res.json()) as { user: UserItem };
  return body.user;
}

export async function setUserDisabled(id: number, disabled: boolean): Promise<void> {
  await engineFetch(`/v1/admin/users/${id}/disable`, {
    method: "POST",
    body: JSON.stringify({ disabled }),
  });
}

export async function resetUserPassword(id: number, password: string): Promise<void> {
  await engineFetch(`/v1/admin/users/${id}/reset-password`, {
    method: "POST",
    body: JSON.stringify({ password }),
  });
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
