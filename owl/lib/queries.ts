"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AuditEventSchema,
  parseData,
  type Agent,
  type AuditEvent,
  type CerberusData,
  type BreachResult,
  type AgentSummary,
  type RotateKeyResult,
  type PolicyModuleItem,
  type TestRunResponse,
} from "./schema";

// The one server-state hook for the data document: every page reads the
// engine's data through this same ["data"] cache entry, so a PUT elsewhere
// invalidates everywhere.
export type OwlData = { data: CerberusData; epoch: number };

async function fetchData(): Promise<OwlData> {
  const res = await fetch("/api/data");
  const body = (await res.json()) as { data?: unknown; epoch?: number; error?: string };
  if (!res.ok) throw new Error(body.error ?? `GET /api/data failed (${res.status})`);
  return { data: parseData(body.data), epoch: body.epoch ?? 0 };
}

export function useData() {
  return useQuery({ queryKey: ["data"], queryFn: fetchData });
}

// Newest-first decision history; params are the engine's filter params
// (key_id, stage, decision, rule_id, since, limit) passed through verbatim.
export function useAudit(params: URLSearchParams) {
  return useQuery({
    queryKey: ["audit", params.toString()],
    queryFn: async (): Promise<AuditEvent[]> => {
      const res = await fetch(`/api/audit?${params.toString()}`);
      const body = await res.json();
      if (!res.ok) {
        throw new Error((body as { error?: string }).error ?? "audit query failed");
      }
      return AuditEventSchema.array().parse(body);
    },
  });
}

// One PUT for the whole data document; both the agent editor and settings
// clone the live doc, patch it, and hand the result here. An engine 422
// throws with its message verbatim; the live cache is untouched until the
// engine confirms.
export function usePutData() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (next: CerberusData) => {
      const res = await fetch("/api/data", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parseData(next)),
      });
      const out = (await res.json()) as { epoch?: number; error?: string };
      if (!res.ok) throw new Error(out.error ?? `PUT /api/data failed (${res.status})`);
      return out as { epoch: number };
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["data"] }),
  });
}

// Save = clone the live document, replace one agent, zod-parse, PUT.
export function useSaveAgent() {
  const { data: current } = useData();
  const put = usePutData();
  return useMutation({
    mutationFn: async ({ keyId, agent }: { keyId: string; agent: Agent }) => {
      if (!current) throw new Error("no data loaded");
      const next = structuredClone(current.data);
      next.agents[keyId] = agent;
      return put.mutateAsync(next);
    },
  });
}

// Delete = clone live document, remove agent key, PUT.
export function useDeleteAgent() {
  const { data: current } = useData();
  const put = usePutData();
  return useMutation({
    mutationFn: async (keyId: string) => {
      if (!current) throw new Error("no data loaded");
      const next = structuredClone(current.data);
      delete next.agents[keyId];
      return put.mutateAsync(next);
    },
  });
}

export function useToggleKillSwitch() {
  const { data: current } = useData();
  const put = usePutData();
  return useMutation({
    mutationFn: async ({ keyId, active }: { keyId: string; active: boolean }) => {
      if (!current) throw new Error("no data loaded");
      const next = structuredClone(current.data);
      if (!next.config) next.config = {};
      if (!next.config.kill_switch) next.config.kill_switch = {};
      if (!next.config.kill_switch.keys) next.config.kill_switch.keys = {};
      if (active) {
        next.config.kill_switch.keys[keyId] = true;
      } else {
        delete next.config.kill_switch.keys[keyId];
      }
      return put.mutateAsync(next);
    },
  });
}

export function useBreakGlass() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ keyId, reason, durationMinutes }: { keyId: string; reason: string; durationMinutes?: number }) => {
      const res = await fetch("/api/admin/break-glass", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key_id: keyId, reason, duration_minutes: durationMinutes ?? 15 }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || "Failed to activate break glass");
      }
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["break-glass"] });
      qc.invalidateQueries({ queryKey: ["data"] });
      qc.invalidateQueries({ queryKey: ["components"] });
    },
  });
}

export interface BreakGlassData {
  active: boolean;
  reason: string;
  global_expires_at?: string;
  key_expires_at?: string;
}

export function useBreakGlassStatus(keyId?: string) {
  return useQuery({
    queryKey: ["break-glass", keyId ?? ""],
    queryFn: async (): Promise<BreakGlassData> => {
      const q = keyId ? `?key_id=${encodeURIComponent(keyId)}` : "";
      const res = await fetch(`/api/admin/break-glass${q}`);
      if (!res.ok) return { active: false, reason: "" };
      return res.json();
    },
    refetchInterval: 5_000,
  });
}

export function useRevokeBreakGlass() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (keyId?: string) => {
      const q = keyId ? `?key_id=${encodeURIComponent(keyId)}` : "";
      const res = await fetch(`/api/admin/break-glass${q}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Gagal mencabut break-glass");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["break-glass"] });
      qc.invalidateQueries({ queryKey: ["data"] });
      qc.invalidateQueries({ queryKey: ["components"] });
    },
  });
}

export interface ComponentHealth {
  component: string;
  status: "ok" | "degraded" | "down";
  detail: string;
  meta?: Record<string, unknown>;
}

export function useComponents() {
  return useQuery({
    queryKey: ["components"],
    queryFn: async (): Promise<ComponentHealth[]> => {
      const res = await fetch("/api/components");
      if (!res.ok) throw new Error("Gagal memuat status komponen");
      const body = await res.json();
      return (body as { components: ComponentHealth[] }).components;
    },
    refetchInterval: 15_000,
  });
}

export interface EngineStatusData {
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

export function useStatus() {
  return useQuery({
    queryKey: ["status"],
    queryFn: async (): Promise<EngineStatusData> => {
      const res = await fetch("/api/status");
      const body = await res.json();
      if (!res.ok) throw new Error((body as { error?: string }).error ?? "status failed");
      return body as EngineStatusData;
    },
    refetchInterval: 15_000,
  });
}

export interface RevisionData {
  id: number;
  time: string;
  author: string;
  summary: string;
  data_json?: string;
}

export function useRevisions() {
  return useQuery({
    queryKey: ["revisions"],
    queryFn: async (): Promise<RevisionData[]> => {
      const res = await fetch("/api/admin/revisions");
      if (!res.ok) throw new Error("Gagal mengambil histori revisi");
      return res.json();
    },
  });
}

export function useRollback() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (revisionId?: number) => {
      const res = await fetch("/api/admin/rollback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ revision_id: revisionId }),
      });
      const data = (await res.json()) as { ok?: boolean; epoch?: number; revision_id?: number; error?: string };
      if (!res.ok) throw new Error(data.error ?? "Gagal rollback revisi");
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["data"] });
      qc.invalidateQueries({ queryKey: ["revisions"] });
    },
  });
}

// Live + history, newest-first. The engine replays its last-50 ring on every
// (re)connect and the history page already contains those rows, so duplicates
// are dropped by id — first occurrence wins (live rows sit ahead of history).
export function mergeEvents(
  live: AuditEvent[],
  history: AuditEvent[],
  cap = 200,
): AuditEvent[] {
  const seen = new Set<number>();
  const out: AuditEvent[] = [];
  for (const e of [...live].reverse().concat(history)) {
    if (seen.has(e.id)) continue;
    seen.add(e.id);
    out.push(e);
  }
  return out.slice(0, cap);
}

export function useBreaches(params: URLSearchParams) {
  return useQuery({
    queryKey: ["breaches", params.toString()],
    queryFn: async (): Promise<BreachResult> => {
      const res = await fetch(`/api/audit/breaches?${params.toString()}`);
      const body = await res.json();
      if (!res.ok) {
        throw new Error((body as { error?: string }).error ?? "breaches query failed");
      }
      return body as BreachResult;
    },
  });
}

export function useAgentsSummary(since = "24h") {
  return useQuery({
    queryKey: ["agents-summary", since],
    queryFn: async (): Promise<AgentSummary[]> => {
      const res = await fetch(`/api/audit/agents-summary?since=${encodeURIComponent(since)}`);
      const body = await res.json();
      if (!res.ok) {
        throw new Error((body as { error?: string }).error ?? "agents summary query failed");
      }
      return body as AgentSummary[];
    },
  });
}

export function useRotateKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      keyId,
      revoke_old = false,
      suffix,
      new_key_id,
    }: {
      keyId: string;
      revoke_old?: boolean;
      suffix?: string;
      new_key_id?: string;
    }): Promise<RotateKeyResult> => {
      const res = await fetch(`/api/admin/keys/${encodeURIComponent(keyId)}/rotate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ revoke_old, suffix, new_key_id }),
      });
      const data = (await res.json()) as RotateKeyResult & { error?: string };
      if (!res.ok) throw new Error(data.error ?? "Failed to rotate key");
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["data"] });
      qc.invalidateQueries({ queryKey: ["agents-summary"] });
    },
  });
}

export function usePolicyModules() {
  return useQuery({
    queryKey: ["policy-modules"],
    queryFn: async (): Promise<PolicyModuleItem[]> => {
      const res = await fetch("/api/policy/modules");
      const body = await res.json();
      if (!res.ok) {
        throw new Error((body as { error?: string }).error ?? "failed to fetch policy modules");
      }
      return body as PolicyModuleItem[];
    },
  });
}

export function useRunPolicyTests() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (): Promise<TestRunResponse> => {
      const res = await fetch("/api/policy/test-run", {
        method: "POST",
      });
      const body = (await res.json()) as TestRunResponse & { error?: string };
      if (!res.ok) {
        throw new Error(body.error ?? "failed to run policy tests");
      }
      return body;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit"] });
      qc.invalidateQueries({ queryKey: ["breaches"] });
    },
  });
}
