"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AuditEventSchema, parseData, type Agent, type AuditEvent, type CerberusData } from "./schema";

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
