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
