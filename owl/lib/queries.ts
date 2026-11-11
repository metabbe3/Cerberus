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

// Save = clone the live document, replace one agent, zod-parse, PUT. An
// engine 422 throws with its message verbatim; the live cache is untouched.
export function useSaveAgent() {
  const qc = useQueryClient();
  const { data: current } = useData();
  return useMutation({
    mutationFn: async ({ keyId, agent }: { keyId: string; agent: Agent }) => {
      if (!current) throw new Error("no data loaded");
      const next = structuredClone(current.data);
      next.agents[keyId] = agent;
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
