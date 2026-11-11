"use client";

import { useQuery } from "@tanstack/react-query";
import { parseData, type CerberusData } from "./schema";

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
