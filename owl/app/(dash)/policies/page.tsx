"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useData } from "@/lib/queries";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, CheckCircle2, Clock, GitCommit, Layers, RefreshCw } from "lucide-react";

interface EngineStatus {
  bundle_epoch: number;
  revision?: string;
  active_revision?: string;
  policies_loaded_at?: string;
  snapshot_age?: string;
  last_reload?: string;
}

export default function PoliciesPage() {
  const qc = useQueryClient();
  const [prevShield, setPrevShield] = useState<string | null>(null);
  const [reloadMsg, setReloadMsg] = useState<string | null>(null);

  // 1. Fetch engine status
  const statusQuery = useQuery<EngineStatus>({
    queryKey: ["status"],
    queryFn: async () => {
      const res = await fetch("/api/status");
      if (!res.ok) throw new Error(`GET /api/status failed (${res.status})`);
      return res.json();
    },
    refetchInterval: 5000,
  });

  // 2. Fetch data document for prod_shield
  const { data: owlData, isLoading: dataLoading } = useData();
  const currentShield = owlData?.data.prod_shield ?? {};
  const currentShieldStr = JSON.stringify(currentShield, null, 2);

  // Store & compare previous prod_shield snapshot from localStorage
  useEffect(() => {
    if (typeof window === "undefined") return;
    const stored = localStorage.getItem("cerberus_prev_prod_shield");
    if (stored) {
      setPrevShield(stored);
    }
  }, []);

  const saveCurrentSnapshot = () => {
    if (typeof window !== "undefined" && currentShieldStr) {
      localStorage.setItem("cerberus_prev_prod_shield", currentShieldStr);
      setPrevShield(currentShieldStr);
    }
  };

  // 3. Reload policy mutation
  const reloadMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/policy/reload", { method: "POST" });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "reload failed");
      return body as { epoch: number };
    },
    onSuccess: (data) => {
      setReloadMsg(`Policy reloaded successfully (New Epoch: ${data.epoch})`);
      qc.invalidateQueries({ queryKey: ["status"] });
      qc.invalidateQueries({ queryKey: ["data"] });
      saveCurrentSnapshot();
    },
  });

  // JSON Diff ringkas: compare current vs prevShield
  const computeDiff = () => {
    if (!prevShield) {
      return { status: "no_baseline", changes: [] };
    }
    try {
      const prev = JSON.parse(prevShield);
      const curr = currentShield as Record<string, unknown>;
      const allKeys = Array.from(new Set([...Object.keys(prev), ...Object.keys(curr)]));

      const changes: { key: string; type: "added" | "removed" | "modified"; prevVal: unknown; currVal: unknown }[] = [];

      for (const k of allKeys) {
        const inPrev = k in prev;
        const inCurr = k in curr;
        if (!inPrev && inCurr) {
          changes.push({ key: k, type: "added", prevVal: undefined, currVal: curr[k] });
        } else if (inPrev && !inCurr) {
          changes.push({ key: k, type: "removed", prevVal: prev[k], currVal: undefined });
        } else if (JSON.stringify(prev[k]) !== JSON.stringify(curr[k])) {
          changes.push({ key: k, type: "modified", prevVal: prev[k], currVal: curr[k] });
        }
      }
      return { status: "compared", changes };
    } catch {
      return { status: "error", changes: [] };
    }
  };

  const diffResult = computeDiff();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Policies & Bundle"
        description="View active policy revision, inspect Production Shield configuration diffs, and reload policies."
      >
        <Button
          onClick={() => reloadMutation.mutate()}
          disabled={reloadMutation.isPending}
          className="flex items-center gap-1.5"
        >
          <RefreshCw className={`size-4 ${reloadMutation.isPending ? "animate-spin" : ""}`} />
          Reload Policy
        </Button>
      </PageHeader>

      {reloadMsg && (
        <Alert>
          <CheckCircle2 className="text-green-500" />
          <AlertTitle>Reload Complete</AlertTitle>
          <AlertDescription>{reloadMsg}</AlertDescription>
        </Alert>
      )}

      {reloadMutation.isError && (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Reload failed</AlertTitle>
          <AlertDescription>{(reloadMutation.error as Error).message}</AlertDescription>
        </Alert>
      )}

      {/* Revision & Epoch Information */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Revision</CardTitle>
            <GitCommit className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {statusQuery.isLoading ? (
              <Skeleton className="h-7 w-28" />
            ) : (
              <div className="text-xl font-mono font-bold">
                {statusQuery.data?.active_revision || statusQuery.data?.revision || "dev"}
              </div>
            )}
            <p className="text-xs text-muted-foreground mt-1">Git commit / bundle digest</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Policy Epoch</CardTitle>
            <Layers className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {statusQuery.isLoading ? (
              <Skeleton className="h-7 w-16" />
            ) : (
              <div className="text-2xl font-bold">
                #{statusQuery.data?.bundle_epoch ?? 0}
              </div>
            )}
            <p className="text-xs text-muted-foreground mt-1">Increments on every reload</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Snapshot Age</CardTitle>
            <Clock className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {statusQuery.isLoading ? (
              <Skeleton className="h-7 w-24" />
            ) : (
              <div className="text-xl font-bold">
                {statusQuery.data?.snapshot_age || "just now"}
              </div>
            )}
            <p className="text-xs text-muted-foreground mt-1">
              Loaded: {statusQuery.data?.last_reload ? new Date(statusQuery.data.last_reload).toLocaleTimeString() : "N/A"}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Diff data.prod_shield vs Sebelumnya */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base font-semibold">
                data.prod_shield Diff (vs Previous Snapshot)
              </CardTitle>
              <CardDescription>
                Summary of changes between the live Production Shield data and the last saved baseline.
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={saveCurrentSnapshot}>
              Mark Current as Baseline
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {diffResult.status === "no_baseline" ? (
            <div className="rounded-md border border-dashed p-4 text-center text-sm text-muted-foreground">
              No previous snapshot saved. Click &ldquo;Mark Current as Baseline&rdquo; or reload policy to record baseline.
            </div>
          ) : diffResult.changes.length === 0 ? (
            <div className="flex items-center gap-2 rounded-md border border-green-500/20 bg-green-500/10 p-3 text-sm text-green-700 dark:text-green-400">
              <CheckCircle2 className="size-4" />
              <span>No changes in data.prod_shield compared to baseline snapshot.</span>
            </div>
          ) : (
            <div className="space-y-2">
              {diffResult.changes.map((ch) => (
                <div
                  key={ch.key}
                  className="rounded-md border p-3 font-mono text-xs flex flex-col gap-1 bg-muted/30"
                >
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        ch.type === "added"
                          ? "default"
                          : ch.type === "removed"
                          ? "destructive"
                          : "secondary"
                      }
                    >
                      {ch.type}
                    </Badge>
                    <span className="font-semibold text-foreground">{ch.key}</span>
                  </div>
                  {ch.type === "modified" && (
                    <div className="grid grid-cols-2 gap-2 mt-1">
                      <div className="rounded bg-red-500/10 p-2 text-red-600 dark:text-red-400 overflow-auto max-h-32">
                        - {JSON.stringify(ch.prevVal, null, 2)}
                      </div>
                      <div className="rounded bg-green-500/10 p-2 text-green-600 dark:text-green-400 overflow-auto max-h-32">
                        + {JSON.stringify(ch.currVal, null, 2)}
                      </div>
                    </div>
                  )}
                  {ch.type === "added" && (
                    <div className="rounded bg-green-500/10 p-2 text-green-600 dark:text-green-400 overflow-auto max-h-32 mt-1">
                      + {JSON.stringify(ch.currVal, null, 2)}
                    </div>
                  )}
                  {ch.type === "removed" && (
                    <div className="rounded bg-red-500/10 p-2 text-red-600 dark:text-red-400 overflow-auto max-h-32 mt-1">
                      - {JSON.stringify(ch.prevVal, null, 2)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Current data.prod_shield Document */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base font-semibold">Active data.prod_shield Configuration</CardTitle>
          <CardDescription>Live JSON document governing Production Shield enforcement.</CardDescription>
        </CardHeader>
        <CardContent>
          {dataLoading ? (
            <Skeleton className="h-48 w-full" />
          ) : (
            <pre className="max-h-96 overflow-auto rounded-md border bg-muted/50 p-4 font-mono text-xs leading-relaxed">
              {currentShieldStr}
            </pre>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
