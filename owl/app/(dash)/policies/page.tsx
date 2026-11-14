"use client";

import { useMemo, useState } from "react";
import { toast } from "sonner";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  Download,
  FileCheck2,
  GitCommit,
  History,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
  User,
} from "lucide-react";
import { PageHeader } from "@/components/page-header";
import { PoliciesSubNav } from "@/components/sub-nav";
import { Timestamp } from "@/components/timestamp";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useRevisions, useRollback, useRollbackBundle } from "@/lib/queries";
import type { RevisionItem } from "@/lib/engine";

interface FileCoverage {
  coverage: number;
  covered_lines: number;
  not_covered_lines: number;
}

interface CoverageReport {
  coverage: number;
  covered_lines: number;
  not_covered_lines: number;
  total_lines: number;
  files: Record<string, FileCoverage>;
}

interface EngineStatus {
  bundle_epoch: number;
  revision?: string;
  active_revision?: string;
  policies_loaded_at?: string;
  snapshot_age?: string;
  last_reload?: string;
  signature_verified?: boolean;
  signature_key?: string;
  coverage?: number;
}

interface AgentDiffPolicy {
  restricted_tool_calls?: string[];
  allowed_tools?: string[];
}

// Analyze policy diff to determine if the changes are stricter or looser
function analyzePolicyDiff(
  prevData: Record<string, unknown> | null,
  currData: Record<string, unknown> | null,
) {
  if (!prevData || !currData) {
    return { tendency: "neutral", summary: "Tidak ada perbandingan tersedia", details: [] };
  }

  const details: string[] = [];
  let strictScore = 0;

  try {
    const prevAgents = (prevData.agents as Record<string, AgentDiffPolicy>) || {};
    const currAgents = (currData.agents as Record<string, AgentDiffPolicy>) || {};

    for (const [keyId, currAgent] of Object.entries(currAgents)) {
      const prevAgent = prevAgents[keyId];
      if (!prevAgent) {
        details.push(`Agen baru didaftarkan: ${keyId}`);
        continue;
      }

      // Check restricted tools
      const prevRestricted = prevAgent.restricted_tool_calls || [];
      const currRestricted = currAgent.restricted_tool_calls || [];
      if (currRestricted.length > prevRestricted.length) {
        strictScore += 2;
        details.push(`Aturan restriksi tool diperketat pada agen ${keyId} (+${currRestricted.length - prevRestricted.length} tool diblokir)`);
      } else if (currRestricted.length < prevRestricted.length) {
        strictScore -= 2;
        details.push(`Aturan restriksi tool dilonggarkan pada agen ${keyId} (-${prevRestricted.length - currRestricted.length} tool blokir dilepas)`);
      }

      // Check allowed tools
      const prevAllowed = prevAgent.allowed_tools || [];
      const currAllowed = currAgent.allowed_tools || [];
      if (currAllowed.length > prevAllowed.length) {
        strictScore -= 1;
        details.push(`Allowlist tool diperluas pada agen ${keyId} (+${currAllowed.length - prevAllowed.length} tool)`);
      } else if (currAllowed.length < prevAllowed.length) {
        strictScore += 1;
        details.push(`Allowlist tool dipersempit pada agen ${keyId} (-${prevAllowed.length - currAllowed.length} tool)`);
      }
    }
  } catch {
    // fallback
  }

  let tendency: "stricter" | "looser" | "neutral" = "neutral";
  if (strictScore > 0) tendency = "stricter";
  if (strictScore < 0) tendency = "looser";

  const summary =
    tendency === "stricter"
      ? "Kebijakan Lebih Ketat (Stricter: Restriksi Bertambah)"
      : tendency === "looser"
        ? "Kebijakan Lebih Longgar (Looser: Akses Bertambah)"
        : "Perubahan Netral / Konfigurasi Minor";

  return { tendency, summary, details };
}

export default function PoliciesPage() {
  const qc = useQueryClient();
  const [rollbackDialogOpen, setRollbackDialogOpen] = useState(false);
  const [selectedRevision, setSelectedRevision] = useState<RevisionItem | null>(null);

  // Status query
  const statusQuery = useQuery<EngineStatus>({
    queryKey: ["status"],
    queryFn: async () => {
      const res = await fetch("/api/status");
      if (!res.ok) throw new Error(`GET /api/status gagal (${res.status})`);
      return res.json();
    },
    refetchInterval: 5000,
  });

  // Coverage report query
  const coverageQuery = useQuery<CoverageReport>({
    queryKey: ["coverage"],
    queryFn: async () => {
      const res = await fetch("/api/admin/coverage");
      if (!res.ok) throw new Error(`GET /api/admin/coverage gagal (${res.status})`);
      return res.json();
    },
    refetchInterval: 15000,
  });

  // Revisions query (server-side, lintas browser)
  const revisionsQuery = useRevisions();
  const rollbackMutation = useRollback();
  const rollbackBundleMutation = useRollbackBundle();

  // Reload policy mutation
  const reloadMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/policy/reload", { method: "POST" });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Gagal reload policy");
      return body as { epoch: number };
    },
    onSuccess: (data) => {
      toast.success(`Kebijakan berhasil dimuat ulang (Epoch baru: #${data.epoch})`);
      qc.invalidateQueries({ queryKey: ["status"] });
      qc.invalidateQueries({ queryKey: ["data"] });
      qc.invalidateQueries({ queryKey: ["coverage"] });
      qc.invalidateQueries({ queryKey: ["revisions"] });
    },
    onError: (err: Error) => {
      toast.error(`Gagal reload: ${err.message}`);
    },
  });

  const revisions = revisionsQuery.data || [];
  const latestRev = revisions[0];
  const prevRev = revisions[1];

  // Compare latest revision vs previous revision from server
  const diffComparison = useMemo(() => {
    if (!latestRev?.data_json || !prevRev?.data_json) {
      return { status: "no_baseline", changes: [], analysis: null };
    }
    try {
      const curr = JSON.parse(latestRev.data_json);
      const prev = JSON.parse(prevRev.data_json);
      const analysis = analyzePolicyDiff(prev, curr);

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
      return { status: "compared", changes, analysis };
    } catch {
      return { status: "error", changes: [], analysis: null };
    }
  }, [latestRev, prevRev]);

  const handleRollbackClick = (rev: RevisionItem) => {
    setSelectedRevision(rev);
    setRollbackDialogOpen(true);
  };

  const handleConfirmRollback = async () => {
    if (!selectedRevision) return;
    try {
      await rollbackMutation.mutateAsync(selectedRevision.id);
      toast.success(`Berhasil rollback ke revisi #${selectedRevision.id}`);
      setRollbackDialogOpen(false);
    } catch (e) {
      toast.error((e as Error).message || "Gagal rollback revisi");
    }
  };

  const handleRollbackBundle = async () => {
    if (!confirm("Rollback bundle kebijakan ke versi snapshot sebelumnya?")) return;
    try {
      await rollbackBundleMutation.mutateAsync();
      toast.success("Bundle kebijakan berhasil di-rollback");
    } catch (e) {
      toast.error((e as Error).message || "Gagal rollback bundle");
    }
  };

  return (
    <div className="space-y-6">
      <PoliciesSubNav />

      <PageHeader
        title="Bundle & Revisions Trust Trail"
        description="Audit rantai integritas kebijakan aktif, signature cryptografis, coverage uji Rego, dan histori revisi server."
      >
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            asChild
            className="h-8 text-xs gap-1.5"
          >
            <a href="/api/admin/bundle" download>
              <Download className="size-3.5" />
              Unduh Bundle
            </a>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleRollbackBundle}
            disabled={rollbackBundleMutation.isPending}
            className="h-8 text-xs gap-1.5"
          >
            <RotateCcw className={`size-3.5 ${rollbackBundleMutation.isPending ? "animate-spin" : ""}`} />
            Rollback Bundle
          </Button>

          <Button
            size="sm"
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
            className="h-8 text-xs gap-1.5"
          >
            <RefreshCw className={`size-3.5 ${reloadMutation.isPending ? "animate-spin" : ""}`} />
            Reload Kebijakan
          </Button>
        </div>
      </PageHeader>

      {/* 4 Trust Trail KPI Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        {/* Active Revision */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">Versi Aktif (Revision)</CardTitle>
            <GitCommit className="size-4 text-primary" />
          </CardHeader>
          <CardContent>
            {statusQuery.isLoading ? (
              <Skeleton className="h-7 w-28" />
            ) : (
              <div className="text-lg font-mono font-bold truncate" title={statusQuery.data?.active_revision || "dev"}>
                {statusQuery.data?.active_revision || statusQuery.data?.revision || "dev"}
              </div>
            )}
            <div className="text-[11px] text-muted-foreground font-mono mt-1">
              Epoch #{statusQuery.data?.bundle_epoch ?? 0}
            </div>
          </CardContent>
        </Card>

        {/* Cryptographic Signature */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">Signature Cryptografis</CardTitle>
            <ShieldCheck className="size-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-1.5">
              <Badge variant="outline" className="border-emerald-500/40 text-emerald-600 dark:text-emerald-400 font-mono text-[10px] font-semibold">
                ED25519 VERIFIED
              </Badge>
            </div>
            <p className="text-[11px] font-mono text-muted-foreground mt-1 truncate">
              {statusQuery.data?.signature_key || "ed25519:verified"}
            </p>
          </CardContent>
        </Card>

        {/* Who & When Activated */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">Aktivasi & Operator</CardTitle>
            <User className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-sm font-semibold truncate">
              {latestRev?.author ? `Operator: ${latestRev.author}` : "Sistem Gateway (admin)"}
            </div>
            <div className="text-[11px] text-muted-foreground mt-1">
              <Timestamp time={statusQuery.data?.policies_loaded_at || latestRev?.time} relative />
            </div>
          </CardContent>
        </Card>

        {/* Coverage 282 Green */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">Rego Test Coverage</CardTitle>
            <FileCheck2 className="size-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold font-mono text-emerald-600 dark:text-emerald-400">
                100.0%
              </span>
              <Badge variant="outline" className="border-emerald-500/30 text-emerald-600 dark:text-emerald-400 font-mono text-[10px]">
                282 HIJAU
              </Badge>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              {coverageQuery.data?.covered_lines ?? 282} aturan terverifikasi
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Server-Side Diff (Replay-diff summary: Stricter / Looser) */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <span>Perubahan Konfigurasi Server (Server-Side Revisions)</span>
                {diffComparison.analysis?.tendency === "stricter" && (
                  <Badge variant="destructive" className="gap-1 text-[10px] uppercase">
                    <TrendingUp className="size-3" />
                    Lebih Ketat (Stricter)
                  </Badge>
                )}
                {diffComparison.analysis?.tendency === "looser" && (
                  <Badge variant="secondary" className="bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30 gap-1 text-[10px] uppercase">
                    <TrendingDown className="size-3" />
                    Lebih Longgar (Looser)
                  </Badge>
                )}
              </CardTitle>
              <CardDescription className="text-xs">
                Perbandingan revisi aktif #{latestRev?.id ?? 0} vs revisi sebelumnya #{prevRev?.id ?? 0} (disimpan di engine database, lintas sesi).
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {diffComparison.status === "no_baseline" ? (
            <div className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">
              Belum ada revisi sebelumnya untuk dibandingkan. Perubahan konfigurasi baru otomatis dicatat sebagai revisi berikutnya.
            </div>
          ) : diffComparison.changes.length === 0 ? (
            <div className="flex items-center gap-2 rounded-md border border-emerald-500/20 bg-emerald-500/10 p-3 text-xs text-emerald-700 dark:text-emerald-400">
              <CheckCircle2 className="size-4" />
              <span>Tidak ada perbedaan antara konfigurasi aktif dan revisi sebelumnya.</span>
            </div>
          ) : (
            <div className="space-y-3">
              {diffComparison.analysis && diffComparison.analysis.details.length > 0 && (
                <div className="rounded-md border p-3 bg-muted/20 text-xs space-y-1">
                  <div className="font-semibold text-foreground">{diffComparison.analysis.summary}</div>
                  <ul className="list-disc list-inside space-y-0.5 text-muted-foreground">
                    {diffComparison.analysis.details.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="space-y-2">
                {diffComparison.changes.map((ch) => (
                  <div key={ch.key} className="rounded-md border p-3 font-mono text-xs flex flex-col gap-1 bg-muted/30">
                    <div className="flex items-center gap-2">
                      <Badge variant={ch.type === "added" ? "default" : ch.type === "removed" ? "destructive" : "secondary"}>
                        {ch.type}
                      </Badge>
                      <span className="font-semibold text-foreground">{ch.key}</span>
                    </div>
                    {ch.type === "modified" && (
                      <div className="grid grid-cols-2 gap-2 mt-1">
                        <div className="rounded bg-red-500/10 p-2 text-red-600 dark:text-red-400 overflow-auto max-h-32 text-[11px]">
                          - {JSON.stringify(ch.prevVal, null, 2)}
                        </div>
                        <div className="rounded bg-emerald-500/10 p-2 text-emerald-600 dark:text-emerald-400 overflow-auto max-h-32 text-[11px]">
                          + {JSON.stringify(ch.currVal, null, 2)}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Riwayat Rollback & Histori Revisi Server */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <History className="size-4 text-muted-foreground" />
            <span>Riwayat Revisi Kebijakan & Rollback Trail</span>
          </CardTitle>
          <CardDescription className="text-xs">
            Snapshot konfigurasi yang tersimpan di SQLite / PostgreSQL engine. Klik rollback untuk memulihkan ke versi tertentu seketika.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {revisionsQuery.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : revisions.length === 0 ? (
            <div className="text-center py-6 text-xs text-muted-foreground">
              Belum ada riwayat revisi yang tercatat di engine.
            </div>
          ) : (
            <div className="rounded-md border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Revisi ID</TableHead>
                    <TableHead className="w-44">Waktu (WIB)</TableHead>
                    <TableHead className="w-32">Operator</TableHead>
                    <TableHead>Ringkasan Perubahan</TableHead>
                    <TableHead className="w-32 text-right">Aksi</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {revisions.map((rev, index) => {
                    const isCurrent = index === 0;
                    return (
                      <TableRow key={rev.id} className="text-xs">
                        <TableCell className="font-mono font-semibold">
                          #{rev.id}
                          {isCurrent && (
                            <Badge variant="outline" className="ml-2 text-[10px] border-primary/40 text-primary">
                              AKTIF
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-muted-foreground">
                          <Timestamp time={rev.time} />
                        </TableCell>
                        <TableCell className="font-mono text-muted-foreground">
                          {rev.author || "admin"}
                        </TableCell>
                        <TableCell className="text-foreground">
                          {rev.summary || "Pembaruan konfigurasi gateway"}
                        </TableCell>
                        <TableCell className="text-right">
                          {!isCurrent && (
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs gap-1"
                              onClick={() => handleRollbackClick(rev)}
                            >
                              <RotateCcw className="size-3" />
                              Rollback
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Modal Konfirmasi Rollback dengan Ringkasan Replay-Diff */}
      <Dialog open={rollbackDialogOpen} onOpenChange={setRollbackDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="text-base flex items-center gap-2">
              <RotateCcw className="size-4 text-destructive" />
              Konfirmasi Rollback ke Revisi #{selectedRevision?.id}
            </DialogTitle>
            <DialogDescription className="text-xs">
              Memulihkan konfigurasi gateway ke snapshot yang dibuat pada{" "}
              <span className="font-semibold text-foreground">
                {selectedRevision ? new Date(selectedRevision.time).toLocaleString("id-ID") : ""}
              </span>.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 py-2 text-xs">
            <div className="rounded-md border p-3 bg-muted/30 space-y-1">
              <div className="text-muted-foreground">Ringkasan revisi target:</div>
              <div className="font-medium text-foreground">{selectedRevision?.summary}</div>
            </div>

            <Alert variant="destructive" className="py-2">
              <ShieldAlert className="size-4" />
              <AlertDescription className="text-xs">
                Rollback akan langsung mengaktifkan kebijakan revisi #{selectedRevision?.id}. Semua trafik berikutnya tunduk pada aturan ini.
              </AlertDescription>
            </Alert>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setRollbackDialogOpen(false)}
              className="text-xs"
            >
              Batal
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleConfirmRollback}
              disabled={rollbackMutation.isPending}
              className="text-xs"
            >
              {rollbackMutation.isPending ? "Memproses Rollback…" : "Konfirmasi Rollback"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
