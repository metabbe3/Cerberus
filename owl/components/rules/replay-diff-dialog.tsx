"use client";

import { useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  Play,
  RotateCcw,
  ShieldAlert,
  TrendingDown,
  TrendingUp,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { CerberusData } from "@/lib/schema";

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

interface ReplayDiffDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  draftData: CerberusData | null;
}

export function ReplayDiffDialog({ open, onOpenChange, draftData }: ReplayDiffDialogProps) {
  const [limit, setLimit] = useState<number>(500);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ReplayReport | null>(null);

  const runReplay = async (customLimit = limit) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/replay", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          limit: customLimit,
          data: draftData || undefined,
        }),
      });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP ${res.status}`);
      }
      const data: ReplayReport = await res.json();
      setReport(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Gagal mengevaluasi replay audit");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[85vh] flex flex-col p-6 overflow-hidden">
        <DialogHeader className="border-b pb-4 shrink-0">
          <div className="flex items-center justify-between">
            <div>
              <DialogTitle className="text-lg font-bold flex items-center gap-2">
                <RotateCcw className="size-5 text-blue-600 dark:text-blue-400" />
                Uji Replay Audit & Diff Dampak Aturan
              </DialogTitle>
              <DialogDescription className="mt-1 text-xs">
                Mengevaluasi ulang keputusan audit riil dengan draft aturan saat ini untuk mendeteksi perubahan allow/deny sebelum aktivasi.
              </DialogDescription>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1 border rounded-md p-0.5 bg-muted/40">
                {[100, 500, 1000].map((n) => (
                  <Button
                    key={n}
                    size="sm"
                    variant={limit === n ? "secondary" : "ghost"}
                    className="h-6 text-[10px] px-2"
                    onClick={() => {
                      setLimit(n);
                      runReplay(n);
                    }}
                    disabled={loading}
                  >
                    {n}
                  </Button>
                ))}
              </div>
              <Button
                size="sm"
                variant="outline"
                onClick={() => runReplay(limit)}
                disabled={loading}
                className="text-xs"
              >
                <Play className={`mr-1.5 size-3.5 ${loading ? "animate-spin" : ""}`} />
                {loading ? "Menguji..." : `Uji ${limit} Event`}
              </Button>
            </div>
          </div>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 py-4 pr-1">
          {error && (
            <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-xs text-destructive flex items-center gap-2">
              <XCircle className="size-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!report && !loading && !error && (
            <div className="text-center py-12 space-y-3">
              <RotateCcw className="size-10 mx-auto text-muted-foreground/60" />
              <div className="text-sm font-medium">Uji Dampak Perubahan Aturan</div>
              <p className="text-xs text-muted-foreground max-w-md mx-auto">
                Jalankan replay terhadap event audit riil untuk melihat berapa keputusan yang berubah jika draft aturan diaktifkan.
              </p>
              <Button onClick={() => runReplay(500)} size="sm" className="bg-blue-600 hover:bg-blue-700 text-white text-xs">
                Mulai Replay 500 Audit Event
              </Button>
            </div>
          )}

          {loading && (
            <div className="text-center py-16 space-y-3">
              <RotateCcw className="size-8 mx-auto animate-spin text-blue-600" />
              <p className="text-xs text-muted-foreground">Mengevaluasi ulang event audit dengan policy engine...</p>
            </div>
          )}

          {report && !loading && (
            <>
              {/* Ringkasan Dampak Banner */}
              <div
                className={`rounded-lg border p-4 text-xs ${
                  report.diff_count > 0
                    ? "border-blue-500/30 bg-blue-500/10 text-blue-900 dark:text-blue-200"
                    : "border-emerald-500/30 bg-emerald-500/10 text-emerald-900 dark:text-emerald-200"
                }`}
              >
                <div className="font-semibold text-sm flex items-center gap-2">
                  {report.diff_count > 0 ? (
                    <ShieldAlert className="size-4 text-blue-600" />
                  ) : (
                    <CheckCircle2 className="size-4 text-emerald-600" />
                  )}
                  Ringkasan Dampak: {report.diff_count} dari {report.total_evaluated} keputusan berubah
                </div>
                <div className="mt-1 opacity-90">
                  Dengan perubahan ini, <strong>{report.diff_count}</strong> dari{" "}
                  <strong>{report.total_evaluated}</strong> keputusan berubah —{" "}
                  <strong>{report.stricter_count}</strong> jadi lebih ketat,{" "}
                  <strong>{report.looser_count}</strong> lebih longgar, dan{" "}
                  <strong>{report.unchanged_count}</strong> tetap identik.
                </div>
              </div>

              {/* 4 Kartu Metrik */}
              <div className="grid grid-cols-4 gap-3">
                <div className="rounded-lg border p-3 bg-muted/20">
                  <div className="text-[11px] text-muted-foreground font-medium">Total Diuji</div>
                  <div className="text-xl font-bold mt-0.5">{report.total_evaluated}</div>
                </div>
                <div className="rounded-lg border p-3 bg-muted/20">
                  <div className="text-[11px] text-muted-foreground font-medium">Tidak Berubah</div>
                  <div className="text-xl font-bold mt-0.5 text-muted-foreground">{report.unchanged_count}</div>
                </div>
                <div className="rounded-lg border p-3 bg-red-500/5 border-red-500/20">
                  <div className="text-[11px] text-red-600 dark:text-red-400 font-medium flex items-center gap-1">
                    <TrendingUp className="size-3" /> Lebih Ketat (Deny)
                  </div>
                  <div className="text-xl font-bold mt-0.5 text-red-600 dark:text-red-400">{report.stricter_count}</div>
                </div>
                <div className="rounded-lg border p-3 bg-amber-500/5 border-amber-500/20">
                  <div className="text-[11px] text-amber-600 dark:text-amber-400 font-medium flex items-center gap-1">
                    <TrendingDown className="size-3" /> Lebih Longgar (Allow)
                  </div>
                  <div className="text-xl font-bold mt-0.5 text-amber-600 dark:text-amber-400">{report.looser_count}</div>
                </div>
              </div>

              {/* Tabel Diffs */}
              {report.diffs.length === 0 ? (
                <div className="rounded-lg border border-dashed p-6 text-center text-xs text-muted-foreground">
                  Tidak ada perbedaan hasil keputusan pada {report.total_evaluated} event yang dievaluasi.
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-muted-foreground">
                    Daftar Keputusan yang Berubah ({report.diffs.length} Event):
                  </div>
                  <div className="rounded-md border overflow-hidden">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[100px]">Stage / Key</TableHead>
                          <TableHead className="w-[140px]">Subjek</TableHead>
                          <TableHead className="w-[180px]">Keputusan (Lama &rarr; Baru)</TableHead>
                          <TableHead>Aturan (Rule ID)</TableHead>
                          <TableHead className="w-[110px] text-right">Pergeseran</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {report.diffs.map((diff, idx) => (
                          <TableRow key={diff.event_id || idx}>
                            <TableCell className="font-mono text-xs">
                              <div>{diff.stage}</div>
                              <div className="text-[10px] text-muted-foreground truncate">{diff.key_id}</div>
                            </TableCell>
                            <TableCell className="font-mono text-xs truncate max-w-[140px]" title={diff.subject}>
                              {diff.subject || "-"}
                            </TableCell>
                            <TableCell className="text-xs font-mono">
                              <div className="flex items-center gap-1.5">
                                <Badge
                                  variant={diff.old_decision === "allow" ? "default" : "destructive"}
                                  className="text-[10px] uppercase h-5 px-1.5"
                                >
                                  {diff.old_decision}
                                </Badge>
                                <ArrowRight className="size-3 text-muted-foreground" />
                                <Badge
                                  variant={diff.new_decision === "allow" ? "default" : "destructive"}
                                  className="text-[10px] uppercase h-5 px-1.5"
                                >
                                  {diff.new_decision}
                                </Badge>
                              </div>
                            </TableCell>
                            <TableCell className="text-xs font-mono">
                              <div className="text-[11px] text-muted-foreground line-through">{diff.old_rule_id}</div>
                              <div className="font-semibold text-foreground">{diff.new_rule_id}</div>
                              {diff.new_reason && (
                                <div className="text-[10px] text-muted-foreground mt-0.5">{diff.new_reason}</div>
                              )}
                            </TableCell>
                            <TableCell className="text-right">
                              <Badge
                                variant={
                                  diff.shift === "stricter"
                                    ? "destructive"
                                    : diff.shift === "looser"
                                    ? "secondary"
                                    : "outline"
                                }
                                className="text-[10px]"
                              >
                                {diff.shift === "stricter"
                                  ? "Lebih Ketat"
                                  : diff.shift === "looser"
                                  ? "Lebih Longgar"
                                  : "Ganti Rule"}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
