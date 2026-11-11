"use client";

import { useEffect, useState } from "react";
import { AlertCircle, CheckCircle2, HelpCircle, RefreshCcw, XCircle } from "lucide-react";
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
import type { AuditEvent } from "@/lib/schema";

interface TraceEntry {
  op: string;
  rule?: string;
  location?: string;
  result?: string;
}

interface ExplainResponse {
  decision: string;
  rule_id: string;
  reason: string;
  epoch: number;
  trace: TraceEntry[];
  pretty_trace?: string;
}

interface TraceDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  event?: AuditEvent | null;
  customInput?: Record<string, unknown> | null;
  title?: string;
}

export function TraceDialog({
  open,
  onOpenChange,
  event,
  customInput,
  title = "Penjelasan Keputusan (Trace)",
}: TraceDialogProps) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ExplainResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    if (!open) {
      setData(null);
      setError(null);
      return;
    }

    const payload = customInput ?? (event ? {
      stage: event.stage,
      key_id: event.key_id,
      tool_call: event.stage === "tool" ? event.subject : undefined,
      model: event.stage === "llm" ? event.subject : undefined,
      args: event.args ?? {},
    } : null);

    if (!payload) return;

    setLoading(true);
    setError(null);

    fetch("/api/admin/explain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then(async (res) => {
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.error ?? `Explain failed (${res.status})`);
        }
        return res.json() as Promise<ExplainResponse>;
      })
      .then((res) => setData(res))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [open, event, customInput]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col overflow-hidden">
        <DialogHeader className="shrink-0 pb-2">
          <DialogTitle className="flex items-center gap-2 text-lg">
            <HelpCircle className="size-5 text-primary" />
            {title}
          </DialogTitle>
          <DialogDescription className="text-xs">
            Evaluasi mendalam mesin OPA: melacak urutan rule yang diuji hingga menghasilkan keputusan akhir.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 pr-1">
          {loading && (
            <div className="flex h-48 items-center justify-center gap-2 text-sm text-muted-foreground">
              <RefreshCcw className="size-4 animate-spin" />
              Menjalankan evaluasi OPA dan membaca trace...
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              <AlertCircle className="size-4 shrink-0" />
              <span>Gagal memuat trace: {error}</span>
            </div>
          )}

          {data && (
            <div className="space-y-4">
              {/* Verdict Summary Card */}
              <div className="rounded-lg border bg-muted/30 p-3 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  {data.decision === "allow" ? (
                    <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 font-semibold text-xs px-2.5 py-0.5">
                      <CheckCircle2 className="size-3.5 mr-1" />
                      IZINKAN (ALLOW)
                    </Badge>
                  ) : (
                    <Badge variant="destructive" className="font-semibold text-xs px-2.5 py-0.5">
                      <XCircle className="size-3.5 mr-1" />
                      TOLAK (DENY)
                    </Badge>
                  )}
                  <div>
                    <span className="text-xs text-muted-foreground mr-1.5">Rule yang menang:</span>
                    <span className="font-mono text-xs font-semibold">{data.rule_id}</span>
                  </div>
                </div>
                <div className="text-xs text-muted-foreground font-mono">
                  Epoch: {data.epoch}
                </div>
                {data.reason && (
                  <div className="w-full text-xs text-muted-foreground pt-1 border-t">
                    <span className="font-medium text-foreground">Alasan: </span>
                    {data.reason}
                  </div>
                )}
              </div>

              {/* View toggle */}
              <div className="flex items-center justify-between pt-1">
                <span className="text-xs font-semibold">
                  Daftar Rule yang Dievaluasi ({data.trace?.length ?? 0} langkah)
                </span>
                {data.pretty_trace && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => setShowRaw(!showRaw)}
                  >
                    {showRaw ? "Tampilkan Tabel Rule" : "Tampilkan Raw Pretty Trace"}
                  </Button>
                )}
              </div>

              {showRaw && data.pretty_trace ? (
                <pre className="rounded-md border bg-muted/50 p-3 font-mono text-[11px] leading-relaxed overflow-x-auto max-h-[360px] whitespace-pre">
                  {data.pretty_trace}
                </pre>
              ) : (
                <div className="rounded-md border overflow-x-auto max-h-[360px]">
                  <Table>
                    <TableHeader className="bg-muted/40 sticky top-0 z-10">
                      <TableRow>
                        <TableHead className="w-[80px]">Operasi</TableHead>
                        <TableHead>Rule / Ekspresi</TableHead>
                        <TableHead className="w-[180px]">Lokasi</TableHead>
                        <TableHead className="w-[90px] text-right">Hasil</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.trace && data.trace.length > 0 ? (
                        data.trace.map((t, idx) => (
                          <TableRow key={idx} className="text-xs font-mono">
                            <TableCell className="font-semibold text-muted-foreground text-[11px]">
                              {t.op}
                            </TableCell>
                            <TableCell className="max-w-[320px] truncate" title={t.rule}>
                              {t.rule || "—"}
                            </TableCell>
                            <TableCell className="text-muted-foreground text-[11px]">
                              {t.location || "—"}
                            </TableCell>
                            <TableCell className="text-right">
                              {t.result === "pass" ? (
                                <span className="text-emerald-600 dark:text-emerald-400 font-semibold">
                                  pass
                                </span>
                              ) : t.result === "fail" ? (
                                <span className="text-destructive font-semibold">
                                  fail
                                </span>
                              ) : (
                                <span className="text-muted-foreground">{t.result || "—"}</span>
                              )}
                            </TableCell>
                          </TableRow>
                        ))
                      ) : (
                        <TableRow>
                          <TableCell colSpan={4} className="text-center py-6 text-xs text-muted-foreground font-sans">
                            Tidak ada rule step trace yang terekam.
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
