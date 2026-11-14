"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Code2,
  HelpCircle,
  Key,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Timestamp } from "@/components/timestamp";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { TraceDialog } from "@/components/decisions/trace-dialog";
import { useEraseDecision } from "@/lib/queries";
import type { AuditEvent } from "@/lib/schema";

interface InspectorDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  event: AuditEvent | null;
}

export function InspectorDrawer({ open, onOpenChange, event }: InspectorDrawerProps) {
  const router = useRouter();
  const erase = useEraseDecision();
  const [traceOpen, setTraceOpen] = useState(false);

  if (!event) return null;

  const isDeny = event.decision === "deny";
  const isAllow = event.decision === "allow";

  const handleErase = async () => {
    if (!confirm(`Hapus payload sensitif untuk event #${event.id}?`)) return;
    try {
      await erase.mutateAsync(event.id);
      toast.success(`Payload event #${event.id} berhasil dihapus`);
    } catch (e) {
      toast.error((e as Error).message || "Gagal menghapus payload");
    }
  };

  const handleContextualRemediation = () => {
    onOpenChange(false);
    if (isDeny) {
      // Allowlist exception for this agent
      router.push(`/agents/${encodeURIComponent(event.key_id)}?prefill=allow:${encodeURIComponent(event.subject)}`);
    } else {
      // Restrict suspicious allow
      router.push(`/agents/${encodeURIComponent(event.key_id)}?prefill=restricted:${encodeURIComponent(event.subject)}`);
    }
  };

  const latencyStr =
    event.latency_us !== undefined && event.latency_us > 0
      ? event.latency_us < 1000
        ? `${event.latency_us} µs`
        : `${(event.latency_us / 1000).toFixed(2)} ms`
      : "< 1 ms";

  return (
    <>
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent className="overflow-y-auto">
          <SheetHeader className="pb-4">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge
                  variant={isDeny ? "destructive" : "default"}
                  className={`uppercase text-xs font-semibold px-2 py-0.5 ${
                    isAllow ? "bg-emerald-600 hover:bg-emerald-600 text-white" : ""
                  }`}
                >
                  {event.decision}
                </Badge>
                <Badge variant="outline" className="font-mono text-xs">
                  {event.stage}
                </Badge>
                {event.cached ? (
                  <Badge variant="outline" className="text-emerald-500 border-emerald-500/30 text-[10px] font-mono">
                    CACHED
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-muted-foreground text-[10px] font-mono">
                    EVAL
                  </Badge>
                )}
              </div>
              <span className="text-xs font-mono text-muted-foreground">#{event.id}</span>
            </div>
            <SheetTitle className="text-base font-semibold mt-2">
              Detail Investigasi Keputusan
            </SheetTitle>
            <SheetDescription className="text-xs text-muted-foreground">
              Inspeksi metadata evaluasi OPA, argumen masked, dan jejak keputusan.
            </SheetDescription>
          </SheetHeader>

          <div className="space-y-5 py-4 text-xs">
            {/* Action Bar */}
            <div className="flex flex-wrap items-center gap-2 border-b pb-4">
              <Button
                size="sm"
                variant="outline"
                className="h-8 text-xs font-medium"
                onClick={() => setTraceOpen(true)}
              >
                <HelpCircle className="size-3.5 mr-1 text-primary" />
                Jelaskan (Trace)
              </Button>

              {isDeny ? (
                <Button
                  size="sm"
                  variant="default"
                  className="h-8 text-xs font-medium bg-emerald-600 hover:bg-emerald-700 text-white"
                  onClick={handleContextualRemediation}
                >
                  <ShieldCheck className="size-3.5 mr-1" />
                  + Izinkan utk Agen Ini
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="destructive"
                  className="h-8 text-xs font-medium"
                  onClick={handleContextualRemediation}
                >
                  <ShieldAlert className="size-3.5 mr-1" />
                  Blokir Tool Ini
                </Button>
              )}

              <Button
                size="sm"
                variant="ghost"
                className="h-8 text-xs text-muted-foreground hover:text-foreground ml-auto"
                onClick={handleErase}
                disabled={erase.isPending}
                title="Hapus argumen payload dari database audit"
              >
                <Trash2 className="size-3.5 mr-1 text-destructive" />
                Hapus Payload
              </Button>
            </div>

            {/* Core Metadata Grid */}
            <div className="grid grid-cols-2 gap-3 rounded-lg border bg-muted/20 p-3">
              <div>
                <span className="text-[11px] text-muted-foreground font-medium block">Agen (Key ID)</span>
                <Link
                  href={`/agents/${encodeURIComponent(event.key_id)}`}
                  className="font-mono text-xs font-semibold text-primary hover:underline flex items-center gap-1 mt-0.5"
                >
                  <Key className="size-3" />
                  {event.key_id}
                </Link>
              </div>

              <div>
                <span className="text-[11px] text-muted-foreground font-medium block">Subjek (Tool / Model)</span>
                <span className="font-mono text-xs font-semibold text-foreground block mt-0.5">
                  {event.subject}
                </span>
              </div>

              <div>
                <span className="text-[11px] text-muted-foreground font-medium block">Waktu Evaluasi</span>
                <div className="mt-0.5">
                  <Timestamp time={event.time} />
                </div>
              </div>

              <div>
                <span className="text-[11px] text-muted-foreground font-medium block">Latensi & Epoch</span>
                <span className="font-mono text-xs text-foreground tabular-nums block mt-0.5">
                  {latencyStr} • epoch {event.epoch}
                </span>
              </div>
            </div>

            {/* Rule & Reason */}
            <div className="space-y-1.5 rounded-lg border p-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-muted-foreground font-medium">Aturan (Rule ID)</span>
                <Badge variant="outline" className="font-mono text-xs">
                  {event.rule_id}
                </Badge>
              </div>
              <div className="text-[11px] text-muted-foreground font-medium mt-2">Alasan Keputusan</div>
              <div className="rounded bg-muted/50 p-2 font-mono text-xs text-foreground break-words">
                {event.reason || "(Tidak ada alasan khusus)"}
              </div>
            </div>

            {/* Masked Arguments / Payload */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold flex items-center gap-1.5">
                  <Code2 className="size-3.5 text-muted-foreground" />
                  Payload / Argumen (Masked)
                </span>
                <span className="text-[10px] text-muted-foreground">PII otomatis disamarkan</span>
              </div>
              <div className="max-h-60 overflow-y-auto rounded-lg border bg-zinc-950 p-3 font-mono text-[11px] text-zinc-100">
                {event.args && Object.keys(event.args).length > 0 ? (
                  <pre className="whitespace-pre-wrap break-all">
                    {JSON.stringify(event.args, null, 2)}
                  </pre>
                ) : (
                  <span className="text-muted-foreground italic">
                    (Tidak ada payload atau payload telah dihapus)
                  </span>
                )}
              </div>
            </div>

            {/* Deep Links */}
            <div className="border-t pt-3 flex items-center justify-between">
              <Link
                href={`/decisions?key_id=${encodeURIComponent(event.key_id)}`}
                className="text-xs text-primary hover:underline flex items-center gap-1"
                onClick={() => onOpenChange(false)}
              >
                Lihat semua audit trail agen ini &rarr;
              </Link>
              <Link
                href={`/decisions?rule_id=${encodeURIComponent(event.rule_id)}`}
                className="text-xs text-muted-foreground hover:underline flex items-center gap-1"
                onClick={() => onOpenChange(false)}
              >
                Filter aturan ini &rarr;
              </Link>
            </div>
          </div>
        </SheetContent>
      </Sheet>

      {/* Trace Dialog */}
      <TraceDialog
        open={traceOpen}
        onOpenChange={setTraceOpen}
        event={event}
      />
    </>
  );
}
