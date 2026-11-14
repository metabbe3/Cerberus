"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { ChevronRight } from "lucide-react";
import { DataTable } from "@/components/data-table";
import { KeyCell } from "@/components/key-cell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { AuditEvent } from "@/lib/schema";

function TimeCell({ time }: { time: string }) {
  const d = new Date(time);
  const timeStr = d.toLocaleTimeString("id-ID", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const dateStr = d.toLocaleDateString("id-ID", { day: "2-digit", month: "short" });
  return (
    <div
      className="font-mono text-xs tabular-nums text-foreground flex items-center gap-1.5"
      title={`${d.toISOString()} (UTC)`}
    >
      <span className="text-muted-foreground text-[11px]">{dateStr}</span>
      <span>{timeStr}</span>
    </div>
  );
}

function LatencyCell({ latencyUs, cached }: { latencyUs?: number; cached?: boolean }) {
  const latStr =
    latencyUs !== undefined && latencyUs > 0
      ? latencyUs < 1000
        ? `${latencyUs} µs`
        : `${(latencyUs / 1000).toFixed(1)} ms`
      : "—";

  return (
    <div className="flex items-center gap-1.5 font-mono text-xs tabular-nums">
      <span>{latStr}</span>
      {cached ? (
        <Badge variant="outline" className="text-[10px] px-1 py-0 h-4 text-emerald-500 border-emerald-500/30 font-mono">
          CACHED
        </Badge>
      ) : (
        <Badge variant="outline" className="text-[10px] px-1 py-0 h-4 text-muted-foreground font-mono">
          EVAL
        </Badge>
      )}
    </div>
  );
}

const columns = (onSelectEvent?: (ev: AuditEvent) => void): ColumnDef<AuditEvent, unknown>[] => [
  {
    id: "time",
    header: "Waktu (WIB)",
    cell: ({ row }) => <TimeCell time={row.original.time} />,
  },
  {
    accessorKey: "stage",
    header: "Stage",
    cell: ({ row }) => (
      <Badge variant="outline" className="font-mono text-[11px] uppercase">
        {row.original.stage}
      </Badge>
    ),
  },
  {
    accessorKey: "key_id",
    header: "Agen",
    cell: ({ row }) => <KeyCell id={row.original.key_id} />,
  },
  {
    accessorKey: "subject",
    header: "Subjek",
    cell: ({ row }) => <span className="font-mono text-xs font-medium">{row.original.subject}</span>,
  },
  {
    accessorKey: "decision",
    header: "Keputusan",
    cell: ({ row }) => {
      const isAllow = row.original.decision === "allow";
      return (
        <Badge
          variant={isAllow ? "secondary" : "destructive"}
          className={
            isAllow
              ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 font-semibold text-[11px] uppercase"
              : "uppercase font-semibold text-[11px]"
          }
        >
          {row.original.decision}
        </Badge>
      );
    },
  },
  {
    accessorKey: "rule_id",
    header: "Aturan (Rule)",
    cell: ({ row }) => <span className="font-mono text-xs text-muted-foreground">{row.original.rule_id}</span>,
  },
  {
    id: "latency",
    header: "Latensi",
    cell: ({ row }) => <LatencyCell latencyUs={row.original.latency_us} cached={row.original.cached} />,
  },
  {
    id: "action",
    header: "",
    cell: ({ row }) => (
      <Button
        variant="ghost"
        size="sm"
        className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
        onClick={(e) => {
          e.stopPropagation();
          onSelectEvent?.(row.original);
        }}
      >
        Detail
        <ChevronRight className="size-3.5 ml-1" />
      </Button>
    ),
  },
];

export function AuditTable({
  events,
  onSelectEvent,
}: {
  events: AuditEvent[];
  onSelectEvent?: (ev: AuditEvent) => void;
  onCreateRule?: (ev: AuditEvent) => void;
}) {
  return (
    <DataTable
      columns={columns(onSelectEvent)}
      data={events}
      onRowClick={onSelectEvent}
    />
  );
}
