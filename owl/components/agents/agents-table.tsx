"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { Badge } from "@/components/ui/badge";
import { KeyCell } from "@/components/key-cell";
import { Timestamp } from "@/components/timestamp";
import type { Agent } from "@/lib/schema";

export type AgentRow = {
  keyId: string;
  count24h?: number;
  denyCount24h?: number;
  denyRatio24h?: number;
  breachCount24h?: number;
  dailyToolCalls?: number;
  rateLimitHits?: number;
  lastActive?: string;
  isKilled?: boolean;
} & Agent;

function ToolCountCell({ agent }: { agent: Agent }) {
  const n =
    (agent.allowed_tools?.length ?? 0) +
    (agent.restricted_tools?.length ?? 0) +
    (agent.allowed_tool_calls?.length ?? 0) +
    (agent.restricted_tool_calls?.length ?? 0);
  return <span className="tabular-nums font-mono text-xs">{n}</span>;
}

function DenyRatioCell({ count24h, denyCount24h }: { count24h?: number; denyCount24h?: number }) {
  const total = count24h ?? 0;
  const deny = denyCount24h ?? 0;
  if (total === 0) {
    return <span className="text-muted-foreground font-mono text-xs tabular-nums">0.0%</span>;
  }
  const ratio = (deny / total) * 100;
  const isHigh = ratio > 20;
  const isMed = ratio > 5;

  return (
    <div className="flex items-center gap-1.5 font-mono text-xs tabular-nums">
      <Badge
        variant="outline"
        className={`text-[11px] px-1.5 py-0 h-5 font-semibold ${
          isHigh
            ? "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30"
            : isMed
              ? "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30"
              : "text-muted-foreground border-border/60"
        }`}
      >
        {ratio.toFixed(1)}%
      </Badge>
      <span className="text-[10px] text-muted-foreground">({deny}/{total})</span>
    </div>
  );
}

function QuotaBurnCell({
  dailyCalls,
  limit,
}: {
  dailyCalls?: number;
  limit?: number;
}) {
  const usage = dailyCalls ?? 0;
  if (!limit || limit <= 0) {
    return (
      <div className="space-y-0.5">
        <div className="font-mono text-xs tabular-nums text-foreground">
          {usage.toLocaleString("id-ID")}{" "}
          <span className="text-[10px] text-muted-foreground">pggl</span>
        </div>
        <div className="text-[10px] text-muted-foreground">tanpa limit harian</div>
      </div>
    );
  }

  const pct = Math.min(100, Math.round((usage / limit) * 100));
  const isCritical = usage >= limit;
  const isWarning = pct >= 80 && !isCritical;

  // Hourly burn projection based on 24h usage
  const hourlyBurn = usage / 24;
  let projection = "";
  if (isCritical) {
    projection = "Kuota habis";
  } else if (hourlyBurn > 0) {
    const hoursLeft = Math.round((limit - usage) / hourlyBurn);
    if (pct >= 50 && hoursLeft <= 24) {
      projection = `≈ habis ${hoursLeft} jam`;
    }
  }

  return (
    <div className="w-44 space-y-1">
      <div className="flex items-center justify-between text-[11px] font-mono tabular-nums">
        <span>
          {usage.toLocaleString("id-ID")} / {limit.toLocaleString("id-ID")}
        </span>
        <span
          className={`font-semibold ${
            isCritical
              ? "text-red-600 dark:text-red-400"
              : isWarning
                ? "text-amber-600 dark:text-amber-400"
                : "text-muted-foreground"
          }`}
        >
          {pct}%
        </span>
      </div>

      {/* Progress Bar */}
      <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
        <div
          className={`h-full transition-all rounded-full ${
            isCritical
              ? "bg-red-500"
              : isWarning
                ? "bg-amber-500"
                : "bg-emerald-500"
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>

      {projection && (
        <div
          className={`text-[10px] font-mono ${
            isCritical
              ? "text-red-600 dark:text-red-400 font-semibold"
              : "text-amber-600 dark:text-amber-400"
          }`}
        >
          {projection}
        </div>
      )}
    </div>
  );
}

export const agentColumns: ColumnDef<AgentRow, unknown>[] = [
  {
    accessorKey: "name",
    header: "Agen",
    cell: ({ row }) => (
      <div className="flex items-center gap-1.5 font-medium">
        <span>{row.original.name ?? row.original.keyId}</span>
        {row.original.isKilled && (
          <Badge variant="destructive" className="text-[10px] py-0 px-1 font-mono font-semibold">
            KILL
          </Badge>
        )}
      </div>
    ),
  },
  {
    accessorKey: "keyId",
    header: "Key ID",
    cell: ({ row }) => <KeyCell id={row.original.keyId} />,
  },
  {
    accessorKey: "team_id",
    header: "Tim",
    cell: ({ row }) => (
      <span className="text-xs text-muted-foreground font-mono">
        {row.original.team_id || "—"}
      </span>
    ),
  },
  {
    id: "quotaBurn",
    header: "Kuota Harian (Panggilan)",
    cell: ({ row }) => (
      <QuotaBurnCell
        dailyCalls={row.original.dailyToolCalls}
        limit={row.original.rate_limit?.daily_tool_calls}
      />
    ),
  },
  {
    id: "denyRatio",
    header: "Deny Ratio (24h)",
    cell: ({ row }) => (
      <DenyRatioCell
        count24h={row.original.count24h}
        denyCount24h={row.original.denyCount24h}
      />
    ),
  },
  {
    accessorKey: "rateLimitHits",
    header: "429 Hits",
    cell: ({ row }) => {
      const hits = row.original.rateLimitHits ?? 0;
      if (hits === 0) {
        return <span className="text-muted-foreground font-mono text-xs tabular-nums">—</span>;
      }
      return (
        <Badge
          variant="destructive"
          className="bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30 font-mono text-xs tabular-nums"
        >
          {hits}
        </Badge>
      );
    },
  },
  {
    accessorKey: "lastActive",
    header: "Aktivitas Terakhir",
    cell: ({ row }) => (
      <Timestamp time={row.original.lastActive} relative />
    ),
  },
  {
    id: "tools",
    header: "Aturan Tool",
    cell: ({ row }) => <ToolCountCell agent={row.original} />,
  },
];
