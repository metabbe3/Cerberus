"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { Badge } from "@/components/ui/badge";
import { KeyCell } from "@/components/key-cell";
import type { Agent } from "@/lib/schema";

export type AgentRow = {
  keyId: string;
  count24h?: number;
  lastActive?: string;
} & Agent;

function ToolCountCell({ agent }: { agent: Agent }) {
  const n =
    (agent.allowed_tools?.length ?? 0) +
    (agent.restricted_tools?.length ?? 0) +
    (agent.allowed_tool_calls?.length ?? 0) +
    (agent.restricted_tool_calls?.length ?? 0);
  return <span className="tabular-nums">{n}</span>;
}

function formatLastActive(isoString?: string): string {
  if (!isoString) return "Belum aktif";
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return "Belum aktif";
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 60) return "Baru saja";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m lalu`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}j lalu`;
  return d.toLocaleDateString("id-ID", { month: "short", day: "numeric" });
}

function Decisions24hCell({ count }: { count: number }) {
  if (count < 10) {
    return (
      <Badge variant="outline" className="text-muted-foreground font-normal text-xs">
        {count} • sepi
      </Badge>
    );
  }
  if (count <= 100) {
    return (
      <Badge variant="secondary" className="bg-primary/15 text-primary border-primary/20 text-xs font-medium">
        {count} • aktif
      </Badge>
    );
  }
  return (
    <Badge variant="destructive" className="bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30 text-xs font-semibold">
      {count} • sibuk
    </Badge>
  );
}

export const agentColumns: ColumnDef<AgentRow, unknown>[] = [
  {
    accessorKey: "name",
    header: "Name",
    cell: ({ row }) => (
      <span className="font-medium">{row.original.name ?? row.original.keyId}</span>
    ),
  },
  {
    accessorKey: "keyId",
    header: "Key ID",
    cell: ({ row }) => <KeyCell id={row.original.keyId} />,
  },
  { accessorKey: "team_id", header: "Team" },
  {
    accessorKey: "lastActive",
    header: "Last active",
    cell: ({ row }) => (
      <span
        className="text-xs text-muted-foreground whitespace-nowrap"
        title={row.original.lastActive ? new Date(row.original.lastActive).toLocaleString("id-ID") : undefined}
      >
        {formatLastActive(row.original.lastActive)}
      </span>
    ),
  },
  {
    accessorKey: "count24h",
    header: "Decisions 24h",
    cell: ({ row }) => <Decisions24hCell count={row.original.count24h ?? 0} />,
  },
  {
    accessorKey: "risk_tier",
    header: "Risk",
    cell: ({ row }) =>
      row.original.risk_tier ? (
        <Badge
          variant={row.original.risk_tier === "high" ? "destructive" : "secondary"}
          className={
            row.original.risk_tier === "low"
              ? "bg-success/15 text-success"
              : row.original.risk_tier === "medium"
                ? "bg-primary/15 text-primary"
                : undefined
          }
        >
          {row.original.risk_tier}
        </Badge>
      ) : null,
  },
  {
    accessorKey: "budget_limit",
    header: "Budget",
    cell: ({ row }) =>
      row.original.budget_limit != null ? (
        <span className="tabular-nums">{row.original.budget_limit}</span>
      ) : null,
  },
  {
    id: "tools",
    header: "Tool rules",
    cell: ({ row }) => <ToolCountCell agent={row.original} />,
  },
];
