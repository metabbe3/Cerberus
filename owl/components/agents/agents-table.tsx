"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { Badge } from "@/components/ui/badge";
import { KeyCell } from "@/components/key-cell";
import type { Agent } from "@/lib/schema";

export type AgentRow = { keyId: string } & Agent;

function ToolCountCell({ agent }: { agent: Agent }) {
  const n =
    (agent.allowed_tools?.length ?? 0) +
    (agent.restricted_tools?.length ?? 0) +
    (agent.allowed_tool_calls?.length ?? 0) +
    (agent.restricted_tool_calls?.length ?? 0);
  return <span className="tabular-nums">{n}</span>;
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
