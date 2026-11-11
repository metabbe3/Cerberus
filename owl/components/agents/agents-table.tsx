"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Badge } from "@/components/ui/badge";
import type { Agent } from "@/lib/schema";

export type AgentRow = { keyId: string } & Agent;

// 64-hex key IDs: truncated display, full ID on click-to-copy — and the
// click never bubbles into the row's editor navigation.
function KeyCell({ id }: { id: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={`${id} — click to copy`}
      className="flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(id).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      {id.length > 14 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id}
      {copied ? (
        <Check className="size-3" aria-hidden />
      ) : (
        <Copy className="size-3" aria-hidden />
      )}
    </button>
  );
}

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
        <Badge variant={row.original.risk_tier === "high" ? "destructive" : "secondary"}>
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
