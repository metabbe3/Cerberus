"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { Plus } from "lucide-react";
import { DataTable } from "@/components/data-table";
import { KeyCell } from "@/components/key-cell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { AuditEvent } from "@/lib/schema";

function timeCell(ev: AuditEvent) {
  return new Date(ev.time).toLocaleTimeString();
}

const columns = (onCreateRule: (ev: AuditEvent) => void): ColumnDef<AuditEvent, unknown>[] => [
  { id: "time", header: "Time", cell: ({ row }) => timeCell(row.original) },
  { accessorKey: "stage", header: "Stage" },
  { accessorKey: "key_id", header: "Key", cell: ({ row }) => <KeyCell id={row.original.key_id} /> },
  {
    accessorKey: "subject",
    header: "Subject",
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.subject}</span>,
  },
  {
    accessorKey: "decision",
    header: "Decision",
    cell: ({ row }) => (
      <Badge
        variant={row.original.decision === "allow" ? "secondary" : "destructive"}
        className={row.original.decision === "allow" ? "bg-success/15 text-success" : undefined}
      >
        {row.original.decision}
      </Badge>
    ),
  },
  {
    accessorKey: "rule_id",
    header: "Rule",
    cell: ({ row }) => <span className="font-mono text-xs">{row.original.rule_id}</span>,
  },
  {
    id: "rule-action",
    header: "",
    cell: ({ row }) =>
      row.original.decision === "deny" && row.original.stage === "tool" ? (
        <Button
          variant="outline"
          size="sm"
          onClick={(e) => {
            e.stopPropagation();
            onCreateRule(row.original);
          }}
        >
          <Plus aria-hidden /> Create rule
        </Button>
      ) : null,
  },
];

export function AuditTable({
  events,
  onCreateRule,
}: {
  events: AuditEvent[];
  onCreateRule: (ev: AuditEvent) => void;
}) {
  return <DataTable columns={columns(onCreateRule)} data={events} />;
}
