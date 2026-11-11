"use client";

import { useRouter } from "next/navigation";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { agentColumns, type AgentRow } from "@/components/agents/agents-table";
import { useData } from "@/lib/queries";

export default function AgentsPage() {
  const router = useRouter();
  const { data, isPending, isError, error } = useData();

  if (isPending) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-full" />
      </div>
    );
  }
  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle />
        <AlertTitle>Engine unreachable</AlertTitle>
        <AlertDescription>{error.message}</AlertDescription>
      </Alert>
    );
  }

  const rows: AgentRow[] = Object.entries(data.data.agents).map(([keyId, agent]) => ({
    keyId,
    ...agent,
  }));

  return (
    <div className="space-y-4">
      <PageHeader
        title="Agents"
        description="Registered keys and the policy each one runs under. Click a row to edit."
      />
      {rows.length === 0 ? (
        <EmptyState
          title="No agents registered"
          hint="Add an agent to data/*.json or via PUT /v1/admin/data."
        />
      ) : (
        <DataTable
          columns={agentColumns}
          data={rows}
          onRowClick={(row) => router.push(`/agents/${row.keyId}`)}
        />
      )}
    </div>
  );
}
