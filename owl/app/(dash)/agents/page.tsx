"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertCircle, Plus } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { agentColumns, type AgentRow } from "@/components/agents/agents-table";
import { AddAgentDialog } from "@/components/agents/add-agent-dialog";
import { ConnectInfoCard } from "@/components/agents/connect-info-card";
import { useAudit, useData } from "@/lib/queries";

export default function AgentsPage() {
  const router = useRouter();
  const [wizardOpen, setWizardOpen] = useState(false);
  const { data, isPending, isError, error } = useData();

  // 24h audit window for client-side aggregation
  const twentyFourHoursAgo = useMemo(
    () => new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    [],
  );

  const auditParams = useMemo(() => {
    const p = new URLSearchParams();
    p.set("since", twentyFourHoursAgo);
    p.set("limit", "1000");
    return p;
  }, [twentyFourHoursAgo]);

  const { data: auditEvents } = useAudit(auditParams);

  // Client-side aggregate decisions in last 24h and last event timestamp
  const agentStats = useMemo(() => {
    const stats: Record<string, { count24h: number; lastActive?: string }> = {};
    if (auditEvents) {
      for (const ev of auditEvents) {
        if (!stats[ev.key_id]) {
          stats[ev.key_id] = { count24h: 1, lastActive: ev.time };
        } else {
          stats[ev.key_id].count24h += 1;
          if (
            !stats[ev.key_id].lastActive ||
            new Date(ev.time) > new Date(stats[ev.key_id].lastActive!)
          ) {
            stats[ev.key_id].lastActive = ev.time;
          }
        }
      }
    }
    return stats;
  }, [auditEvents]);

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
    count24h: agentStats[keyId]?.count24h ?? 0,
    lastActive: agentStats[keyId]?.lastActive,
    ...agent,
  }));

  return (
    <div className="space-y-4">
      <PageHeader
        title="Agents"
        description="Registered keys and the policy each one runs under. Click a row to edit."
      >
        <Button onClick={() => setWizardOpen(true)}>
          <Plus className="mr-1.5 size-4" /> Tambah Agent
        </Button>
      </PageHeader>

      {/* 9B Connect Info Card */}
      <ConnectInfoCard />

      {rows.length === 0 ? (
        <EmptyState
          title="No agents registered"
          hint="Gunakan tombol '+ Tambah Agent' di atas atau tambahkan via data/*.json."
        />
      ) : (
        <DataTable
          columns={agentColumns}
          data={rows}
          onRowClick={(row) => router.push(`/agents/${row.keyId}`)}
        />
      )}

      {/* 9A Wizard Tambah Agent */}
      <AddAgentDialog
        open={wizardOpen}
        onOpenChange={setWizardOpen}
        teams={data.data.teams}
      />
    </div>
  );
}
