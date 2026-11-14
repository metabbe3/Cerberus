"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertCircle, Plus, ShieldAlert, UserPlus } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Timestamp } from "@/components/timestamp";
import { agentColumns, type AgentRow } from "@/components/agents/agents-table";
import { AddAgentDialog } from "@/components/agents/add-agent-dialog";
import { ConnectInfoCard } from "@/components/agents/connect-info-card";
import { useAgentsSummary, useData } from "@/lib/queries";

export default function AgentsPage() {
  const router = useRouter();
  const [wizardOpen, setWizardOpen] = useState(false);
  const [initialWizardKey, setInitialWizardKey] = useState<string>("");

  const { data, isPending, isError, error } = useData();
  const { data: summaryData } = useAgentsSummary("24h");

  // Summary statistics from engine agents-summary
  const agentStats = useMemo(() => {
    const stats: Record<
      string,
      {
        count24h: number;
        denyCount24h: number;
        denyRatio24h: number;
        breachCount24h: number;
        dailyToolCalls: number;
        rateLimitHits: number;
        lastActive?: string;
      }
    > = {};

    if (summaryData) {
      for (const s of summaryData) {
        const total = s.total ?? 0;
        const deny = s.deny ?? 0;
        stats[s.key_id] = {
          count24h: total,
          denyCount24h: deny,
          denyRatio24h: total > 0 ? (deny / total) * 100 : 0,
          breachCount24h: s.breach_count ?? 0,
          dailyToolCalls: s.daily_tool_calls ?? 0,
          rateLimitHits: s.rate_limit_hits ?? 0,
          lastActive: s.last_active || undefined,
        };
      }
    }
    return stats;
  }, [summaryData]);

  // Unregistered keys detected in traffic (IAM Access Analyzer style)
  const unregisteredKeys = useMemo(() => {
    if (!summaryData || !data?.data?.agents) return [];
    const registered = new Set(Object.keys(data.data.agents));
    return summaryData.filter((s) => !registered.has(s.key_id));
  }, [summaryData, data?.data?.agents]);

  const handleRegisterUnregistered = (keyId: string) => {
    setInitialWizardKey(keyId);
    setWizardOpen(true);
  };

  const handleOpenNewWizard = () => {
    setInitialWizardKey("");
    setWizardOpen(true);
  };

  if (isPending) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="size-4" />
        <AlertTitle>Engine Tidak Dapat Dihubungi</AlertTitle>
        <AlertDescription>{error.message}</AlertDescription>
      </Alert>
    );
  }

  const registeredAgents = data.data.agents || {};
  const rows: AgentRow[] = Object.entries(registeredAgents).map(([keyId, agent]) => {
    const stat = agentStats[keyId];
    return {
      keyId,
      count24h: stat?.count24h ?? 0,
      denyCount24h: stat?.denyCount24h ?? 0,
      denyRatio24h: stat?.denyRatio24h ?? 0,
      breachCount24h: stat?.breachCount24h ?? 0,
      dailyToolCalls: stat?.dailyToolCalls ?? 0,
      rateLimitHits: stat?.rateLimitHits ?? 0,
      lastActive: stat?.lastActive,
      isKilled: !!data.data.config?.kill_switch?.keys?.[keyId],
      ...agent,
    };
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agen & Kebijakan Akses"
        description="Daftar kunci terdaftar dan kebijakan keamanan aktif. Klik baris untuk detail atau konfigurasi."
      >
        <Button onClick={handleOpenNewWizard}>
          <Plus className="mr-1.5 size-4" /> Tambah Agen
        </Button>
      </PageHeader>

      {/* Unregistered Keys Detected in Traffic (IAM Access Analyzer) */}
      {unregisteredKeys.length > 0 && (
        <Card className="border-amber-500/40 bg-amber-500/5">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="size-5 text-amber-600 dark:text-amber-400" />
              <CardTitle className="text-sm font-semibold text-amber-900 dark:text-amber-200">
                Kunci Belum Terdaftar (Terdeteksi di Trafik)
              </CardTitle>
              <Badge variant="outline" className="ml-auto font-mono text-xs border-amber-500/40 text-amber-600 dark:text-amber-400">
                {unregisteredKeys.length} KUNCI
              </Badge>
            </div>
            <CardDescription className="text-xs text-amber-800/80 dark:text-amber-300/80">
              Kunci berikut terdeteksi dalam evaluasi gateway tetapi belum terdaftar dalam kebijakan resmi.
              Daftarkan kunci ini agar aman ketika fail-open dimatikan.
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="rounded-md border border-amber-500/20 bg-background overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-48">Key ID</TableHead>
                    <TableHead className="w-28 text-right">Panggilan 24h</TableHead>
                    <TableHead className="w-28 text-right">Ditolak (Deny)</TableHead>
                    <TableHead className="w-40 text-right">Aktivitas Terakhir</TableHead>
                    <TableHead className="w-36 text-right">Aksi</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {unregisteredKeys.map((u) => (
                    <TableRow key={u.key_id} className="text-xs">
                      <TableCell className="font-mono font-semibold text-foreground">
                        {u.key_id}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        {u.total.toLocaleString("id-ID")}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums text-red-600 dark:text-red-400">
                        {u.deny.toLocaleString("id-ID")}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        <Timestamp time={u.last_active} relative />
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="secondary"
                          className="h-7 text-xs gap-1"
                          onClick={() => handleRegisterUnregistered(u.key_id)}
                        >
                          <UserPlus className="size-3.5" />
                          Daftarkan 1-Klik
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Panduan Integrasi Cepat */}
      <ConnectInfoCard />

      {/* Tabel Agen Terdaftar */}
      {rows.length === 0 ? (
        <EmptyState
          title="Belum ada agen terdaftar"
          hint="Klik tombol '+ Tambah Agen' di atas untuk mendaftarkan kredensial agen pertama Anda."
        />
      ) : (
        <DataTable
          columns={agentColumns}
          data={rows}
          onRowClick={(row) => router.push(`/agents/${row.keyId}`)}
        />
      )}

      {/* Wizard Tambah Agen */}
      <AddAgentDialog
        open={wizardOpen}
        onOpenChange={setWizardOpen}
        teams={data.data.teams}
        initialKeyId={initialWizardKey}
      />
    </div>
  );
}
