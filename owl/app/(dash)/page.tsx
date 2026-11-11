"use client";

import { useQuery } from "@tanstack/react-query";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Activity, AlertCircle, ShieldAlert, ShieldCheck, type LucideIcon } from "lucide-react";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useData } from "@/lib/queries";
import { AuditEventSchema } from "@/lib/schema";

// ponytail: stats over a single 5-min audit page, aggregated client-side —
// aggregate server-side (or scrape /metrics) if the dashboard scales up.
async function fetchStats() {
  const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const res = await fetch(`/api/audit?since=${encodeURIComponent(since)}&limit=500`);
  const body = await res.json();
  if (!res.ok) {
    throw new Error((body as { error?: string }).error ?? "audit query failed");
  }
  return AuditEventSchema.array().parse(body);
}

function StatsCard({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: LucideIcon;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="size-4 text-muted-foreground" aria-hidden />
      </CardHeader>
      <CardContent className="space-y-2">{children}</CardContent>
    </Card>
  );
}

export default function OverviewPage() {
  const stats = useQuery({
    queryKey: ["stats"],
    queryFn: fetchStats,
    refetchInterval: 30_000,
  });
  const { data, isPending } = useData();

  const header = (
    <PageHeader title="Overview" description="Gateway decisions over the last 5 minutes.">
      <Badge variant="outline" className="font-mono">
        epoch {isPending ? "…" : (data?.epoch ?? 0)}
      </Badge>
    </PageHeader>
  );

  if (stats.isPending) {
    return (
      <div className="space-y-6">
        {header}
        <div className="grid gap-4 sm:grid-cols-3">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      </div>
    );
  }
  if (stats.isError) {
    return (
      <div className="space-y-6">
        {header}
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Engine unreachable</AlertTitle>
          <AlertDescription>{(stats.error as Error).message}</AlertDescription>
        </Alert>
      </div>
    );
  }

  const events = stats.data;
  const perMin = Math.round(events.length / 5);
  const denies = events.filter((e) => e.decision === "deny");
  const denyPct = events.length ? Math.round((denies.length / events.length) * 100) : 0;
  const topDenied = Object.entries(
    denies.reduce<Record<string, number>>((acc, e) => {
      acc[e.rule_id] = (acc[e.rule_id] ?? 0) + 1;
      return acc;
    }, {}),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);

  return (
    <div className="space-y-6">
      {header}
      <div className="grid gap-4 sm:grid-cols-3">
        <StatsCard title="Decisions / min" icon={Activity}>
          <div className="text-3xl font-semibold tabular-nums">{perMin}</div>
          <p className="text-xs text-muted-foreground">{events.length} in the last 5 minutes</p>
        </StatsCard>
        <StatsCard title="Allow / deny" icon={ShieldCheck}>
          <div className="text-3xl font-semibold tabular-nums">
            <span className="text-success">{events.length ? 100 - denyPct : 0}%</span>
            <span className="px-1.5 text-muted-foreground">/</span>
            <span className="text-destructive">{denyPct}%</span>
          </div>
          <div className="flex h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden>
            {events.length ? (
              <>
                <div className="bg-success" style={{ width: `${100 - denyPct}%` }} />
                <div className="bg-destructive" style={{ width: `${denyPct}%` }} />
              </>
            ) : null}
          </div>
          <p className="text-xs text-muted-foreground">
            {denies.length} of {events.length} denied
          </p>
        </StatsCard>
        <StatsCard title="Top denied rules" icon={ShieldAlert}>
          {topDenied.length === 0 ? (
            <p className="text-sm text-muted-foreground">No denials 🎉</p>
          ) : (
            topDenied.map(([rule, n]) => (
              <div key={rule} className="flex justify-between gap-4 text-sm">
                <span className="truncate font-mono text-xs">{rule}</span>
                <span className="tabular-nums text-destructive">{n}</span>
              </div>
            ))
          )}
        </StatsCard>
      </div>
    </div>
  );
}
