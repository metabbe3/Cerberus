"use client";

import { useQuery } from "@tanstack/react-query";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";
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
  value,
  sub,
}: {
  title: string;
  value: string;
  sub?: string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold tabular-nums">{value}</div>
        {sub ? <p className="text-xs text-muted-foreground">{sub}</p> : null}
      </CardContent>
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

  if (stats.isPending) {
    return (
      <div className="grid gap-4 sm:grid-cols-3">
        <Skeleton className="h-28" />
        <Skeleton className="h-28" />
        <Skeleton className="h-28" />
      </div>
    );
  }
  if (stats.isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle />
        <AlertTitle>Engine unreachable</AlertTitle>
        <AlertDescription>{(stats.error as Error).message}</AlertDescription>
      </Alert>
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
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Overview</h1>
        {isPending ? (
          <Badge variant="outline">epoch …</Badge>
        ) : (
          <Badge variant="outline">epoch {data?.epoch ?? 0}</Badge>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <StatsCard title="Decisions / min" value={String(perMin)} sub="last 5 minutes" />
        <StatsCard
          title="Allow / deny"
          value={`${100 - denyPct}% / ${denyPct}%`}
          sub={`${denies.length} of ${events.length} denied`}
        />
        <Card>
          <CardHeader>
            <CardTitle className="text-sm text-muted-foreground">
              Top denied rules
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {topDenied.length === 0 ? (
              <p className="text-sm text-muted-foreground">No denials 🎉</p>
            ) : (
              topDenied.map(([rule, n]) => (
                <div key={rule} className="flex justify-between gap-4 text-sm">
                  <span className="truncate font-mono text-xs">{rule}</span>
                  <span className="tabular-nums">{n}</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
