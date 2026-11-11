"use client";

// Deep monitoring overview — Astryx Service Health Monitor pattern
// (KPI tiles with status dots + sparklines, ranged time-series chart,
// component health strip) adapted to Owl's dark dense dashboard.
// Data comes from the new engine endpoints: /api/timeseries (bucketed
// allow/deny over a selectable window) and /api/components (estate health).

import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, CheckCircle2, Clock, ShieldAlert, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

type Bucket = { bucket_ns: number; allow: number; deny: number; total: number };
type Component = { component: string; status: "ok" | "degraded" | "down"; detail: string; meta?: Record<string, unknown> };

const WINDOWS = [
  { id: "1h", label: "1 jam", hours: 1, buckets: 60 },
  { id: "6h", label: "6 jam", hours: 6, buckets: 48 },
  { id: "24h", label: "24 jam", hours: 24, buckets: 48 },
  { id: "7d", label: "7 hari", hours: 24 * 7, buckets: 84 },
] as const;

type WindowId = (typeof WINDOWS)[number]["id"];

function sinceFor(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

async function fetchTimeseries(windowId: WindowId): Promise<Bucket[]> {
  const w = WINDOWS.find((x) => x.id === windowId)!;
  const res = await fetch(`/api/timeseries?since=${encodeURIComponent(sinceFor(w.hours))}&buckets=${w.buckets}`);
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? "timeseries failed");
  return body as Bucket[];
}

async function fetchComponents(): Promise<Component[]> {
  const res = await fetch("/api/components");
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? "components failed");
  return (body as { components: Component[] }).components;
}

// Minimal SVG sparkline — no chart lib needed for 40 points.
function Sparkline({ data, stroke }: { data: number[]; stroke: string }) {
  if (data.length === 0) return <div className="h-8" />;
  const max = Math.max(...data, 1);
  const w = 120;
  const h = 32;
  const pts = data
    .map((v, i) => `${(i / Math.max(data.length - 1, 1)) * w},${h - (v / max) * (h - 2) - 1}`)
    .join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-8 w-full" preserveAspectRatio="none" aria-hidden>
      <polyline points={pts} fill="none" stroke={stroke} strokeWidth="1.5" />
    </svg>
  );
}

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function KpiTile({
  label,
  value,
  sub,
  spark,
  stroke,
  icon: Icon,
}: {
  label: string;
  value: string;
  sub: string;
  spark: number[];
  stroke: string;
  icon: typeof Activity;
}) {
  return (
    <Card>
      <CardContent className="space-y-2 pt-4">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Icon className="size-4" aria-hidden />
          <span className="text-sm font-medium">{label}</span>
        </div>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        <div className="text-xs text-muted-foreground">{sub}</div>
        <Sparkline data={spark} stroke={stroke} />
      </CardContent>
    </Card>
  );
}

export default function MonitoringPage() {
  const [win, setWin] = useState<WindowId>("24h");
  const ts = useQuery({ queryKey: ["timeseries", win], queryFn: () => fetchTimeseries(win), refetchInterval: 60_000 });
  const comps = useQuery({ queryKey: ["components"], queryFn: fetchComponents, refetchInterval: 30_000 });

  const stats = useMemo(() => {
    const b = ts.data ?? [];
    const total = b.reduce((s, x) => s + x.total, 0);
    const deny = b.reduce((s, x) => s + x.deny, 0);
    const allow = total - deny;
    const peak = b.reduce((m, x) => Math.max(m, x.total), 0);
    return { total, deny, allow, peak, denyPct: total > 0 ? Math.round((deny / total) * 1000) / 10 : 0 };
  }, [ts.data]);

  const header = (
    <PageHeader title="Monitoring" description="Decisions, komponen gateway, dan tren beban dalam satu tampilan.">
      <div className="flex items-center gap-1 rounded-lg border p-1">
        {WINDOWS.map((w) => (
          <Button
            key={w.id}
            size="sm"
            variant={win === w.id ? "default" : "ghost"}
            className="h-7 px-2 text-xs"
            onClick={() => setWin(w.id)}
          >
            {w.label}
          </Button>
        ))}
      </div>
    </PageHeader>
  );

  if (ts.isPending) {
    return (
      <div className="space-y-6">
        {header}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-36" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }
  if (ts.isError) {
    return (
      <div className="space-y-6">
        {header}
        <Card>
          <CardContent className="pt-6 text-sm text-destructive">Gagal memuat timeseries: {String(ts.error)}</CardContent>
        </Card>
      </div>
    );
  }

  const w = WINDOWS.find((x) => x.id === win)!;

  return (
    <div className="space-y-6">
      {header}

      {/* Estate health strip — one line, every component */}
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {(comps.data ?? []).map((c) => (
          <Card key={c.component}>
            <CardContent className="flex items-center gap-2 pt-4">
              {c.status === "ok" ? (
                <CheckCircle2 className="size-4 shrink-0 text-emerald-500" aria-hidden />
              ) : (
                <AlertTriangle className={`size-4 shrink-0 ${c.status === "down" ? "text-destructive" : "text-amber-500"}`} aria-hidden />
              )}
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">{c.component}</div>
                <div className="truncate text-xs text-muted-foreground">{c.detail}</div>
              </div>
            </CardContent>
          </Card>
        ))}
        {comps.isPending && <Skeleton className="h-16 sm:col-span-2 lg:col-span-5" />}
      </div>

      {/* KPI tiles */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiTile
          label="Total keputusan"
          value={fmt(stats.total)}
          sub={`${w.label} terakhir`}
          spark={(ts.data ?? []).map((b) => b.total)}
          stroke="var(--color-primary, #8884d8)"
          icon={Activity}
        />
        <KpiTile
          label="Diizinkan"
          value={fmt(stats.allow)}
          sub={`${100 - stats.denyPct}% dari total`}
          spark={(ts.data ?? []).map((b) => b.allow)}
          stroke="#10b981"
          icon={ShieldCheck}
        />
        <KpiTile
          label="Ditolak"
          value={fmt(stats.deny)}
          sub={`${stats.denyPct}% dari total`}
          spark={(ts.data ?? []).map((b) => b.deny)}
          stroke="#ef4444"
          icon={ShieldAlert}
        />
        <KpiTile
          label="Puncak per bucket"
          value={fmt(stats.peak)}
          sub={`bucket ${Math.round((w.hours * 60) / w.buckets)} menit`}
          spark={(ts.data ?? []).map((b) => b.total)}
          stroke="#f59e0b"
          icon={Clock}
        />
      </div>

      {/* Allow vs deny area chart (pure SVG, stacked) */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Allow vs Deny — {w.label}</CardTitle>
        </CardHeader>
        <CardContent>
          {(() => {
            const b = ts.data ?? [];
            if (b.length === 0) return <div className="py-10 text-center text-sm text-muted-foreground">Tidak ada keputusan di window ini.</div>;
            const max = Math.max(...b.map((x) => x.total), 1);
            return (
              <svg viewBox={`0 0 1000 160`} className="h-40 w-full" preserveAspectRatio="none" role="img" aria-label="Grafik allow vs deny">
                {b.map((x, i) => {
                  const bw = 1000 / b.length;
                  const allowH = (x.allow / max) * 150;
                  const denyH = (x.deny / max) * 150;
                  return (
                    <g key={i} transform={`translate(${i * bw},0)`}>
                      <rect y={160 - denyH} width={bw * 0.8} height={denyH} fill="#ef4444" opacity="0.75" />
                      <rect y={160 - denyH - allowH} width={bw * 0.8} height={allowH} fill="#10b981" opacity="0.75" />
                    </g>
                  );
                })}
              </svg>
            );
          })()}
          <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><span className="inline-block size-2 rounded-sm bg-emerald-500" /> allow</span>
            <span className="flex items-center gap-1"><span className="inline-block size-2 rounded-sm bg-red-500" /> deny</span>
            <Badge variant="outline" className="ml-auto font-mono text-[10px]">bucket {Math.round((w.hours * 60) / w.buckets)}m</Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
