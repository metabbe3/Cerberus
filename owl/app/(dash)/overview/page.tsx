"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  Layers,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useAgentsSummary,
  useComponents,
  useData,
  useStatus,
  type ComponentHealth,
} from "@/lib/queries";

type Bucket = { bucket_ns: number; allow: number; deny: number; total: number };

const WINDOWS = [
  { id: "1h", label: "1 Jam", hours: 1, buckets: 60 },
  { id: "6h", label: "6 Jam", hours: 6, buckets: 48 },
  { id: "24h", label: "24 Jam", hours: 24, buckets: 48 },
  { id: "7d", label: "7 Hari", hours: 24 * 7, buckets: 84 },
] as const;

type WindowId = (typeof WINDOWS)[number]["id"];

async function fetchTimeseriesRanged(since: string, until?: string, buckets = 48): Promise<Bucket[]> {
  const q = new URLSearchParams();
  q.set("since", since);
  if (until) q.set("until", until);
  q.set("buckets", String(buckets));
  const res = await fetch(`/api/timeseries?${q.toString()}`);
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? "Gagal memuat timeseries");
  return body as Bucket[];
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString("id-ID");
}

function fmtUs(us: number): string {
  if (us < 1000) return `${Math.round(us)} µs`;
  return `${(us / 1000).toFixed(1)} ms`;
}

function Sparkline({ data, stroke }: { data: number[]; stroke: string }) {
  if (!data || data.length === 0) return <div className="h-6" />;
  const max = Math.max(...data, 1);
  const w = 120;
  const h = 24;
  const pts = data
    .map((v, i) => `${(i / Math.max(data.length - 1, 1)) * w},${h - (v / max) * (h - 2) - 1}`)
    .join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-6 w-full" preserveAspectRatio="none" aria-hidden>
      <polyline points={pts} fill="none" stroke={stroke} strokeWidth="1.5" />
    </svg>
  );
}

export default function OverviewPage() {
  const [win, setWin] = useState<WindowId>("24h");
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  const selectedWin = WINDOWS.find((w) => w.id === win)!;

  // Window timestamps
  const { curSince, curUntil, prevSince, prevUntil } = useMemo(() => {
    const now = Date.now();
    const durationMs = selectedWin.hours * 3600_000;
    return {
      curSince: new Date(now - durationMs).toISOString(),
      curUntil: new Date(now).toISOString(),
      prevSince: new Date(now - durationMs * 2).toISOString(),
      prevUntil: new Date(now - durationMs).toISOString(),
    };
  }, [selectedWin]);

  const { data: owlData } = useData();
  const { data: statusData, refetch: refetchStatus } = useStatus();
  const { data: compsData, refetch: refetchComps } = useComponents();
  const { data: agentsSummary } = useAgentsSummary("24h");

  // Current window timeseries
  const tsCur = useQuery({
    queryKey: ["timeseries", win, curSince],
    queryFn: () => fetchTimeseriesRanged(curSince, curUntil, selectedWin.buckets),
    refetchInterval: 30_000,
  });

  // Previous window timeseries (for period-over-period delta)
  const tsPrev = useQuery({
    queryKey: ["timeseries-prev", win, prevSince],
    queryFn: () => fetchTimeseriesRanged(prevSince, prevUntil, selectedWin.buckets),
    refetchInterval: 60_000,
  });

  const handleRefreshAll = () => {
    refetchStatus();
    refetchComps();
    tsCur.refetch();
    tsPrev.refetch();
  };

  // Metrics computation
  const metrics = useMemo(() => {
    const curBuckets = tsCur.data ?? [];
    const prevBuckets = tsPrev.data ?? [];

    const curTotal = curBuckets.reduce((acc, b) => acc + b.total, 0);
    const curDeny = curBuckets.reduce((acc, b) => acc + b.deny, 0);
    const curAllow = curTotal - curDeny;
    const curDenyRate = curTotal > 0 ? (curDeny / curTotal) * 100 : 0;

    const prevTotal = prevBuckets.reduce((acc, b) => acc + b.total, 0);
    const prevDeny = prevBuckets.reduce((acc, b) => acc + b.deny, 0);
    const prevDenyRate = prevTotal > 0 ? (prevDeny / prevTotal) * 100 : 0;

    const deltaDenyRate = curDenyRate - prevDenyRate;
    const deltaTotal = curTotal - prevTotal;

    const curPeak = curBuckets.reduce((m, b) => Math.max(m, b.total), 0);

    return {
      curTotal,
      curAllow,
      curDeny,
      curDenyRate,
      prevTotal,
      prevDenyRate,
      deltaDenyRate,
      deltaTotal,
      curPeak,
    };
  }, [tsCur.data, tsPrev.data]);

  // Top Triggered Rules 24h
  const topRules = useMemo(() => {
    const list = statusData?.top_denies_24h || statusData?.deny_24h_top10 || [];
    const totalDenies = list.reduce((sum, item) => sum + item.count, 0);
    return list.slice(0, 5).map((r) => ({
      rule_id: r.rule_id,
      count: r.count,
      share: totalDenies > 0 ? Math.round((r.count / totalDenies) * 1000) / 10 : 0,
    }));
  }, [statusData]);

  // Top Offenders
  const topOffenders = useMemo(() => {
    const list = (agentsSummary ?? []).filter((a) => a.deny > 0);
    return list
      .sort((a, b) => b.deny - a.deny)
      .slice(0, 5)
      .map((a) => ({
        key_id: a.key_id,
        deny: a.deny,
        total: a.total,
        ratio: a.total > 0 ? Math.round((a.deny / a.total) * 1000) / 10 : 0,
      }));
  }, [agentsSummary]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title="Command Center"
        description="Observabilitas gateway, evaluasi kebijakan, dan postur keamanan waktu nyata."
      >
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="font-mono text-xs">
            epoch {statusData?.bundle_epoch ?? owlData?.epoch ?? 0}
          </Badge>
          <div className="flex items-center gap-1 rounded-lg border p-1 bg-muted/20">
            {WINDOWS.map((w) => (
              <Button
                key={w.id}
                size="sm"
                variant={win === w.id ? "default" : "ghost"}
                className="h-7 px-2.5 text-xs font-medium"
                onClick={() => setWin(w.id)}
              >
                {w.label}
              </Button>
            ))}
          </div>
          <Button
            size="sm"
            variant="outline"
            className="h-9 px-2 text-xs"
            onClick={handleRefreshAll}
            title="Muat ulang data"
          >
            <RefreshCw className="size-3.5 mr-1.5" />
            Perbarui
          </Button>
        </div>
      </PageHeader>

      {/* 1. Health Strip */}
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {(compsData ?? []).map((c: ComponentHealth) => {
          const isOk = c.status === "ok";
          const isDown = c.status === "down";
          return (
            <Card key={c.component} className="border-border/60 bg-card/60">
              <CardContent className="flex items-center gap-2.5 p-3">
                {isOk ? (
                  <CheckCircle2 className="size-4 shrink-0 text-emerald-500" aria-hidden />
                ) : isDown ? (
                  <AlertCircle className="size-4 shrink-0 text-destructive" aria-hidden />
                ) : (
                  <AlertTriangle className="size-4 shrink-0 text-amber-500" aria-hidden />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-1">
                    <span className="truncate text-xs font-semibold capitalize tracking-tight">
                      {c.component.replace("_", " ")}
                    </span>
                    <Badge
                      variant="outline"
                      className={`text-[10px] px-1 py-0 h-4 uppercase ${
                        isOk
                          ? "text-emerald-500 border-emerald-500/30"
                          : isDown
                            ? "text-destructive border-destructive/30"
                            : "text-amber-500 border-amber-500/30"
                      }`}
                    >
                      {c.status}
                    </Badge>
                  </div>
                  <p className="truncate text-[11px] text-muted-foreground mt-0.5">
                    {c.detail || "Komponen berjalan"}
                  </p>
                </div>
              </CardContent>
            </Card>
          );
        })}
        {!compsData && (
          <>
            <Skeleton className="h-14 sm:col-span-2 lg:col-span-5" />
          </>
        )}
      </div>

      {/* 2. KPI Tiles */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {/* Total Keputusan */}
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Total Keputusan</span>
              <Activity className="size-4" aria-hidden />
            </div>
            <div className="text-2xl font-bold tracking-tight tabular-nums font-mono">
              {fmtNum(metrics.curTotal)}
            </div>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              {metrics.deltaTotal >= 0 ? (
                <span className="flex items-center text-emerald-500 font-medium">
                  <ArrowUpRight className="size-3.5 mr-0.5" />
                  +{fmtNum(metrics.deltaTotal)}
                </span>
              ) : (
                <span className="flex items-center text-muted-foreground font-medium">
                  <ArrowDownRight className="size-3.5 mr-0.5" />
                  {fmtNum(metrics.deltaTotal)}
                </span>
              )}
              <span>vs periode sebelumnya</span>
            </div>
            <Sparkline
              data={(tsCur.data ?? []).map((b) => b.total)}
              stroke="var(--primary, #3b82f6)"
            />
          </CardContent>
        </Card>

        {/* Diizinkan vs Ditolak */}
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Allow vs Deny</span>
              <ShieldCheck className="size-4 text-emerald-500" aria-hidden />
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tight text-emerald-500 font-mono tabular-nums">
                {fmtNum(metrics.curAllow)}
              </span>
              <span className="text-sm font-semibold text-muted-foreground">/</span>
              <span className="text-xl font-bold tracking-tight text-destructive font-mono tabular-nums">
                {fmtNum(metrics.curDeny)}
              </span>
            </div>
            <div className="text-xs text-muted-foreground">
              {metrics.curTotal > 0
                ? `${Math.round((metrics.curAllow / metrics.curTotal) * 100)}% lolos evaluasi`
                : "Belum ada evaluasi"}
            </div>
            <Sparkline
              data={(tsCur.data ?? []).map((b) => b.allow)}
              stroke="#10b981"
            />
          </CardContent>
        </Card>

        {/* Deny Rate Ternormalisasi + Delta */}
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Deny Rate (Ternormalisasi)</span>
              <ShieldAlert className="size-4 text-destructive" aria-hidden />
            </div>
            <div className="text-2xl font-bold tracking-tight text-destructive font-mono tabular-nums">
              {metrics.curDenyRate.toFixed(1)}%
            </div>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              {metrics.deltaDenyRate > 0 ? (
                <span className="flex items-center text-destructive font-medium">
                  <ArrowUpRight className="size-3.5 mr-0.5" />
                  +{metrics.deltaDenyRate.toFixed(1)}pp
                </span>
              ) : metrics.deltaDenyRate < 0 ? (
                <span className="flex items-center text-emerald-500 font-medium">
                  <ArrowDownRight className="size-3.5 mr-0.5" />
                  {metrics.deltaDenyRate.toFixed(1)}pp
                </span>
              ) : (
                <span className="text-muted-foreground">0.0pp</span>
              )}
              <span>vs periode sebelumnya</span>
            </div>
            <Sparkline
              data={(tsCur.data ?? []).map((b) => (b.total > 0 ? (b.deny / b.total) * 100 : 0))}
              stroke="#ef4444"
            />
          </CardContent>
        </Card>

        {/* Latensi p50 / p95 / p99 */}
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Latensi Evaluasi</span>
              <Zap className="size-4 text-amber-500" aria-hidden />
            </div>
            <div className="flex items-baseline gap-2 font-mono tabular-nums">
              <span className="text-xl font-bold tracking-tight">
                {fmtUs(statusData?.latency_p50_us ?? 0)}
              </span>
              <span className="text-xs text-muted-foreground font-medium">p50</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono tabular-nums">
              <span>p95: {fmtUs(statusData?.latency_p95_us ?? 0)}</span>
              <span>•</span>
              <span>p99: {fmtUs(statusData?.latency_p99_us ?? 0)}</span>
            </div>
            <Sparkline
              data={statusData?.latency_sparkline && statusData.latency_sparkline.length > 0 ? statusData.latency_sparkline : [1, 2, 1, 1, 3, 2]}
              stroke="#f59e0b"
            />
          </CardContent>
        </Card>

        {/* Cache Hit Rate */}
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Cache Hit Rate</span>
              <Clock className="size-4 text-emerald-500" aria-hidden />
            </div>
            <div className="text-2xl font-bold tracking-tight text-emerald-500 font-mono tabular-nums">
              {statusData?.cache_hit_rate !== undefined
                ? `${(statusData.cache_hit_rate * 100).toFixed(1)}%`
                : "—"}
            </div>
            <div className="text-xs text-muted-foreground">
              Evaluasi OPA disajikan dari cache
            </div>
          </CardContent>
        </Card>

        {/* Fail-closed / Eval Error Rate */}
        <Card className={statusData?.fail_closed_count && statusData.fail_closed_count > 0 ? "border-destructive/60 bg-destructive/10" : ""}>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Fail-Closed & Timeout</span>
              <AlertTriangle className={statusData?.fail_closed_count && statusData.fail_closed_count > 0 ? "size-4 text-destructive" : "size-4 text-emerald-500"} aria-hidden />
            </div>
            <div className={`text-2xl font-bold tracking-tight font-mono tabular-nums ${statusData?.fail_closed_count && statusData.fail_closed_count > 0 ? "text-destructive" : "text-emerald-500"}`}>
              {statusData?.fail_closed_rate !== undefined
                ? `${(statusData.fail_closed_rate * 100).toFixed(1)}%`
                : "0.0%"}
            </div>
            <div className="text-xs text-muted-foreground">
              {statusData?.fail_closed_count && statusData.fail_closed_count > 0
                ? `${statusData.fail_closed_count} evaluasi timeout / error (kebijakan tidak berjalan)`
                : "0.0% (0 error • seluruh evaluasi policy berhasil)"}
            </div>
          </CardContent>
        </Card>

        {/* Audit Queue Depth */}
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Antrean Audit Sink</span>
              <Layers className="size-4 text-muted-foreground" aria-hidden />
            </div>
            <div className="text-2xl font-bold tracking-tight font-mono tabular-nums">
              {statusData?.audit_queue_depth ?? 0}
            </div>
            <div className="text-xs text-muted-foreground">
              {(statusData?.audit_queue_depth ?? 0) === 0
                ? "Antrean sinkron tanpa jeda (0 pending)"
                : `${statusData?.audit_queue_depth} event antre tulis ke disk`}
            </div>
          </CardContent>
        </Card>

        {/* Puncak per Bucket */}
        <Card>
          <CardContent className="space-y-1.5 p-4">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Puncak Beban</span>
              <Clock className="size-4 text-amber-500" aria-hidden />
            </div>
            <div className="text-2xl font-bold tracking-tight font-mono tabular-nums">
              {fmtNum(metrics.curPeak)}
            </div>
            <div className="text-xs text-muted-foreground">
              Keputusan terbanyak per bucket {Math.round((selectedWin.hours * 60) / selectedWin.buckets)}m
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 3. Stacked Chart dengan Sumbu Waktu, Skala Y, dan Hover Tooltip */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-semibold">
            Trafik Evaluasi: Allow vs Deny ({selectedWin.label})
          </CardTitle>
          <div className="flex items-center gap-3 text-xs text-muted-foreground font-medium">
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-sm bg-emerald-500 inline-block" />
              Allow
            </span>
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-sm bg-red-500 inline-block" />
              Deny
            </span>
          </div>
        </CardHeader>
        <CardContent>
          {(() => {
            const buckets = tsCur.data ?? [];
            if (buckets.length === 0) {
              return (
                <div className="py-12 text-center text-sm text-muted-foreground">
                  Belum ada rekaman keputusan pada rentang waktu ini.
                </div>
              );
            }

            const max = Math.max(...buckets.map((x) => x.total), 1);
            const chartHeight = 160;
            const chartWidth = 900;
            const colWidth = chartWidth / buckets.length;

            const hoveredBucket = hoveredIdx !== null ? buckets[hoveredIdx] : null;

            return (
              <div className="space-y-2">
                {/* Chart Box with Y-Axis */}
                <div className="relative flex">
                  {/* Y-Axis scale labels */}
                  <div className="flex flex-col justify-between text-[10px] font-mono tabular-nums text-muted-foreground pr-2 h-[160px] select-none text-right w-10">
                    <span>{fmtNum(max)}</span>
                    <span>{fmtNum(Math.round(max / 2))}</span>
                    <span>0</span>
                  </div>

                  {/* SVG Chart */}
                  <div className="relative flex-1">
                    <svg
                      viewBox={`0 0 ${chartWidth} ${chartHeight}`}
                      className="h-[160px] w-full overflow-visible"
                      preserveAspectRatio="none"
                      role="img"
                      aria-label="Grafik stacked keputusan allow dan deny"
                      onMouseLeave={() => setHoveredIdx(null)}
                    >
                      {/* Grid lines */}
                      <line x1="0" y1="0" x2={chartWidth} y2="0" stroke="currentColor" strokeOpacity="0.1" strokeDasharray="3 3" />
                      <line x1="0" y1={chartHeight / 2} x2={chartWidth} y2={chartHeight / 2} stroke="currentColor" strokeOpacity="0.1" strokeDasharray="3 3" />
                      <line x1="0" y1={chartHeight} x2={chartWidth} y2={chartHeight} stroke="currentColor" strokeOpacity="0.2" />

                      {/* Stacked bars */}
                      {buckets.map((b, i) => {
                        const totalH = (b.total / max) * (chartHeight - 10);
                        const denyH = (b.deny / max) * (chartHeight - 10);
                        const allowH = totalH - denyH;
                        const isHovered = hoveredIdx === i;

                        return (
                          <g
                            key={i}
                            transform={`translate(${i * colWidth}, 0)`}
                            className="cursor-pointer"
                            onMouseEnter={() => setHoveredIdx(i)}
                          >
                            {/* Hitbox */}
                            <rect
                              y="0"
                              width={colWidth}
                              height={chartHeight}
                              fill="transparent"
                            />
                            {/* Hover highlight background */}
                            {isHovered && (
                              <rect
                                y="0"
                                width={colWidth}
                                height={chartHeight}
                                fill="currentColor"
                                opacity="0.08"
                              />
                            )}
                            {/* Allow bar */}
                            <rect
                              y={chartHeight - denyH - allowH}
                              width={Math.max(colWidth * 0.75, 1)}
                              height={allowH}
                              fill="#10b981"
                              opacity={isHovered ? 1 : 0.8}
                              rx="1"
                            />
                            {/* Deny bar */}
                            <rect
                              y={chartHeight - denyH}
                              width={Math.max(colWidth * 0.75, 1)}
                              height={denyH}
                              fill="#ef4444"
                              opacity={isHovered ? 1 : 0.85}
                              rx="1"
                            />
                          </g>
                        );
                      })}
                    </svg>

                    {/* Tooltip Overlay */}
                    {hoveredBucket && hoveredIdx !== null && (
                      <div
                        className="pointer-events-none absolute z-20 rounded-md border bg-popover px-2.5 py-1.5 text-xs text-popover-foreground shadow-md font-mono"
                        style={{
                          left: `${Math.min(Math.max((hoveredIdx / buckets.length) * 100, 5), 85)}%`,
                          top: "-35px",
                        }}
                      >
                        <div className="font-semibold text-foreground text-[11px]">
                          {new Date(hoveredBucket.bucket_ns / 1_000_000).toLocaleTimeString("id-ID", {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}{" "}
                          WIB
                        </div>
                        <div className="flex items-center gap-2 mt-0.5 text-[10px]">
                          <span className="text-emerald-500 font-bold">
                            Allow: {hoveredBucket.allow}
                          </span>
                          <span>•</span>
                          <span className="text-destructive font-bold">
                            Deny: {hoveredBucket.deny}
                          </span>
                          <span>•</span>
                          <span>
                            Total: {hoveredBucket.total}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* X-Axis Time Ticks */}
                <div className="flex justify-between pl-10 text-[10px] font-mono tabular-nums text-muted-foreground pt-1">
                  {(() => {
                    const tickCount = 5;
                    const ticks = [];
                    for (let i = 0; i < tickCount; i++) {
                      const idx = Math.floor((i / (tickCount - 1)) * (buckets.length - 1));
                      const b = buckets[idx];
                      if (b) {
                        const date = new Date(b.bucket_ns / 1_000_000);
                        const label =
                          selectedWin.hours > 24
                            ? `${date.getDate()} ${date.toLocaleDateString("id-ID", { month: "short" })} ${date.getHours()}:00`
                            : date.toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" });
                        ticks.push(
                          <span key={i}>
                            {label}
                          </span>,
                        );
                      }
                    }
                    return ticks;
                  })()}
                </div>
              </div>
            );
          })()}
        </CardContent>
      </Card>

      {/* 4. Top Triggered Rules 24h & Top Offenders */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Top 5 Triggered Rules */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-sm font-semibold">
                Top 5 Aturan Pemicu Penolakan (24h)
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                Klik aturan untuk membuka filter di catatan keputusan
              </p>
            </div>
            <ShieldAlert className="size-4 text-destructive" />
          </CardHeader>
          <CardContent>
            {topRules.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted-foreground">
                Tidak ada penolakan kebijakan dalam 24 jam terakhir.
              </div>
            ) : (
              <div className="space-y-2">
                {topRules.map((r) => (
                  <Link
                    key={r.rule_id}
                    href={`/decisions?rule_id=${encodeURIComponent(r.rule_id)}`}
                    className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 transition-colors group"
                  >
                    <div className="min-w-0 pr-2">
                      <div className="truncate font-mono text-xs font-medium text-foreground group-hover:text-primary">
                        {r.rule_id}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        {r.share}% dari seluruh penolakan
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Badge variant="outline" className="font-mono text-xs bg-destructive/10 text-destructive border-destructive/20">
                        {r.count} deny
                      </Badge>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Top Offenders */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-sm font-semibold">
                Top Agen Pelanggar (24h)
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                Agen dengan frekuensi dan rasio penolakan tertinggi
              </p>
            </div>
            <Activity className="size-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            {topOffenders.length === 0 ? (
              <div className="py-8 text-center text-xs text-muted-foreground">
                Seluruh agen beroperasi tanpa penolakan (0 pelanggaran).
              </div>
            ) : (
              <div className="space-y-2">
                {topOffenders.map((off) => (
                  <Link
                    key={off.key_id}
                    href={`/decisions?key_id=${encodeURIComponent(off.key_id)}`}
                    className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 transition-colors group"
                  >
                    <div className="min-w-0 pr-2">
                      <div className="truncate font-mono text-xs font-semibold text-foreground group-hover:text-primary">
                        {off.key_id}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        Rasio penolakan: {off.ratio}% ({off.deny} dari {off.total} panggilan)
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <Badge
                        variant="outline"
                        className={`font-mono text-xs ${
                          off.ratio > 50
                            ? "bg-destructive/15 text-destructive border-destructive/30"
                            : "bg-amber-500/15 text-amber-500 border-amber-500/30"
                        }`}
                      >
                        {off.deny} penolakan
                      </Badge>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
