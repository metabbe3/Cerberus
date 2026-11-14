"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  AlertOctagon,
  ChevronDown,
  ChevronRight,
  Download,
  Flame,
  Radio,
  Search,
  Skull,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { downloadCSV } from "@/lib/csv";
import { formatWibDateTime } from "@/components/timestamp";
import { InspectorDrawer } from "@/components/decisions/inspector-drawer";
import { PageHeader } from "@/components/page-header";
import { ActivitySubNav } from "@/components/sub-nav";
import { EmptyState } from "@/components/empty-state";
import { RefreshIndicator } from "@/components/refresh-indicator";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useBreaches, useData, usePutData } from "@/lib/queries";
import { getSeverity, getSeverityBadge, groupSecuritySignals, isBreach, type Severity } from "@/lib/severity";
import type { AuditEvent } from "@/lib/schema";

function BreachCenterContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Read URL query parameters
  const severityFilter = searchParams.get("severity") ?? "all";
  const stageFilter = searchParams.get("stage") ?? "all";
  const rulePrefixFilter = searchParams.get("rule_prefix") ?? "all";
  const searchKeyId = searchParams.get("key_id") ?? "";
  const timeWindow = searchParams.get("since") ?? "24h";

  const [live, setLive] = useState(false);
  const [expandedSignals, setExpandedSignals] = useState<Record<string, boolean>>({});
  const [liveEvents, setLiveEvents] = useState<AuditEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const { data: configData } = useData();
  const putDataMutation = usePutData();

  // Helper to sync filter updates to URL
  const updateFilter = (key: string, val: string) => {
    const p = new URLSearchParams(searchParams.toString());
    if (!val || val === "all") {
      p.delete(key);
    } else {
      p.set(key, val);
    }
    router.replace(`/breaches?${p.toString()}`);
  };

  const clearAllFilters = () => {
    router.replace("/breaches");
  };

  const hasActiveFilters =
    severityFilter !== "all" ||
    stageFilter !== "all" ||
    rulePrefixFilter !== "all" ||
    Boolean(searchKeyId) ||
    timeWindow !== "24h";

  // Query parameters for engine API
  const queryParams = useMemo(() => {
    const p = new URLSearchParams();
    p.set("since", timeWindow);
    if (stageFilter !== "all") p.set("stage", stageFilter);
    if (rulePrefixFilter !== "all") p.set("rule_prefix", rulePrefixFilter);
    if (severityFilter !== "all") p.set("severity", severityFilter);
    if (searchKeyId.trim()) p.set("key_id", searchKeyId.trim());
    p.set("limit", "500");
    return p;
  }, [timeWindow, stageFilter, rulePrefixFilter, severityFilter, searchKeyId]);

  const { data: breachData, isPending, refetch } = useBreaches(queryParams);

  // Live SSE listener when live toggle is ON
  useEffect(() => {
    if (!live) return;
    const es = new EventSource("/api/events");
    es.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data) as AuditEvent;
        if (ev && isBreach(ev.rule_id, ev.decision)) {
          setLiveEvents((prev) => [ev, ...prev.slice(0, 99)]);
        }
      } catch {
        // ignore parse error
      }
    };
    return () => {
      es.close();
    };
  }, [live]);

  // Combine fetched events with live streamed events
  const combinedEvents = useMemo(() => {
    const initial = breachData?.events ?? [];
    if (!live || liveEvents.length === 0) return initial;
    const seen = new Set<number>();
    const res: AuditEvent[] = [];
    for (const ev of [...liveEvents, ...initial]) {
      if (!seen.has(ev.id)) {
        seen.add(ev.id);
        res.push(ev);
      }
    }
    return res;
  }, [breachData?.events, liveEvents, live]);

  // Deduplicate into security signals using 15m fingerprint window: hash(rule_id+key_id+normalized_reason)
  const signals = useMemo(() => {
    return groupSecuritySignals(combinedEvents, 15);
  }, [combinedEvents]);

  // Client-side search / filter on signals
  const filteredSignals = useMemo(() => {
    return signals.filter((sig) => {
      if (severityFilter !== "all" && sig.severity.toLowerCase() !== severityFilter.toLowerCase()) {
        return false;
      }
      if (searchKeyId.trim() && !sig.key_id.toLowerCase().includes(searchKeyId.toLowerCase())) {
        return false;
      }
      if (rulePrefixFilter !== "all" && !sig.rule_id.startsWith(rulePrefixFilter)) {
        return false;
      }
      if (stageFilter !== "all" && sig.stages.length > 0 && !sig.stages.includes(stageFilter)) {
        return false;
      }
      return true;
    });
  }, [signals, severityFilter, searchKeyId, rulePrefixFilter, stageFilter]);

  const summary = breachData?.summary ?? { total: 0, critical: 0, high: 0, medium: 0 };
  const topOffenders = breachData?.top_offenders ?? [];
  const buckets = breachData?.buckets ?? [];

  const [killTarget, setKillTarget] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedSignals((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleKillAgent = (keyId: string) => {
    if (!configData?.data) return;
    const current = configData.data;
    const isKilled = !!current.config?.kill_switch?.keys?.[keyId];
    const next = structuredClone(current);
    if (!next.config) next.config = {};
    if (!next.config.kill_switch) next.config.kill_switch = {};
    if (!next.config.kill_switch.keys) next.config.kill_switch.keys = {};

    if (isKilled) {
      delete next.config.kill_switch.keys[keyId];
    } else {
      next.config.kill_switch.keys[keyId] = true;
    }
    putDataMutation.mutate(next);
  };

  const inspectEvent = (ev: AuditEvent) => {
    setSelectedEvent(ev);
    setDrawerOpen(true);
  };

  const exportBreachesCSV = () => {
    if (combinedEvents.length === 0) return;
    const headers = [
      "ID",
      "Timestamp (UTC)",
      "Timestamp (WIB)",
      "Severity",
      "Key ID",
      "Stage",
      "Rule ID",
      "Reason",
      "Subject",
      "Latency (µs)",
    ];
    const rows = combinedEvents.map((ev) => [
      ev.id,
      ev.time,
      formatWibDateTime(ev.time),
      getSeverity(ev.rule_id),
      ev.key_id,
      ev.stage,
      ev.rule_id,
      ev.reason,
      ev.subject,
      ev.latency_us ?? 0,
    ]);
    const dateStr = new Date().toISOString().slice(0, 10);
    downloadCSV(`cerberus-breaches-${dateStr}.csv`, headers, rows);
    toast.success(`Berhasil mengunduh ${combinedEvents.length} baris pelanggaran (CSV)`);
  };

  return (
    <div className="space-y-6">
      <ActivitySubNav />

      {/* Header */}
      <PageHeader
        title={
          <div className="flex items-center gap-2">
            <span>Breach Center</span>
            <Badge
              variant="outline"
              className={live ? "gap-1.5 border-emerald-500/40 text-emerald-500 text-xs font-mono" : "gap-1.5 text-xs font-mono"}
            >
              <Radio className={live ? "size-3 animate-pulse" : "size-3"} aria-hidden />
              {live ? "streaming live" : "snapshot beku"}
            </Badge>
          </div>
        }
        description="Pusat triase dan investigasi insiden keamanan: sinyal terdedup 15m, deteksi first-seen, dan respon cepat."
      >
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={exportBreachesCSV}
            className="h-8 gap-1.5 text-xs"
            disabled={combinedEvents.length === 0}
          >
            <Download className="size-3.5" />
            Ekspor CSV ({combinedEvents.length})
          </Button>
          <label className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
            Stream Otomatis <Switch checked={live} onCheckedChange={setLive} />
          </label>
          <RefreshIndicator
            autoIntervalSec={10}
            onRefresh={() => refetch()}
            isRefreshing={isPending}
          />
        </div>
      </PageHeader>

      {/* Overview 3-Tile Row */}
      <div className="grid gap-4 md:grid-cols-3">
        {/* Col 1: Severity Breakdown */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs flex items-center justify-between">
              <span>Distribusi Severity</span>
              <Select value={timeWindow} onValueChange={(val) => updateFilter("since", val)}>
                <SelectTrigger className="w-20 h-6 text-[11px] font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1h">1 Jam</SelectItem>
                  <SelectItem value="24h">24 Jam</SelectItem>
                  <SelectItem value="7d">7 Hari</SelectItem>
                </SelectContent>
              </Select>
            </CardDescription>
            <CardTitle className="text-2xl font-bold flex items-baseline gap-2">
              <span className="tabular-nums font-mono text-destructive">
                {summary.critical + summary.high}
              </span>
              <span className="text-xs font-normal text-muted-foreground">pelanggaran kritis/tinggi</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5 pt-1 text-xs">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-red-600 dark:text-red-400 font-medium">
                <AlertOctagon className="size-3.5" />
                CRITICAL
              </span>
              <span className="tabular-nums font-mono font-semibold text-red-600 dark:text-red-400">
                {summary.critical}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400 font-medium">
                <Flame className="size-3.5" />
                HIGH
              </span>
              <span className="tabular-nums font-mono font-semibold text-amber-600 dark:text-amber-400">
                {summary.high}
              </span>
            </div>
            <div className="flex items-center justify-between pt-1 border-t text-muted-foreground text-[11px]">
              <span>MEDIUM (Peringatan Operasional)</span>
              <span className="tabular-nums font-mono">{summary.medium}</span>
            </div>
          </CardContent>
        </Card>

        {/* Col 2: Sparkline Trend */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs">Tren Insiden ({timeWindow})</CardDescription>
            <CardTitle className="text-sm font-medium">Distribusi Frekuensi Waktu</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {buckets.length === 0 ? (
              <div className="h-20 flex items-center justify-center text-xs text-muted-foreground">
                Tidak ada data insiden pada rentang ini
              </div>
            ) : (
              <div className="space-y-2">
                <div className="h-16 flex items-end gap-1 px-1">
                  {buckets.map((b, i) => {
                    const total = b.critical + b.high;
                    const maxB = Math.max(...buckets.map((x) => x.critical + x.high), 1);
                    const heightPct = Math.max(Math.round((total / maxB) * 100), total > 0 ? 15 : 4);
                    const isCrit = b.critical > 0;
                    return (
                      <div
                        key={i}
                        className="flex-1 flex flex-col justify-end group relative"
                        title={`${new Date(b.bucket_ns / 1_000_000).toLocaleTimeString("id-ID", {
                          hour: "2-digit",
                          minute: "2-digit",
                        })}: ${b.critical} critical, ${b.high} high`}
                      >
                        <div
                          style={{ height: `${heightPct}%` }}
                          className={`w-full rounded-t transition-all ${
                            total === 0
                              ? "bg-muted/40"
                              : isCrit
                                ? "bg-red-500 hover:bg-red-600"
                                : "bg-amber-500 hover:bg-amber-600"
                          }`}
                        />
                      </div>
                    );
                  })}
                </div>
                <div className="flex justify-between text-[10px] font-mono text-muted-foreground px-1">
                  <span>{timeWindow} lalu</span>
                  <span>sekarang</span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Col 3: Top Offenders */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs">Top Agen Pelanggar</CardDescription>
            <CardTitle className="text-sm font-medium">Pelanggar Terbanyak</CardTitle>
          </CardHeader>
          <CardContent className="pt-1">
            {topOffenders.length === 0 ? (
              <div className="h-20 flex items-center justify-center text-xs text-muted-foreground">
                Bersih — tidak ada pelanggaran keamanan
              </div>
            ) : (
              <div className="space-y-2">
                {topOffenders.slice(0, 3).map((off) => {
                  const isKilled = !!configData?.data?.config?.kill_switch?.keys?.[off.key_id];
                  return (
                    <div
                      key={off.key_id}
                      className="flex items-center justify-between gap-2 p-1.5 rounded-md bg-muted/40 text-xs"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5 font-mono font-medium">
                          <Link
                            href={`/agents/${encodeURIComponent(off.key_id)}`}
                            className="hover:underline truncate text-foreground font-semibold"
                          >
                            {off.key_id}
                          </Link>
                          {isKilled && (
                            <Badge variant="destructive" className="text-[9px] py-0 px-1 font-mono">
                              KILLED
                            </Badge>
                          )}
                        </div>
                        <div className="text-[10px] text-muted-foreground truncate">
                          {off.top_rule_id} •{" "}
                          <span className="font-mono tabular-nums text-destructive font-semibold">
                            {off.count} pelanggaran
                          </span>
                        </div>
                      </div>
                      <Button
                        variant={isKilled ? "outline" : "destructive"}
                        size="sm"
                        disabled={putDataMutation.isPending}
                        onClick={() => {
                            if (isKilled) {
                              handleKillAgent(off.key_id);
                            } else {
                              setKillTarget(off.key_id);
                            }
                          }}
                        className="h-6 text-[10px] px-2 font-mono shrink-0"
                      >
                        {isKilled ? (
                          "Pulihkan"
                        ) : (
                          <>
                            <Skull className="mr-1 size-3" />
                            Kill
                          </>
                        )}
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Incident Signals Section */}
      <div className="space-y-4">
        {/* Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 bg-muted/20 p-2.5 rounded-lg border">
          <div className="flex flex-wrap items-center gap-2">
            {/* Severity Filter */}
            <Select value={severityFilter} onValueChange={(val) => updateFilter("severity", val)}>
              <SelectTrigger className="w-32 h-8 text-xs">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Semua Severity</SelectItem>
                <SelectItem value="critical">CRITICAL</SelectItem>
                <SelectItem value="high">HIGH</SelectItem>
              </SelectContent>
            </Select>

            {/* Stage Filter */}
            <Select value={stageFilter} onValueChange={(val) => updateFilter("stage", val)}>
              <SelectTrigger className="w-32 h-8 text-xs">
                <SelectValue placeholder="Stage" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Semua Stage</SelectItem>
                <SelectItem value="tool">tool</SelectItem>
                <SelectItem value="llm">llm</SelectItem>
                <SelectItem value="http">http</SelectItem>
                <SelectItem value="docker">docker</SelectItem>
                <SelectItem value="ssh">ssh</SelectItem>
                <SelectItem value="db">db</SelectItem>
                <SelectItem value="k8s">k8s</SelectItem>
              </SelectContent>
            </Select>

            {/* Rule Family Filter */}
            <Select value={rulePrefixFilter} onValueChange={(val) => updateFilter("rule_prefix", val)}>
              <SelectTrigger className="w-36 h-8 text-xs">
                <SelectValue placeholder="Rule Family" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Semua Family</SelectItem>
                <SelectItem value="shield.">shield.*</SelectItem>
                <SelectItem value="k8s.">k8s.*</SelectItem>
                <SelectItem value="db.">db.*</SelectItem>
                <SelectItem value="docker.">docker.*</SelectItem>
                <SelectItem value="ssh.">ssh.*</SelectItem>
                <SelectItem value="shellguard.">shellguard.*</SelectItem>
                <SelectItem value="ai.">ai.*</SelectItem>
              </SelectContent>
            </Select>

            {/* Key ID Search */}
            <div className="relative w-48">
              <Search className="absolute left-2.5 top-2.5 size-3 text-muted-foreground" />
              <Input
                placeholder="Cari key_id…"
                value={searchKeyId}
                onChange={(e) => updateFilter("key_id", e.target.value)}
                className="pl-8 h-8 text-xs font-mono"
              />
            </div>

            {hasActiveFilters && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8 px-2 text-xs text-muted-foreground hover:text-foreground"
                onClick={clearAllFilters}
              >
                <X className="size-3.5 mr-1" />
                Reset Filter
              </Button>
            )}
          </div>

          <span className="text-xs text-muted-foreground tabular-nums font-mono">
            {filteredSignals.length} sinyal terdedup ({combinedEvents.length} raw events)
          </span>
        </div>

        {/* Signals Table with Dedup & Slide-over Inspector */}
        <div className="rounded-md border bg-card overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead className="w-24">Severity</TableHead>
                <TableHead className="w-56">Aturan (Rule ID)</TableHead>
                <TableHead className="w-40">Agen (Key ID)</TableHead>
                <TableHead className="w-24 text-center">Grup Sinyal</TableHead>
                <TableHead>Alasan / Detail</TableHead>
                <TableHead className="w-36 text-right">Rentang Waktu</TableHead>
                <TableHead className="w-24 text-right">Aksi</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredSignals.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="p-4">
                    {hasActiveFilters ? (
                      <EmptyState
                        type="filtered-out"
                        title="Tidak Ada Sinyal Pelanggaran yang Cocok"
                        hint="Tidak ada event pelanggaran yang cocok dengan filter yang aktif saat ini."
                        actionLabel="Reset Semua Filter"
                        onAction={clearAllFilters}
                      />
                    ) : (
                      <EmptyState
                        type="clean-security"
                        title="Sistem Aman — Nol Pelanggaran Terdeteksi"
                        hint="Seluruh evaluasi kebijakan mematuhi aturan keamanan gateway tanpa pelanggaran keamanan dalam periode ini."
                      />
                    )}
                  </TableCell>
                </TableRow>
              ) : (
                filteredSignals.map((sig) => {
                  const isExpanded = !!expandedSignals[sig.id];
                  const badge = getSeverityBadge(sig.severity as Severity);
                  const sample = sig.sample_event as AuditEvent;
                  return (
                    <>
                      <TableRow
                        key={sig.id}
                        className="hover:bg-muted/50 cursor-pointer"
                        onClick={() => toggleExpand(sig.id)}
                      >
                        <TableCell className="p-2 text-center">
                          {isExpanded ? (
                            <ChevronDown className="size-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="size-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <Badge variant="outline" className={`text-[10px] ${badge.badgeClass}`}>
                              {badge.label}
                            </Badge>
                            {sig.is_new && (
                              <Badge
                                variant="outline"
                                className="bg-red-500/15 text-red-500 border-red-500/30 text-[9px] font-bold px-1 py-0 h-4"
                                title="Sinyal baru: kombinasi rule+key ini tidak pernah terlihat dalam 7 hari terakhir"
                              >
                                BARU
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs font-semibold text-foreground">
                          {sig.rule_id}
                        </TableCell>
                        <TableCell className="font-mono text-xs" onClick={(e) => e.stopPropagation()}>
                          <Link
                            href={`/agents/${encodeURIComponent(sig.key_id)}`}
                            className="text-primary hover:underline font-semibold"
                          >
                            {sig.key_id}
                          </Link>
                        </TableCell>
                        <TableCell className="text-center font-mono tabular-nums text-xs">
                          <Badge
                            variant="secondary"
                            className="font-mono text-xs font-bold bg-muted text-foreground"
                          >
                            ×{sig.count}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground truncate max-w-xs font-mono">
                          {sig.normalized_reason || sample?.reason || sample?.subject || "—"}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                          <div>
                            {new Date(sig.last_seen).toLocaleTimeString("id-ID", {
                              hour: "2-digit",
                              minute: "2-digit",
                            })} WIB
                          </div>
                          {sig.count > 1 && (
                            <div className="text-[10px] text-muted-foreground/70">
                              sejak {new Date(sig.first_seen).toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" })}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs px-2"
                            onClick={() => inspectEvent(sample)}
                          >
                            Inspeksi
                          </Button>
                        </TableCell>
                      </TableRow>

                      {/* Expandable row: list of events within the 15m signal window */}
                      {isExpanded && (
                        <TableRow key={`${sig.id}-details`} className="bg-muted/15 border-b">
                          <TableCell colSpan={8} className="p-4 space-y-3">
                            <div className="flex items-center justify-between text-xs font-medium text-muted-foreground border-b pb-2">
                              <span>Daftar {sig.events.length} Kejadian dalam Jendela Sinyal 15 Menit:</span>
                              <span>Klik salah satu untuk inspeksi slide-over</span>
                            </div>

                            <div className="space-y-1.5 max-h-60 overflow-y-auto">
                              {sig.events.map((ev: AuditEvent) => (
                                <div
                                  key={ev.id}
                                  className="flex items-center justify-between gap-3 p-2 rounded border bg-background hover:bg-muted/40 cursor-pointer text-xs font-mono"
                                  onClick={() => inspectEvent(ev)}
                                >
                                  <div className="flex items-center gap-2">
                                    <span className="text-muted-foreground">#{ev.id}</span>
                                    <Badge variant="outline" className="text-[10px] uppercase">
                                      {ev.stage}
                                    </Badge>
                                    <span className="font-semibold text-foreground">{ev.subject}</span>
                                    <span className="text-muted-foreground truncate max-w-md">
                                      {ev.reason || "—"}
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-3 shrink-0 text-muted-foreground tabular-nums">
                                    <span>
                                      {ev.latency_us ? `${ev.latency_us} µs` : "—"}
                                    </span>
                                    <span>
                                      {new Date(ev.time).toLocaleTimeString("id-ID", {
                                        hour: "2-digit",
                                        minute: "2-digit",
                                        second: "2-digit",
                                      })} WIB
                                    </span>
                                    <Button size="sm" variant="outline" className="h-6 text-[10px] px-1.5">
                                      Inspeksi
                                    </Button>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Slide-over Inspector Drawer */}
      <InspectorDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        event={selectedEvent}
      />
              {/* Konfirmasi Kill agen — memutus SEMUA trafik key ini di gerbang */}
        <AlertDialog
          open={!!killTarget}
          onOpenChange={(o) => {
            if (!o) setKillTarget(null);
          }}
        >
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                Kill agen <span className="font-mono">{killTarget ?? ""}</span>?
              </AlertDialogTitle>
              <AlertDialogDescription>
                Semua request key ini ditolak gerbang seketika (fail-closed).
                Pulihkan kapan saja dari tombol Pulihkan.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Batal</AlertDialogCancel>
              <AlertDialogAction
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                onClick={() => {
                  if (killTarget) handleKillAgent(killTarget);
                  setKillTarget(null);
                }}
              >
                Ya, Kill
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
    </div>
  );
}

export default function BreachCenterPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-xs text-muted-foreground">Memuat data breach center…
</div>}>
      <BreachCenterContent />
    </Suspense>
  );
}
