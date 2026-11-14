"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useBreaches, useData, usePutData } from "@/lib/queries";
import { dedupIncidents, getSeverityBadge, isBreach, type Severity } from "@/lib/severity";
import type { AuditEvent } from "@/lib/schema";
import {
  AlertCircle,
  AlertOctagon,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Flame,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  Skull,
} from "lucide-react";

export default function BreachCenterPage() {
  const [live, setLive] = useState(false); // Default OFF (Snapshot Frozen) per Opus anti-pattern
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [stageFilter, setStageFilter] = useState<string>("all");
  const [rulePrefixFilter, setRulePrefixFilter] = useState<string>("all");
  const [searchKeyId, setSearchKeyId] = useState("");
  const [timeWindow, setTimeWindow] = useState("24h");
  const [expandedIncidents, setExpandedIncidents] = useState<Record<string, boolean>>({});
  const [liveEvents, setLiveEvents] = useState<AuditEvent[]>([]);

  const { data: configData } = useData();
  const putDataMutation = usePutData();

  // Query parameters for the engine
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

  const { data: breachData, isPending, isError, error, refetch } = useBreaches(queryParams);

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

  // Deduplicate into incidents grouped by (key_id, rule_id, day)
  const incidents = useMemo(() => {
    return dedupIncidents(combinedEvents);
  }, [combinedEvents]);

  // Client-side search / filter on deduped incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (severityFilter !== "all" && inc.severity.toLowerCase() !== severityFilter.toLowerCase()) {
        return false;
      }
      if (searchKeyId.trim() && !inc.key_id.toLowerCase().includes(searchKeyId.toLowerCase())) {
        return false;
      }
      if (rulePrefixFilter !== "all" && !inc.rule_id.startsWith(rulePrefixFilter)) {
        return false;
      }
      if (stageFilter !== "all" && inc.stages.length > 0 && !inc.stages.includes(stageFilter)) {
        return false;
      }
      return true;
    });
  }, [incidents, severityFilter, searchKeyId, rulePrefixFilter, stageFilter]);

  const toggleExpand = (id: string) => {
    setExpandedIncidents((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // 1-Click Kill Agent
  const handleKillAgent = async (keyId: string) => {
    if (!configData) return;
    const next = structuredClone(configData.data);
    if (!next.config.kill_switch) {
      next.config.kill_switch = { keys: {} };
    }
    if (!next.config.kill_switch.keys) {
      next.config.kill_switch.keys = {};
    }
    const currentlyKilled = !!next.config.kill_switch.keys[keyId];
    next.config.kill_switch.keys[keyId] = !currentlyKilled;
    try {
      await putDataMutation.mutateAsync(next);
      refetch();
    } catch {
      // error handled by mutation
    }
  };

  if (isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="size-4" />
        <AlertTitle>Gagal memuat Breach Center</AlertTitle>
        <AlertDescription>{error.message}</AlertDescription>
      </Alert>
    );
  }

  const summary = breachData.summary;
  const buckets = breachData.buckets ?? [];
  const topOffenders = breachData.top_offenders ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Breach Center"
        description="Pusat pemantauan insiden keamanan dan pelanggaran aturan kritis (CRITICAL & HIGH)."
      >
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-xs font-medium cursor-pointer text-muted-foreground select-none">
            <Radio
              className={`size-3.5 ${
                live ? "text-emerald-500 animate-pulse" : "text-muted-foreground"
              }`}
            />
            {live ? "Live Streaming" : "Snapshot Frozen"}
            <Switch checked={live} onCheckedChange={setLive} />
          </label>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="text-xs">
            <RefreshCw className="mr-1.5 size-3.5" />
            Refresh
          </Button>
        </div>
      </PageHeader>

      {/* Top 3 KPI Columns */}
      <div className="grid gap-4 md:grid-cols-3">
        {/* Col 1: Severity Summary */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs flex items-center justify-between">
              <span>Severity Breakdown</span>
              <Select value={timeWindow} onValueChange={setTimeWindow}>
                <SelectTrigger className="w-20 h-6 text-[11px] font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1h">1h</SelectItem>
                  <SelectItem value="24h">24h</SelectItem>
                  <SelectItem value="7d">7d</SelectItem>
                </SelectContent>
              </Select>
            </CardDescription>
            <CardTitle className="text-2xl font-bold flex items-baseline gap-2">
              <span className="tabular-nums font-mono text-destructive">
                {summary.critical + summary.high}
              </span>
              <span className="text-xs font-normal text-muted-foreground">total breaches</span>
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
              <span>MEDIUM (Warning / Info)</span>
              <span className="tabular-nums font-mono">{summary.medium}</span>
            </div>
          </CardContent>
        </Card>

        {/* Col 2: Sparkline Trend */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs">Insiden Trend ({timeWindow})</CardDescription>
            <CardTitle className="text-sm font-medium">Distribusi Waktu</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {buckets.length === 0 ? (
              <div className="h-20 flex items-center justify-center text-xs text-muted-foreground">
                Tidak ada data bucket
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
                        title={`${new Date(b.bucket_ns / 1000000).toLocaleTimeString("id-ID", {
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

        {/* Col 3: Top Offenders + 1-Click Kill */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs">Top Pelanggar Aturan</CardDescription>
            <CardTitle className="text-sm font-medium">Top Offenders</CardTitle>
          </CardHeader>
          <CardContent className="pt-1">
            {topOffenders.length === 0 ? (
              <div className="h-20 flex items-center justify-center text-xs text-muted-foreground">
                Bersih — tidak ada pelanggar security
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
                            href={`/agents/${off.key_id}`}
                            className="hover:underline truncate text-foreground"
                          >
                            {off.key_id}
                          </Link>
                          {isKilled && (
                            <Badge variant="destructive" className="text-[9px] py-0 px-1">
                              KILLED
                            </Badge>
                          )}
                        </div>
                        <div className="text-[10px] text-muted-foreground truncate">
                          {off.top_rule_id} •{" "}
                          <span className="font-mono tabular-nums text-destructive font-semibold">
                            {off.count} breaches
                          </span>
                        </div>
                      </div>
                      <Button
                        variant={isKilled ? "outline" : "destructive"}
                        size="sm"
                        disabled={putDataMutation.isPending}
                        onClick={() => handleKillAgent(off.key_id)}
                        className="h-6 text-[10px] px-2 font-mono shrink-0"
                      >
                        {isKilled ? (
                          "Restore"
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

      {/* Incident Table with Filters */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {/* Severity Filter */}
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
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
            <Select value={stageFilter} onValueChange={setStageFilter}>
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
            <Select value={rulePrefixFilter} onValueChange={setRulePrefixFilter}>
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
              <Search className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
              <Input
                placeholder="Cari key_id…"
                value={searchKeyId}
                onChange={(e) => setSearchKeyId(e.target.value)}
                className="pl-8 h-8 text-xs"
              />
            </div>
          </div>

          <span className="text-xs text-muted-foreground tabular-nums">
            Menampilkan {filteredIncidents.length} incident terdedup ({combinedEvents.length} raw events)
          </span>
        </div>

        {/* Incidents Table */}
        <div className="rounded-md border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead className="w-24">Severity</TableHead>
                <TableHead className="w-56">Rule ID</TableHead>
                <TableHead className="w-40">Agent Key ID</TableHead>
                <TableHead className="w-24 text-center">Incidents</TableHead>
                <TableHead>Reason / Details</TableHead>
                <TableHead className="w-36 text-right">Last Seen</TableHead>
                <TableHead className="w-24 text-right">Aksi</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredIncidents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="h-32 text-center text-xs text-muted-foreground">
                    <ShieldAlert className="size-8 mx-auto text-emerald-500 mb-2" />
                    Tidak ada security breach terdeteksi untuk filter saat ini.
                  </TableCell>
                </TableRow>
              ) : (
                filteredIncidents.map((inc) => {
                  const isExpanded = !!expandedIncidents[inc.id];
                  const badge = getSeverityBadge(inc.severity as Severity);
                  const sample = inc.sample_event as AuditEvent;
                  return (
                    <>
                      <TableRow
                        key={inc.id}
                        className="hover:bg-muted/50 cursor-pointer"
                        onClick={() => toggleExpand(inc.id)}
                      >
                        <TableCell className="p-2 text-center">
                          {isExpanded ? (
                            <ChevronDown className="size-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="size-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={`text-[10px] ${badge.badgeClass}`}>
                            {badge.label}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs font-semibold text-foreground">
                          {inc.rule_id}
                        </TableCell>
                        <TableCell className="font-mono text-xs" onClick={(e) => e.stopPropagation()}>
                          <Link
                            href={`/agents/${inc.key_id}`}
                            className="text-primary hover:underline font-semibold"
                          >
                            {inc.key_id}
                          </Link>
                        </TableCell>
                        <TableCell className="text-center font-mono tabular-nums text-xs">
                          <Badge variant="secondary" className="font-mono text-xs font-semibold">
                            {inc.count}x
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground truncate max-w-xs">
                          {sample?.reason || sample?.subject || "—"}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                          {new Date(inc.last_seen).toLocaleTimeString("id-ID", {
                            hour: "2-digit",
                            minute: "2-digit",
                            second: "2-digit",
                          })}
                        </TableCell>
                        <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                          <Button variant="ghost" size="sm" asChild className="h-7 text-xs px-2">
                            <Link href={`/agents/${inc.key_id}`}>
                              <ExternalLink className="size-3 mr-1" />
                              Detail
                            </Link>
                          </Button>
                        </TableCell>
                      </TableRow>

                      {/* Expandable row: sample masked args and details */}
                      {isExpanded && (
                        <TableRow key={`${inc.id}-details`} className="bg-muted/20">
                          <TableCell colSpan={8} className="p-4 space-y-3">
                            <div className="grid gap-3 sm:grid-cols-2 text-xs">
                              <div>
                                <span className="text-muted-foreground block mb-1">Insiden Info:</span>
                                <div className="space-y-1 font-mono text-[11px] bg-background p-2.5 rounded border">
                                  <div>
                                    <span className="text-muted-foreground">Key ID:</span> {inc.key_id}
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Rule:</span> {inc.rule_id}
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">First Seen:</span>{" "}
                                    {new Date(inc.first_seen).toLocaleString("id-ID")}
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Last Seen:</span>{" "}
                                    {new Date(inc.last_seen).toLocaleString("id-ID")}
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Stages:</span>{" "}
                                    {inc.stages.join(", ") || "—"}
                                  </div>
                                </div>
                              </div>

                              <div>
                                <span className="text-muted-foreground block mb-1">
                                  Sample Masked Args / Payload:
                                </span>
                                <pre className="bg-background p-2.5 rounded border text-[11px] font-mono overflow-x-auto max-h-40">
                                  {sample?.args
                                    ? JSON.stringify(sample.args, null, 2)
                                    : "// Tidak ada args payload"}
                                </pre>
                              </div>
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
    </div>
  );
}
