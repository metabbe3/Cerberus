"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { InspectorDrawer } from "@/components/decisions/inspector-drawer";
import { TraceDialog } from "@/components/decisions/trace-dialog";
import { EmptyState } from "@/components/empty-state";
import {
  useAudit,
  useBreaches,
  useData,
  usePutData,
  useRotateKey,
} from "@/lib/queries";
import { getSeverityBadge, type Severity } from "@/lib/severity";
import type { Agent, AuditEvent, Team } from "@/lib/schema";
import {
  AlertCircle,
  AlertOctagon,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Edit,
  Key,
  Search,
  Shield,
  ShieldCheck,
  Skull,
  Terminal,
} from "lucide-react";

export default function AgentObservabilityPage() {
  const { keyId } = useParams<{ keyId: string }>();
  const router = useRouter();

  const [timeWindow, setTimeWindow] = useState<"24h" | "7d">("24h");
  const [filterText, setFilterText] = useState("");
  const [selectedRowIndex, setSelectedRowIndex] = useState<number>(0);
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});
  const [traceEvent, setTraceEvent] = useState<AuditEvent | null>(null);
  const [traceOpen, setTraceOpen] = useState(false);
  const [inspectEvent, setInspectEvent] = useState<AuditEvent | null>(null);
  const [rotateDialogOpen, setRotateDialogOpen] = useState(false);
  const [rotateSuffix, setRotateSuffix] = useState("-v2");
  const [revokeOld, setRevokeOld] = useState(false);
  const [rotateResult, setRotateResult] = useState<{ newKeyId: string } | null>(null);

  const searchInputRef = useRef<HTMLInputElement>(null);

  // Queries
  const { data: configData, isPending: configPending, isError: configError, error: configErr } = useData();
  const putDataMutation = usePutData();
  const rotateKeyMutation = useRotateKey();

  // Breaches in window
  const breachParams = useMemo(() => {
    const p = new URLSearchParams();
    p.set("key_id", keyId);
    p.set("since", timeWindow);
    p.set("limit", "100");
    return p;
  }, [keyId, timeWindow]);
  const { data: breachData } = useBreaches(breachParams);

  // Recent timeline events
  const auditParams = useMemo(() => {
    const p = new URLSearchParams();
    p.set("key_id", keyId);
    p.set("limit", "100");
    return p;
  }, [keyId]);
  const { data: auditEvents, isPending: auditPending } = useAudit(auditParams);

  // Timeseries sparkline
  const [timeseriesBuckets, setTimeseriesBuckets] = useState<
    Array<{ bucket_ns: number; allow: number; deny: number; total: number }>
  >([]);

  useEffect(() => {
    const since =
      timeWindow === "24h"
        ? new Date(Date.now() - 24 * 3600 * 1000).toISOString()
        : new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();

    fetch(`/api/timeseries?key_id=${encodeURIComponent(keyId)}&since=${encodeURIComponent(since)}&buckets=24`)
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        if (Array.isArray(data)) setTimeseriesBuckets(data);
      })
      .catch(() => setTimeseriesBuckets([]));
  }, [keyId, timeWindow]);

  const agent: Agent | undefined = configData?.data?.agents?.[keyId];
  const team: Team | undefined = agent?.team_id ? configData?.data?.teams?.[agent.team_id] : undefined;

  const isKilled = !!configData?.data?.config?.kill_switch?.keys?.[keyId];

  // Effective Policy calculation (Argon spec)
  const effectivePolicy = useMemo(() => {
    if (!agent) return null;

    // Tightest budget: min of agent and team budget
    let effectiveBudget: number | undefined = agent.budget_limit;
    if (team?.budget_limit != null) {
      if (effectiveBudget == null) {
        effectiveBudget = team.budget_limit;
      } else {
        effectiveBudget = Math.min(effectiveBudget, team.budget_limit);
      }
    }

    // Union allowlist
    const allowedToolsSet = new Set<string>([
      ...(agent.allowed_tools ?? []),
      ...(team?.allowed_tools ?? []),
    ]);

    // Restricted wins (union of restricted tools)
    const restrictedToolsSet = new Set<string>([
      ...(agent.restricted_tools ?? []),
    ]);

    // Allowed models
    const allowedModelsSet = new Set<string>([
      ...(agent.allowed_models ?? []),
      ...(team?.allowed_models ?? []),
    ]);

    return {
      budget_limit: effectiveBudget,
      allowed_tools: Array.from(allowedToolsSet),
      restricted_tools: Array.from(restrictedToolsSet),
      allowed_models: Array.from(allowedModelsSet),
      risk_tier: agent.risk_tier ?? "standard",
      prod_access: !!agent.prod_access,
      rate_limit: agent.rate_limit,
    };
  }, [agent, team]);

  // Filtered timeline events
  const filteredEvents = useMemo(() => {
    if (!auditEvents) return [];
    if (!filterText.trim()) return auditEvents;
    const q = filterText.toLowerCase();
    return auditEvents.filter(
      (ev) =>
        ev.stage.toLowerCase().includes(q) ||
        ev.decision.toLowerCase().includes(q) ||
        ev.rule_id.toLowerCase().includes(q) ||
        ev.subject.toLowerCase().includes(q) ||
        ev.reason.toLowerCase().includes(q),
    );
  }, [auditEvents, filterText]);

  const handleToggleKill = async () => {
    if (!configData) return;
    const next = structuredClone(configData.data);
    if (!next.config.kill_switch) {
      next.config.kill_switch = { keys: {} };
    }
    if (!next.config.kill_switch.keys) {
      next.config.kill_switch.keys = {};
    }
    next.config.kill_switch.keys[keyId] = !isKilled;
    try {
      await putDataMutation.mutateAsync(next);
    } catch {
      // handled
    }
  };

  const killRef = useRef(handleToggleKill);
  killRef.current = handleToggleKill;

  // Keyboard navigation shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in an input
      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA"
      ) {
        if (e.key === "Escape") {
          (document.activeElement as HTMLElement).blur();
        }
        return;
      }

      if (e.key === "j") {
        e.preventDefault();
        setSelectedRowIndex((prev) => Math.min(prev + 1, Math.max(filteredEvents.length - 1, 0)));
      } else if (e.key === "k") {
        e.preventDefault();
        setSelectedRowIndex((prev) => Math.max(prev - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const ev = filteredEvents[selectedRowIndex];
        if (ev) {
          setExpandedRows((prev) => ({ ...prev, [ev.id]: !prev[ev.id] }));
        }
      } else if (e.key === "t") {
        e.preventDefault();
        const ev = filteredEvents[selectedRowIndex];
        if (ev) {
          setTraceEvent(ev);
          setTraceOpen(true);
        }
      } else if (e.key === "x") {
        e.preventDefault();
        killRef.current();
      } else if (e.key === "/") {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredEvents, selectedRowIndex]);

  const handleRotateKeySubmit = async () => {
    try {
      const res = await rotateKeyMutation.mutateAsync({
        keyId,
        suffix: rotateSuffix,
        revoke_old: revokeOld,
      });
      setRotateResult({ newKeyId: res.new_key_id });
    } catch {
      // handled
    }
  };

  if (configPending || auditPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-80" />
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (configError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="size-4" />
        <AlertTitle>Engine unreachable</AlertTitle>
        <AlertDescription>{configErr.message}</AlertDescription>
      </Alert>
    );
  }

  if (!agent) {
    return (
      <EmptyState
        title="Unregistered key — governed by config flags"
        hint={`No agent record for ${keyId}. Register it to give it its own policy.`}
      />
    );
  }

  const breaches = breachData?.events ?? [];
  const breachCount = breaches.length;
  const totalEventsCount = auditEvents?.length ?? 0;

  return (
    <div className="space-y-6">
      {/* 1. Header (Argon Design §1) */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight">
              {agent.name ?? keyId}
            </h1>
            {agent.team_id && (
              <Badge variant="outline" className="font-mono text-xs">
                {agent.team_id}
              </Badge>
            )}
            {isKilled ? (
              <Badge variant="destructive" className="font-mono text-xs font-bold py-0.5 animate-pulse">
                <Skull className="mr-1 size-3 inline" />
                KILL SWITCH ACTIVE
              </Badge>
            ) : (
              <Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-xs">
                ACTIVE
              </Badge>
            )}
            {breachCount === 0 ? (
              <Badge variant="outline" className="bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-xs font-semibold">
                <ShieldCheck className="mr-1 size-3 inline" />
                0 Breaches ({timeWindow})
              </Badge>
            ) : (
              <Badge variant="destructive" className="font-mono text-xs font-bold py-0.5">
                <AlertOctagon className="mr-1 size-3 inline" />
                {breachCount} Breaches ({timeWindow})
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground mt-1">
            <span className="font-mono">{keyId}</span>
            <span>•</span>
            <span>{agent.description ?? "Tidak ada deskripsi"}</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant={isKilled ? "outline" : "destructive"}
            size="sm"
            onClick={handleToggleKill}
            disabled={putDataMutation.isPending}
            className="text-xs"
            title="Shortkey: x"
          >
            {isKilled ? (
              <>
                <ShieldCheck className="mr-1.5 size-3.5" />
                Restore Agent
              </>
            ) : (
              <>
                <Skull className="mr-1.5 size-3.5" />
                Kill Switch
              </>
            )}
          </Button>

          <Button
            variant="outline"
            size="sm"
            asChild
            className="text-xs"
          >
            <Link href={`/agents/${keyId}/edit`}>
              <Edit className="mr-1.5 size-3.5" />
              Edit Policy
            </Link>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setRotateResult(null);
              setRotateDialogOpen(true);
            }}
            className="text-xs"
          >
            <Key className="mr-1.5 size-3.5" />
            Rotate Key
          </Button>
        </div>
      </div>

      {/* 2. Effective Policy Card & Sparkline Grid */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Effective Policy Card (Argon spec) */}
        <Card className="lg:col-span-2 border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Shield className="size-4 text-primary" />
                Effective Policy (Merged Agent ∪ Team)
              </span>
              <Badge variant="secondary" className="text-[10px] font-mono">
                tightest wins
              </Badge>
            </CardTitle>
            <CardDescription className="text-xs">
              Kebijakan efektif hasil konsolidasi batasan spesifik agen dan tim.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 pt-0 text-xs">
            <div className="grid gap-3 sm:grid-cols-3 bg-muted/30 p-3 rounded-md border">
              <div>
                <span className="text-muted-foreground block text-[11px]">Budget Limit</span>
                <span className="font-mono tabular-nums font-semibold text-sm">
                  {effectivePolicy?.budget_limit != null
                    ? `$${effectivePolicy.budget_limit.toLocaleString()}`
                    : "Unset (Unlimited)"}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground block text-[11px]">Risk Tier</span>
                <Badge
                  variant={effectivePolicy?.risk_tier === "high" ? "destructive" : "secondary"}
                  className="mt-0.5 text-[10px]"
                >
                  {effectivePolicy?.risk_tier}
                </Badge>
              </div>
              <div>
                <span className="text-muted-foreground block text-[11px]">Prod Access</span>
                <span className="font-semibold text-xs mt-0.5 block">
                  {effectivePolicy?.prod_access ? (
                    <span className="text-red-500 font-bold">GRANTED</span>
                  ) : (
                    <span className="text-muted-foreground">DENIED</span>
                  )}
                </span>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <span className="text-muted-foreground font-medium block mb-1">
                  Allowed Tools (Union):
                </span>
                <div className="flex flex-wrap gap-1">
                  {effectivePolicy?.allowed_tools.length ? (
                    effectivePolicy.allowed_tools.map((t) => (
                      <Badge key={t} variant="outline" className="font-mono text-[10px] bg-background">
                        {t}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-muted-foreground italic">Semua tool diizinkan (atau unset)</span>
                  )}
                </div>
              </div>

              <div>
                <span className="text-muted-foreground font-medium block mb-1">
                  Restricted Tools (Wins):
                </span>
                <div className="flex flex-wrap gap-1">
                  {effectivePolicy?.restricted_tools.length ? (
                    effectivePolicy.restricted_tools.map((t) => (
                      <Badge key={t} variant="destructive" className="font-mono text-[10px]">
                        {t}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-muted-foreground italic">Tidak ada tool terestriksi</span>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Sparkline Activity Trend */}
        <Card className="border-border">
          <CardHeader className="pb-2">
            <CardDescription className="text-xs flex items-center justify-between">
              <span>Activity Trend</span>
              <div className="flex items-center gap-1 bg-muted p-0.5 rounded text-[11px]">
                <button
                  type="button"
                  onClick={() => setTimeWindow("24h")}
                  className={`px-2 py-0.5 rounded font-mono ${
                    timeWindow === "24h" ? "bg-background shadow-xs font-semibold text-foreground" : "text-muted-foreground"
                  }`}
                >
                  24h
                </button>
                <button
                  type="button"
                  onClick={() => setTimeWindow("7d")}
                  className={`px-2 py-0.5 rounded font-mono ${
                    timeWindow === "7d" ? "bg-background shadow-xs font-semibold text-foreground" : "text-muted-foreground"
                  }`}
                >
                  7d
                </button>
              </div>
            </CardDescription>
            <CardTitle className="text-sm font-medium">Keputusan & Denials</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {timeseriesBuckets.length === 0 ? (
              <div className="h-28 flex items-center justify-center text-xs text-muted-foreground">
                Tidak ada riwayat aktivitas
              </div>
            ) : (
              <div className="space-y-2">
                <div className="h-24 flex items-end gap-1 px-1">
                  {timeseriesBuckets.map((b, i) => {
                    const maxT = Math.max(...timeseriesBuckets.map((x) => x.total), 1);
                    const allowH = Math.round((b.allow / maxT) * 100);
                    const denyH = Math.round((b.deny / maxT) * 100);
                    return (
                      <div
                        key={i}
                        className="flex-1 flex flex-col justify-end group relative h-full"
                        title={`${new Date(b.bucket_ns / 1000000).toLocaleString("id-ID")}: Allow ${b.allow}, Deny ${b.deny}`}
                      >
                        {b.deny > 0 && (
                          <div
                            style={{ height: `${Math.max(denyH, 8)}%` }}
                            className="w-full bg-red-500 rounded-t"
                          />
                        )}
                        <div
                          style={{ height: `${Math.max(allowH, b.total > 0 ? 6 : 2)}%` }}
                          className={`w-full rounded-t ${
                            b.total === 0 ? "bg-muted/40" : "bg-emerald-500/80 hover:bg-emerald-500"
                          }`}
                        />
                      </div>
                    );
                  })}
                </div>
                <div className="flex justify-between text-[10px] font-mono text-muted-foreground px-1">
                  <span className="flex items-center gap-1">
                    <span className="size-2 rounded-full bg-emerald-500 inline-block" /> Allow
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="size-2 rounded-full bg-red-500 inline-block" /> Deny
                  </span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* 3. Empty States (2 kondisi) */}
      {totalEventsCount === 0 ? (
        /* Kondisi B: Belum Aktif + snippet curl */
        <Card className="border-dashed border-2 border-border bg-muted/10">
          <CardHeader>
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Terminal className="size-4 text-primary" />
              Agen Belum Aktif
            </CardTitle>
            <CardDescription className="text-xs">
              Belum ada evaluasi atau tool calls yang tercatat untuk Key ID{" "}
              <code className="font-mono text-foreground font-semibold">{keyId}</code>.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <span className="text-xs text-muted-foreground block">
              Jalankan request contoh berikut untuk mulai mengirim traffic ke Cerberus:
            </span>
            <pre className="bg-background p-3 rounded-md border font-mono text-xs overflow-x-auto text-foreground">
              {`curl -X POST http://localhost:8080/v1/decide \\
  -H "Content-Type: application/json" \\
  -d '{"stage":"tool","key_id":"${keyId}","action":"read","resource":"users"}'`}
            </pre>
          </CardContent>
        </Card>
      ) : breachCount === 0 ? (
        /* Kondisi A: Aktif & Bersih hijau */
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="flex items-center gap-3 py-4">
            <CheckCircle2 className="size-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <div className="text-xs">
              <span className="font-semibold text-emerald-700 dark:text-emerald-300 block">
                Status Operasional: Aktif & Bersih
              </span>
              <span className="text-emerald-600/90 dark:text-emerald-400/90">
                0 security breaches tercatat dalam {timeWindow}. Seluruh aktivitas berjalan aman di bawah perimeter kebijakan.
              </span>
            </div>
          </CardContent>
        </Card>
      ) : (
        /* 4. Panel BREACH (jika ada security denials) */
        <Card className="border-destructive/40 bg-destructive/5">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold text-destructive flex items-center gap-2">
                <AlertOctagon className="size-4" />
                Security Breaches ({breachCount})
              </CardTitle>
              <Badge variant="destructive" className="font-mono text-xs font-semibold">
                CRITICAL / HIGH VIOLATIONS
              </Badge>
            </div>
            <CardDescription className="text-xs text-muted-foreground">
              Pelanggaran aturan keamanan yang memicu penolakan seketika (fail-closed).
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="rounded-md border bg-background overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Severity</TableHead>
                    <TableHead className="w-56">Rule ID</TableHead>
                    <TableHead>Alasan / Detail</TableHead>
                    <TableHead className="w-32 text-right">Waktu</TableHead>
                    <TableHead className="w-28 text-right">Aksi</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {breaches.map((b) => {
                    const sevBadge = getSeverityBadge(
                      (b.rule_id.includes("dangerous") || b.rule_id.includes("unparseable")
                        ? "CRITICAL"
                        : "HIGH") as Severity,
                    );
                    const isExpanded = !!expandedRows[`breach-${b.id}`];
                    return (
                      <>
                        <TableRow key={b.id} className="hover:bg-muted/40 text-xs">
                          <TableCell>
                            <Badge variant="outline" className={`text-[10px] ${sevBadge.badgeClass}`}>
                              {sevBadge.label}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono font-semibold text-foreground">
                            {b.rule_id}
                          </TableCell>
                          <TableCell className="text-muted-foreground truncate max-w-xs">
                            {b.reason}
                          </TableCell>
                          <TableCell className="text-right font-mono tabular-nums text-muted-foreground">
                            {new Date(b.time).toLocaleTimeString("id-ID")}
                          </TableCell>
                          <TableCell className="text-right space-x-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-[10px] px-1.5"
                              onClick={() => setInspectEvent(b)}
                            >
                              Detail
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-[10px] px-1.5"
                              onClick={() => {
                                setTraceEvent(b);
                                setTraceOpen(true);
                              }}
                            >
                              Trace
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-[10px] px-1.5"
                              onClick={() =>
                                setExpandedRows((prev) => ({
                                  ...prev,
                                  [`breach-${b.id}`]: !prev[`breach-${b.id}`],
                                }))
                              }
                            >
                              {isExpanded ? "Tutup" : "Args"}
                            </Button>
                          </TableCell>
                        </TableRow>
                        {isExpanded && (
                          <TableRow key={`breach-expand-${b.id}`} className="bg-muted/30">
                            <TableCell colSpan={5} className="p-3 text-xs font-mono">
                              <pre className="bg-background p-2 rounded border overflow-x-auto text-[11px]">
                                {b.args ? JSON.stringify(b.args, null, 2) : "// Tidak ada args payload"}
                              </pre>
                            </TableCell>
                          </TableRow>
                        )}
                      </>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* 5. Dense Timeline Table (Argon spec) */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold">Decision Timeline</h2>
            <Badge variant="secondary" className="font-mono text-xs tabular-nums">
              {filteredEvents.length} decisions
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative w-64">
              <Search className="absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
              <Input
                ref={searchInputRef}
                placeholder="Filter timeline… (press /)"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                className="pl-8 h-8 text-xs"
              />
            </div>
            <div className="hidden sm:flex items-center gap-1 text-[10px] text-muted-foreground font-mono bg-muted/60 px-2 py-1 rounded">
              <span>nav: j/k</span>
              <span>•</span>
              <span>expand: Enter</span>
              <span>•</span>
              <span>trace: t</span>
            </div>
          </div>
        </div>

        <div className="rounded-md border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead className="w-32">Time</TableHead>
                <TableHead className="w-20">Stage</TableHead>
                <TableHead className="w-20">Verdict</TableHead>
                <TableHead className="w-36">Subject</TableHead>
                <TableHead className="w-48">Rule ID</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead className="w-28 text-right">Latency</TableHead>
                <TableHead className="w-16 text-right">Aksi</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredEvents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="h-24 text-center text-xs text-muted-foreground">
                    Tidak ada event timeline yang cocok.
                  </TableCell>
                </TableRow>
              ) : (
                filteredEvents.map((ev, index) => {
                  const isSelected = index === selectedRowIndex;
                  const isExpanded = !!expandedRows[ev.id];
                  const isAllow = ev.decision === "allow";
                  return (
                    <>
                      <TableRow
                        key={ev.id}
                        className={`text-xs cursor-pointer ${
                          isSelected ? "bg-accent/40 ring-1 ring-primary/30" : "hover:bg-muted/40"
                        }`}
                        onClick={() => setSelectedRowIndex(index)}
                        onDoubleClick={() =>
                          setExpandedRows((prev) => ({ ...prev, [ev.id]: !prev[ev.id] }))
                        }
                      >
                        <TableCell className="p-2 text-center" onClick={(e) => {
                          e.stopPropagation();
                          setExpandedRows((prev) => ({ ...prev, [ev.id]: !prev[ev.id] }));
                        }}>
                          {isExpanded ? (
                            <ChevronDown className="size-3.5 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="size-3.5 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-muted-foreground tabular-nums whitespace-nowrap">
                          {new Date(ev.time).toLocaleTimeString("id-ID", {
                            hour: "2-digit",
                            minute: "2-digit",
                            second: "2-digit",
                          })}
                        </TableCell>
                        <TableCell className="font-medium text-muted-foreground">
                          {ev.stage}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={
                              isAllow
                                ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-[10px]"
                                : "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30 text-[10px]"
                            }
                          >
                            {ev.decision.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono truncate max-w-[140px]">
                          {ev.subject || "—"}
                        </TableCell>
                        <TableCell className="font-mono font-medium truncate max-w-[180px]">
                          {ev.rule_id}
                        </TableCell>
                        <TableCell className="text-muted-foreground truncate max-w-xs" title={ev.reason}>
                          {ev.reason || "—"}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums text-muted-foreground">
                          {ev.latency_us}µs
                          {ev.cached && (
                            <span className="ml-1 text-[9px] text-primary/80 font-semibold" title="Cached verdict">
                              ⚡
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-right space-x-1" onClick={(e) => e.stopPropagation()}>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 text-[10px] px-1.5"
                            onClick={() => setInspectEvent(ev)}
                          >
                            Detail
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 text-[10px] px-1.5"
                            onClick={() => {
                              setTraceEvent(ev);
                              setTraceOpen(true);
                            }}
                          >
                            Trace
                          </Button>
                        </TableCell>
                      </TableRow>

                      {/* Row Expand: masked args JSON */}
                      {isExpanded && (
                        <TableRow key={`expand-${ev.id}`} className="bg-muted/20">
                          <TableCell colSpan={9} className="p-3">
                            <div className="space-y-1 text-xs">
                              <span className="text-[11px] font-medium text-muted-foreground">
                                Payload Arguments (Masked):
                              </span>
                              <pre className="bg-background p-2.5 rounded border text-[11px] font-mono overflow-x-auto max-h-40">
                                {ev.args ? JSON.stringify(ev.args, null, 2) : "// Tidak ada arguments payload"}
                              </pre>
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

      {/* Trace Dialog */}
      <TraceDialog
        open={traceOpen}
        onOpenChange={setTraceOpen}
        event={traceEvent}
      />

      {/* Rotate Key Dialog */}
      <Dialog open={rotateDialogOpen} onOpenChange={setRotateDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-base font-semibold flex items-center gap-2">
              <Key className="size-4 text-primary" />
              Rotate API Key
            </DialogTitle>
            <DialogDescription className="text-xs">
              Kloning konfigurasi kebijakan agen ke key baru, dengan opsi mencabut (revoke) key lama seketika.
            </DialogDescription>
          </DialogHeader>

          {rotateResult ? (
            <div className="space-y-3 py-2">
              <div className="p-3 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-800 dark:text-emerald-300">
                Rotasi berhasil! Key ID baru telah dibuat:
                <div className="font-mono font-bold text-sm mt-1 select-all text-foreground">
                  {rotateResult.newKeyId}
                </div>
              </div>
              <DialogFooter>
                <Button
                  size="sm"
                  onClick={() => {
                    setRotateDialogOpen(false);
                    router.push(`/agents/${rotateResult.newKeyId}`);
                  }}
                  className="text-xs"
                >
                  Buka Key Baru
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-4 py-2 text-xs">
              <div className="space-y-1.5">
                <label className="font-medium text-muted-foreground">Key ID Saat Ini:</label>
                <Input value={keyId} disabled className="font-mono text-xs bg-muted" />
              </div>

              <div className="space-y-1.5">
                <label className="font-medium text-muted-foreground">Suffix Key Baru:</label>
                <Input
                  value={rotateSuffix}
                  onChange={(e) => setRotateSuffix(e.target.value)}
                  placeholder="-v2"
                  className="font-mono text-xs"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <Switch
                  id="revoke-old"
                  checked={revokeOld}
                  onCheckedChange={setRevokeOld}
                />
                <label
                  htmlFor="revoke-old"
                  className="text-xs font-medium text-muted-foreground cursor-pointer"
                >
                  Revoke key lama ({keyId}) seketika
                </label>
              </div>

              {rotateKeyMutation.isError && (
                <div className="text-destructive text-xs">
                  {rotateKeyMutation.error.message}
                </div>
              )}

              <DialogFooter>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setRotateDialogOpen(false)}
                  className="text-xs"
                >
                  Batal
                </Button>
                <Button
                  size="sm"
                  onClick={handleRotateKeySubmit}
                  disabled={rotateKeyMutation.isPending}
                  className="text-xs"
                >
                  {rotateKeyMutation.isPending ? "Memproses…" : "Rotate Key Sekarang"}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
      <InspectorDrawer
        open={!!inspectEvent}
        onOpenChange={(open) => !open && setInspectEvent(null)}
        event={inspectEvent}
      />
    </div>
  );
}
