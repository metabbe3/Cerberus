"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AlertCircle, Download, Radio, X } from "lucide-react";
import { toast } from "sonner";
import { downloadCSV } from "@/lib/csv";
import { formatWibDateTime } from "@/components/timestamp";
import { AuditTable } from "@/components/decisions/audit-table";
import { InspectorDrawer } from "@/components/decisions/inspector-drawer";
import { useDecisionStream } from "@/components/decisions/stream";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { RefreshIndicator } from "@/components/refresh-indicator";
import { ActivitySubNav } from "@/components/sub-nav";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { mergeEvents, useAudit } from "@/lib/queries";
import type { AuditEvent } from "@/lib/schema";


// Input teks yang sinkron ke URL secara debounced (400 ms) — tidak refetch per keystroke.
function DebouncedFilterInput({
  placeholder,
  value,
  onCommit,
  className,
}: {
  placeholder: string;
  value: string;
  onCommit: (v: string) => void;
  className?: string;
}) {
  const [local, setLocal] = useState(value);
  useEffect(() => setLocal(value), [value]);
  useEffect(() => {
    if (local === value) return;
    const t = setTimeout(() => onCommit(local), 400);
    return () => clearTimeout(t);
  }, [local, value, onCommit]);
  return (
    <Input
      className={className}
      placeholder={placeholder}
      value={local}
      aria-label={placeholder}
      onChange={(e) => setLocal(e.target.value)}
    />
  );
}

function DecisionsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Read URL-driven filters
  const stage = searchParams.get("stage") ?? "all";
  const decision = searchParams.get("decision") ?? "all";
  const keyId = searchParams.get("key_id") ?? "";
  const ruleId = searchParams.get("rule_id") ?? "";

  const [live, setLive] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Sync filter update to URL query string
  const updateFilter = (key: string, val: string) => {
    const p = new URLSearchParams(searchParams.toString());
    if (!val || val === "all") {
      p.delete(key);
    } else {
      p.set(key, val);
    }
    router.replace(`/decisions?${p.toString()}`);
  };

  const clearAllFilters = () => {
    router.replace("/decisions");
  };

  const hasActiveFilters = stage !== "all" || decision !== "all" || Boolean(keyId) || Boolean(ruleId);

  const historyParams = useMemo(() => {
    const p = new URLSearchParams({ limit: "300" });
    if (stage !== "all") p.set("stage", stage);
    if (decision !== "all") p.set("decision", decision);
    if (keyId) p.set("key_id", keyId);
    if (ruleId) p.set("rule_id", ruleId);
    return p;
  }, [stage, decision, keyId, ruleId]);

  const history = useAudit(historyParams);
  const { events: liveEvents, connected } = useDecisionStream(live);

  // Filter live stream client-side to match the current filter
  const shownLive = liveEvents.filter(
    (e) =>
      (stage === "all" || e.stage === stage) &&
      (decision === "all" || e.decision === decision) &&
      (!keyId || e.key_id.toLowerCase().includes(keyId.toLowerCase())) &&
      (!ruleId || e.rule_id.toLowerCase().includes(ruleId.toLowerCase())),
  );

  const events = mergeEvents(shownLive, history.data ?? []);

  const handleSelectEvent = (ev: AuditEvent) => {
    setSelectedEvent(ev);
    setDrawerOpen(true);
  };

  const exportToCSV = () => {
    if (events.length === 0) return;
    const headers = [
      "ID",
      "Timestamp (UTC)",
      "Timestamp (WIB)",
      "Stage",
      "Key ID",
      "Subject",
      "Decision",
      "Rule ID",
      "Reason",
      "Latency (µs)",
      "Cached",
      "Epoch",
    ];
    const rows = events.map((ev) => [
      ev.id,
      ev.time,
      formatWibDateTime(ev.time),
      ev.stage,
      ev.key_id,
      ev.subject,
      ev.decision,
      ev.rule_id,
      ev.reason,
      ev.latency_us ?? 0,
      ev.cached ? "true" : "false",
      ev.epoch,
    ]);
    const dateStr = new Date().toISOString().slice(0, 10);
    downloadCSV(`cerberus-decisions-${dateStr}.csv`, headers, rows);
    toast.success(`Berhasil mengunduh ${events.length} baris keputusan (CSV)`);
  };

  return (
    <div className="space-y-4">
      <ActivitySubNav />

      <PageHeader
        title={
          <div className="flex items-center gap-2">
            <span>Keputusan (Decisions)</span>
            <Badge
              variant="outline"
              className={connected ? "gap-1.5 border-emerald-500/40 text-emerald-500 text-xs font-mono" : "gap-1.5 text-xs font-mono"}
            >
              <Radio className={connected ? "size-3 animate-pulse" : "size-3"} aria-hidden />
              {connected ? "live" : "offline"}
            </Badge>
          </div>
        }
        description="Jejak audit seluruh evaluasi kebijakan allow/deny gateway secara waktu nyata."
      >
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={exportToCSV}
            className="h-8 gap-1.5 text-xs"
            disabled={events.length === 0}
          >
            <Download className="size-3.5" />
            Ekspor CSV ({events.length})
          </Button>
          <label className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
            Aliran Live <Switch checked={live} onCheckedChange={setLive} />
          </label>
        </div>
      </PageHeader>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-2 bg-muted/20 p-2.5 rounded-lg border">
        {/* Stage Filter */}
        <Select value={stage} onValueChange={(val) => updateFilter("stage", val)}>
          <SelectTrigger className="w-32 h-8 text-xs">
            <SelectValue placeholder="Semua Stage" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Semua Stage</SelectItem>
            <SelectItem value="llm">llm</SelectItem>
            <SelectItem value="tool">tool</SelectItem>
            <SelectItem value="http">http</SelectItem>
            <SelectItem value="docker">docker</SelectItem>
            <SelectItem value="ssh">ssh</SelectItem>
            <SelectItem value="db">db</SelectItem>
            <SelectItem value="k8s">k8s</SelectItem>
          </SelectContent>
        </Select>

        {/* Decision Filter */}
        <Select value={decision} onValueChange={(val) => updateFilter("decision", val)}>
          <SelectTrigger className="w-32 h-8 text-xs">
            <SelectValue placeholder="Semua Keputusan" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Semua Keputusan</SelectItem>
            <SelectItem value="allow">Allow</SelectItem>
            <SelectItem value="deny">Deny</SelectItem>
          </SelectContent>
        </Select>

        {/* Key ID Filter */}
        <DebouncedFilterInput
          className="w-48 h-8 text-xs font-mono"
          placeholder="Filter key_id…"
          value={keyId}
          onCommit={(v) => updateFilter("key_id", v)}
        />

        {/* Rule ID Filter */}
        <DebouncedFilterInput
          className="w-48 h-8 text-xs font-mono"
          placeholder="Filter rule_id…"
          value={ruleId}
          onCommit={(v) => updateFilter("rule_id", v)}
        />

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

        <div className="ml-auto flex items-center gap-2">
          <RefreshIndicator
            autoIntervalSec={5}
            onRefresh={() => history.refetch()}
            isRefreshing={history.isFetching}
          />
        </div>
      </div>

      {live && !connected ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Aliran Live Terputus</AlertTitle>
          <AlertDescription>
            Koneksi streaming SSE ke mesin gateway terputus; data di bawah dimuat dari log audit historis.
          </AlertDescription>
        </Alert>
      ) : null}

      {history.isError ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Gagal Menghubungi Gateway</AlertTitle>
          <AlertDescription>
            {(history.error as Error).message}
          </AlertDescription>
        </Alert>
      ) : null}

      {history.isPending ? (
        <div className="space-y-2 rounded-md border p-4">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </div>
      ) : events.length === 0 ? (
        <EmptyState
          type={hasActiveFilters ? "filtered-out" : "zero-data"}
          title="Belum ada keputusan di jendela ini"
          hint={
            hasActiveFilters
              ? "Tidak ada event keputusan yang sesuai dengan parameter filter yang sedang aktif."
              : "Kirim request ke gateway melalui curl atau SDK untuk mulai merekam evaluasi kebijakan."
          }
          actionLabel="Muat ulang"
          onAction={() => history.refetch()}
        />
      ) : (
        <AuditTable
          events={events}
          onSelectEvent={handleSelectEvent}
        />
      )}

      {/* Inspector Slide-over Drawer */}
      <InspectorDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        event={selectedEvent}
      />
    </div>
  );
}

export default function DecisionsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-xs text-muted-foreground">Memuat keputusan…</div>}>
      <DecisionsContent />
    </Suspense>
  );
}
