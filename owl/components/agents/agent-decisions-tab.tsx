"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertCircle, Radio, RefreshCcw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AuditTable } from "@/components/decisions/audit-table";
import { InspectorDrawer } from "@/components/decisions/inspector-drawer";
import { useDecisionStream } from "@/components/decisions/stream";
import { EmptyState } from "@/components/empty-state";
import { mergeEvents, useAudit } from "@/lib/queries";
import type { AuditEvent } from "@/lib/schema";

export function AgentDecisionsTab({ keyId }: { keyId: string }) {
  const router = useRouter();
  const [stage, setStage] = useState("all");
  const [decision, setDecision] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const historyParams = useMemo(() => {
    const p = new URLSearchParams({ limit: "200", key_id: keyId });
    if (stage !== "all") p.set("stage", stage);
    if (decision !== "all") p.set("decision", decision);
    return p;
  }, [keyId, stage, decision]);

  const history = useAudit(historyParams);
  const { events: liveEvents, connected } = useDecisionStream(true);

  const shownLive = useMemo(() => {
    return liveEvents.filter(
      (e) =>
        e.key_id === keyId &&
        (stage === "all" || e.stage === stage) &&
        (decision === "all" || e.decision === decision),
    );
  }, [liveEvents, keyId, stage, decision]);

  const events = useMemo(() => {
    return mergeEvents(shownLive, history.data ?? []);
  }, [shownLive, history.data]);

  const handleCreateRule = (ev: AuditEvent) => {
    if (ev.stage === "tool") {
      router.push(`/agents/${ev.key_id}?prefill=restricted:${encodeURIComponent(ev.subject)}`);
    } else {
      router.push(`/agents/${ev.key_id}?prefill=llm:${encodeURIComponent(ev.subject)}`);
    }
  };

  return (
    <div className="space-y-4 pt-2">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Select value={stage} onValueChange={setStage}>
            <SelectTrigger className="w-32 h-8 text-xs">
              <SelectValue />
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

          <Select value={decision} onValueChange={setDecision}>
            <SelectTrigger className="w-32 h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Semua Keputusan</SelectItem>
              <SelectItem value="allow">allow</SelectItem>
              <SelectItem value="deny">deny</SelectItem>
            </SelectContent>
          </Select>

          <Button
            variant="outline"
            size="sm"
            className="h-8 text-xs gap-1"
            onClick={() => history.refetch()}
          >
            <RefreshCcw className="size-3" />
            Refresh
          </Button>
        </div>

        <Badge
          variant="outline"
          className={
            connected
              ? "gap-1.5 border-success/40 text-success text-xs"
              : "gap-1.5 text-xs text-muted-foreground"
          }
        >
          <Radio className={connected ? "size-3 animate-pulse" : "size-3"} aria-hidden />
          {connected ? "Stream live" : "Stream offline"}
        </Badge>
      </div>

      {history.isError && (
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertTitle>Gagal Memuat Riwayat Keputusan</AlertTitle>
          <AlertDescription className="text-xs">
            {(history.error as Error).message}
          </AlertDescription>
        </Alert>
      )}

      {events.length === 0 && !history.isPending ? (
        <EmptyState
          title="Belum ada aktivitas keputusan"
          hint={`Kirim permintaan POST /v1/decide/* dengan key "${keyId}" untuk melihat riwayat evaluasi gateway.`}
        />
      ) : (
        <AuditTable
          events={events}
          onCreateRule={handleCreateRule}
          onSelectEvent={setSelectedEvent}
        />
      )}

      <InspectorDrawer
        open={!!selectedEvent}
        onOpenChange={(open) => !open && setSelectedEvent(null)}
        event={selectedEvent}
      />
    </div>
  );
}
