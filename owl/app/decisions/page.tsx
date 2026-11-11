"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { AuditTable } from "@/components/decisions/audit-table";
import { useDecisionStream } from "@/components/decisions/stream";
import { EmptyState } from "@/components/empty-state";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, Radio } from "lucide-react";
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
import { useAudit } from "@/lib/queries";
import type { AuditEvent } from "@/lib/schema";

export default function DecisionsPage() {
  const router = useRouter();
  const [live, setLive] = useState(true);
  const [stage, setStage] = useState("all");
  const [decision, setDecision] = useState("all");
  const [keyId, setKeyId] = useState("");

  const historyParams = useMemo(() => {
    const p = new URLSearchParams({ limit: "200" });
    if (stage !== "all") p.set("stage", stage);
    if (decision !== "all") p.set("decision", decision);
    if (keyId) p.set("key_id", keyId);
    return p;
  }, [stage, decision, keyId]);
  const history = useAudit(historyParams);

  const { events: liveEvents, connected } = useDecisionStream(live);

  // Live rows pass the same filters client-side; history is filtered
  // server-side by the engine. Both merge newest-first (history comes
  // newest-first from the audit log; live events arrive oldest→newest).
  const shownLive = liveEvents.filter(
    (e) =>
      (stage === "all" || e.stage === stage) &&
      (decision === "all" || e.decision === decision) &&
      (!keyId || e.key_id.includes(keyId)),
  );
  const events: AuditEvent[] = [...shownLive].reverse().concat(history.data ?? []).slice(0, 200);

  const createRule = (ev: AuditEvent) => {
    if (ev.stage === "tool") {
      router.push(`/agents/${ev.key_id}?prefill=restricted:${encodeURIComponent(ev.subject)}`);
    } else {
      router.push(`/agents/${ev.key_id}?prefill=llm:${encodeURIComponent(ev.subject)}`);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          Decisions
          <Badge variant="outline" className="gap-1.5">
            <Radio className={connected ? "size-3" : "size-3 text-muted-foreground"} aria-hidden />
            {connected ? "live" : "offline"}
          </Badge>
        </h1>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          Live <Switch checked={live} onCheckedChange={setLive} />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select value={stage} onValueChange={setStage}>
          <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all stages</SelectItem>
            <SelectItem value="llm">llm</SelectItem>
            <SelectItem value="tool">tool</SelectItem>
          </SelectContent>
        </Select>
        <Select value={decision} onValueChange={setDecision}>
          <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">all decisions</SelectItem>
            <SelectItem value="allow">allow</SelectItem>
            <SelectItem value="deny">deny</SelectItem>
          </SelectContent>
        </Select>
        <Input
          className="w-64"
          placeholder="key_id contains…"
          value={keyId}
          onChange={(e) => setKeyId(e.target.value)}
        />
        <Button variant="outline" size="sm" onClick={() => history.refetch()}>
          Refresh history
        </Button>
      </div>

      {live && !connected ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Stream offline</AlertTitle>
          <AlertDescription>
            The live stream cannot reach the engine; history below is from the
            audit log.
          </AlertDescription>
        </Alert>
      ) : null}

      {history.isError ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Engine unreachable</AlertTitle>
          <AlertDescription>
            {(history.error as Error).message}
          </AlertDescription>
        </Alert>
      ) : null}

      {events.length === 0 && !history.isPending ? (
        <EmptyState
          title="No decisions yet"
          hint="Fire a POST /v1/decide against the engine, or relax the filters."
        />
      ) : (
        <AuditTable events={events} onCreateRule={createRule} />
      )}
    </div>
  );
}
