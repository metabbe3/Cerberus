"use client";

import { useMemo, useState } from "react";
import { useDecisionStream } from "@/components/decisions/stream";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { mergeEvents, useAudit, useData, usePutData } from "@/lib/queries";
import { AlertCircle, Plus, Radio, Shield, ShieldAlert, ShieldCheck } from "lucide-react";

export default function ShieldPage() {
  const [ruleFilter, setRuleFilter] = useState("all");
  const [newKey, setNewKey] = useState("");
  const [actionErr, setActionErr] = useState<string | null>(null);

  // 1. Data document for exempt_keys
  const { data: owlData, isLoading: dataLoading } = useData();
  const putData = usePutData();

  const prodShield = (owlData?.data.prod_shield ?? {}) as {
    exempt_keys?: string[];
    [key: string]: unknown;
  };
  const exemptKeys: string[] = Array.isArray(prodShield.exempt_keys) ? prodShield.exempt_keys : [];

  // 2. Live feed + historical audit
  const auditParams = useMemo(() => {
    const p = new URLSearchParams({ limit: "200", decision: "deny" });
    return p;
  }, []);
  const history = useAudit(auditParams);
  const { events: liveEvents, connected } = useDecisionStream(true);

  // Filter to shield.* denies only
  const allEvents = useMemo(() => {
    const shieldLive = liveEvents.filter(
      (e) => e.decision === "deny" && e.rule_id?.startsWith("shield."),
    );
    const shieldHistory = (history.data ?? []).filter(
      (e) => e.decision === "deny" && e.rule_id?.startsWith("shield."),
    );
    return mergeEvents(shieldLive, shieldHistory);
  }, [liveEvents, history.data]);

  // Compute counters per pattern
  const patternCounts = useMemo(() => {
    const counts: Record<string, number> = {
      "shield.cmd.dangerous": 0,
      "shield.container.protected": 0,
      "shield.prod.ip_blocked": 0,
      "shield.prod.no_access": 0,
    };
    for (const ev of allEvents) {
      if (ev.rule_id) {
        counts[ev.rule_id] = (counts[ev.rule_id] ?? 0) + 1;
      }
    }
    return counts;
  }, [allEvents]);

  // Filtered events
  const filteredEvents = useMemo(() => {
    if (ruleFilter === "all") return allEvents;
    return allEvents.filter((e) => e.rule_id === ruleFilter);
  }, [allEvents, ruleFilter]);

  // Toggle or add exempt key
  const toggleExemptKey = async (keyId: string, currentExempt: boolean) => {
    if (!owlData) return;
    setActionErr(null);
    try {
      const nextExempt = currentExempt
        ? exemptKeys.filter((k) => k !== keyId)
        : [...exemptKeys, keyId];

      const nextDoc = {
        ...owlData.data,
        prod_shield: {
          ...prodShield,
          exempt_keys: nextExempt,
        },
      };
      await putData.mutateAsync(nextDoc);
    } catch (e) {
      setActionErr((e as Error).message);
    }
  };

  const handleAddKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKey.trim()) return;
    await toggleExemptKey(newKey.trim(), false);
    setNewKey("");
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Production Shield"
        description="Monitor real-time shield violations and manage Production Shield key exemptions."
      >
        <div className="flex items-center gap-2">
          <Badge
            variant={connected ? "default" : "secondary"}
            className="flex items-center gap-1.5"
          >
            <Radio className={`size-3 ${connected ? "animate-pulse text-green-400" : ""}`} />
            {connected ? "Live Stream Connected" : "Connecting..."}
          </Badge>
        </div>
      </PageHeader>

      {actionErr && (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Action failed</AlertTitle>
          <AlertDescription>{actionErr}</AlertDescription>
        </Alert>
      )}

      {/* Counters per Pattern */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Dangerous Commands</CardTitle>
            <ShieldAlert className="size-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{patternCounts["shield.cmd.dangerous"] ?? 0}</div>
            <p className="text-xs text-muted-foreground">shield.cmd.dangerous</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Protected Containers</CardTitle>
            <Shield className="size-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{patternCounts["shield.container.protected"] ?? 0}</div>
            <p className="text-xs text-muted-foreground">shield.container.protected</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Prod IP Blocked</CardTitle>
            <ShieldAlert className="size-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{patternCounts["shield.prod.ip_blocked"] ?? 0}</div>
            <p className="text-xs text-muted-foreground">shield.prod.ip_blocked</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">No Prod Access</CardTitle>
            <Shield className="size-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{patternCounts["shield.prod.no_access"] ?? 0}</div>
            <p className="text-xs text-muted-foreground">shield.prod.no_access</p>
          </CardContent>
        </Card>
      </div>

      {/* Exempt Keys Panel */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base font-semibold">Exempt Keys</CardTitle>
              <CardDescription>
                Keys listed here bypass Production Shield rules (written to data.prod_shield.exempt_keys via Admin API).
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={handleAddKey} className="flex gap-2">
            <Input
              placeholder="e.g. k-emergency-owner"
              value={newKey}
              onChange={(e) => setNewKey(e.target.value)}
              className="max-w-sm"
            />
            <Button type="submit" size="sm" disabled={!newKey.trim() || putData.isPending}>
              <Plus className="size-4 mr-1" />
              Add Exempt Key
            </Button>
          </form>

          {dataLoading ? (
            <p className="text-sm text-muted-foreground">Loading exempt keys...</p>
          ) : exemptKeys.length === 0 ? (
            <div className="rounded-md border border-dashed p-4 text-center text-sm text-muted-foreground">
              No keys are currently exempt. Production Shield is fully enforced.
            </div>
          ) : (
            <div className="divide-y rounded-md border">
              {exemptKeys.map((key) => (
                <div key={key} className="flex items-center justify-between p-3 text-sm">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="size-4 text-green-500" />
                    <span className="font-mono">{key}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">Exempt</span>
                    <Switch
                      checked={true}
                      onCheckedChange={() => toggleExemptKey(key, true)}
                      disabled={putData.isPending}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Live Feed with Filter per rule_id */}
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="text-base font-semibold">Shield Deny Live Feed</CardTitle>
              <CardDescription>
                Real-time stream of denied operations triggered by shield policies.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Rule Filter:</span>
              <Select value={ruleFilter} onValueChange={setRuleFilter}>
                <SelectTrigger className="w-56">
                  <SelectValue placeholder="All Shield Rules" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Shield Rules</SelectItem>
                  <SelectItem value="shield.cmd.dangerous">shield.cmd.dangerous</SelectItem>
                  <SelectItem value="shield.container.protected">shield.container.protected</SelectItem>
                  <SelectItem value="shield.prod.ip_blocked">shield.prod.ip_blocked</SelectItem>
                  <SelectItem value="shield.prod.no_access">shield.prod.no_access</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredEvents.length === 0 ? (
            <EmptyState
              title="No shield violations"
              hint="No deny events matching the selected shield filter have been recorded."
            />
          ) : (
            <div className="rounded-md border overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-36">Time</TableHead>
                    <TableHead className="w-20">Stage</TableHead>
                    <TableHead className="w-48">Rule ID</TableHead>
                    <TableHead className="w-36">Key ID</TableHead>
                    <TableHead>Subject</TableHead>
                    <TableHead>Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredEvents.slice(0, 100).map((ev) => (
                    <TableRow key={ev.id}>
                      <TableCell className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(ev.time).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">
                          {ev.stage}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="destructive" className="font-mono text-xs">
                          {ev.rule_id}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{ev.key_id}</TableCell>
                      <TableCell className="font-mono text-xs max-w-xs truncate" title={ev.subject}>
                        {ev.subject}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{ev.reason}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
