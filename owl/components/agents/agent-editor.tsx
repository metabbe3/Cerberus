"use client";

import { Check, Copy, Flame, History, Plus, Save, ShieldAlert, Terminal, Trash2, X } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { StringListEditor } from "@/components/editors/string-list";
import { AgentDecisionsTab } from "@/components/agents/agent-decisions-tab";
import { useBreakGlass, useData, useDeleteAgent, useSaveAgent, useToggleKillSwitch } from "@/lib/queries";
import type { Agent, MaskingRule } from "@/lib/schema";

// Klik-untuk-tambah: nilai umum yang muncul sebagai chip saran di editor
// (tetap bisa ketik manual untuk nilai custom).
const KNOWN_TOOLS = [
  "read", "write", "edit", "bash", "exec", "grep", "glob",
  "web_search", "web_fetch", "http_request",
  "db_query", "docker_exec", "docker rm", "ssh_run", "k8s_apply",
  "execute_shell", "send_message", "schedule_task", "analyze_logs",
];
const KNOWN_MODELS = [
  "glm-*", "glm-5.2", "glm-5.2-flash",
  "gemini-*", "gpt-4", "m1", "claude-*", "gpt-*",
];


const TRANSFORMS = ["redact", "mask", "hash"] as const;
const SCOPES = ["both", "args", "response"] as const;

// One tab editor per concern. All tabs mutate the same draft and share one
// Save button — the zod gate runs on PUT (parseData in useSaveAgent), and a
// 422 from the engine surfaces here verbatim without touching the cache.
export function AgentEditor({
  keyId,
  agent,
}: {
  keyId: string;
  agent: Agent;
}) {
  const router = useRouter();
  const params = useSearchParams();
  const [draft, setDraft] = useState<Agent>(() => {
    const d = structuredClone(agent);
    // "Create rule from this event" lands here pre-filled: tool denials add
    // the invoked subject to restricted_tool_calls; llm denials can't be a
    // per-agent tool rule (models are gated by allowlists / blocked_patterns),
    // so only a hint is shown.
    const prefill = params.get("prefill");
    if (prefill?.startsWith("restricted:")) {
      const subject = decodeURIComponent(prefill.slice("restricted:".length));
      d.restricted_tool_calls = d.restricted_tool_calls ?? [];
      if (!d.restricted_tool_calls.includes(subject)) {
        d.restricted_tool_calls.push(subject);
      }
    } else if (prefill?.startsWith("allow:")) {
      const subject = decodeURIComponent(prefill.slice("allow:".length));
      d.allowed_tools = d.allowed_tools ?? [];
      if (!d.allowed_tools.includes(subject)) {
        d.allowed_tools.push(subject);
      }
    }
    return d;
  });
  const save = useSaveAgent();
  const deleteAgent = useDeleteAgent();
  const toggleKillSwitch = useToggleKillSwitch();
  const breakGlass = useBreakGlass();
  const { data: rawData } = useData();
  const killSwitchConfig = rawData?.data?.config?.kill_switch;
  const isKilled = Boolean(killSwitchConfig?.keys?.[keyId] || killSwitchConfig?.global);

  const [savedError, setSavedError] = useState<string | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const prefill = params.get("prefill");
  const llmHint = prefill?.startsWith("llm:")
    ? decodeURIComponent(prefill.slice("llm:".length))
    : null;

  const set = (patch: Partial<Agent>) => setDraft((d) => ({ ...d, ...patch }));
  const list = (field: keyof Agent) => (draft[field] as string[] | undefined) ?? [];

  const curlSnippet = useMemo(() => {
    return `curl -X POST $CERBERUS_URL/v1/decide/tool \\
  -H "X-Cerberus-Key: ${keyId}" \\
  -H "Content-Type: application/json" \\
  -d '{"stage":"tool","key_id":"${keyId}","action":"read","resource":"x"}'`;
  }, [keyId]);

  const copyCurl = async () => {
    try {
      await navigator.clipboard.writeText(curlSnippet);
      setCopiedCurl(true);
      setTimeout(() => setCopiedCurl(false), 2000);
      toast.success("Snippet cURL disalin ke clipboard!");
    } catch {
      toast.error("Gagal menyalin cURL");
    }
  };

  const handleDeleteAgent = () => {
    deleteAgent.mutate(keyId, {
      onSuccess: () => {
        toast.success(`Agent ${keyId} berhasil dihapus`);
        router.push("/agents");
      },
      onError: (e) => toast.error(`Gagal menghapus agent: ${e.message}`),
    });
  };

  const onSave = () => {
    setSavedError(null);
    save.mutate(
      { keyId, agent: draft },
      {
        onSuccess: (out) => toast.success(`Data installed (epoch ${out.epoch})`),
        onError: (e) => setSavedError(e.message),
      },
    );
  };

  const handleToggleKillSwitch = () => {
    toggleKillSwitch.mutate(
      { keyId, active: !isKilled },
      {
        onSuccess: () =>
          toast.success(
            !isKilled
              ? `Kill Switch ACTIVATED for ${keyId}`
              : `Kill Switch DEACTIVATED for ${keyId}`,
          ),
        onError: (e) => toast.error(`Failed to update kill switch: ${e.message}`),
      },
    );
  };

  const handleBreakGlass = () => {
    breakGlass.mutate(
      { keyId, reason: `Emergency break-glass for ${keyId} from Owl Console`, durationMinutes: 15 },
      {
        onSuccess: () =>
          toast.success(`Break-Glass bypass active for 15 minutes on ${keyId}`),
        onError: (e) => toast.error(`Break-Glass failed: ${e.message}`),
      },
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="truncate font-mono text-lg">{keyId}</h1>
            {isKilled && (
              <span className="rounded bg-destructive/15 px-2 py-0.5 text-xs font-semibold text-destructive">
                KILL SWITCH ACTIVE
              </span>
            )}
          </div>
          <p className="text-sm text-muted-foreground">
            {draft.description ?? "No description"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {/* Audit Trail Button */}
          <Button variant="outline" size="sm" asChild>
            <Link href={`/decisions?key_id=${encodeURIComponent(keyId)}`}>
              <History className="size-4" /> Audit Trail
            </Link>
          </Button>

          {/* Kill Switch with Confirm Dialog */}
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant={isKilled ? "destructive" : "outline"}
                size="sm"
                className={isKilled ? "animate-pulse" : ""}
                disabled={toggleKillSwitch.isPending}
              >
                <ShieldAlert className="size-4" />
                {isKilled ? "Deactivate Kill Switch" : "Kill Switch"}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  {isKilled
                    ? `Deactivate Kill Switch for ${keyId}?`
                    : `Activate Kill Switch for ${keyId}?`}
                </AlertDialogTitle>
                <AlertDialogDescription>
                  {isKilled
                    ? `This will restore normal policy evaluations for agent ${keyId}.`
                    : `CRITICAL ACTION: This will immediately deny ALL traffic for agent key ${keyId} with rule_id ops.kill_switch.`}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={handleToggleKillSwitch}
                  className={isKilled ? "" : "bg-destructive text-destructive-foreground hover:bg-destructive/90"}
                >
                  {isKilled ? "Restore Agent" : "Confirm Kill"}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>

          {/* Break Glass with Confirm Dialog */}
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="destructive"
                size="sm"
                disabled={breakGlass.isPending}
              >
                <Flame className="size-4" /> Break Glass (15m)
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Trigger Emergency Break-Glass for {keyId}?</AlertDialogTitle>
                <AlertDialogDescription>
                  WARNING: This will bypass ALL policy constraints for key {keyId} for a 15-minute emergency time-window. An urgent real-time security alert will be streamed to all monitoring dashboards.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={handleBreakGlass}
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                >
                  Confirm Break-Glass Bypass
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>

          {/* Delete Agent with Confirm Dialog */}
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                disabled={deleteAgent.isPending}
              >
                <Trash2 className="size-4" />
                Hapus Agent
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Hapus Agent {keyId}?</AlertDialogTitle>
                <AlertDialogDescription>
                  Tindakan ini akan menghapus agent {keyId} dari konfigurasi gateway secara permanen.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Batal</AlertDialogCancel>
                <AlertDialogAction
                  onClick={handleDeleteAgent}
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                >
                  Hapus Sekarang
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>

          {/* Save Button */}
          <Button onClick={onSave} disabled={save.isPending}>
            <Save aria-hidden /> Save
          </Button>
        </div>
      </div>

      {llmHint ? (
        <Alert>
          <AlertCircle />
          <AlertTitle>Model denied: {llmHint}</AlertTitle>
          <AlertDescription>
            Models are gated per-agent (allowed_models) and globally by
            blocked_patterns in the data document — adjust those, not this
            agent&apos;s tool rules.
          </AlertDescription>
        </Alert>
      ) : null}

      {savedError ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Engine rejected the document — nothing was changed</AlertTitle>
          <AlertDescription className="font-mono text-xs">
            {savedError}
          </AlertDescription>
        </Alert>
      ) : null}

      {/* 9B Connect Section */}
      <Card className="border-primary/20 bg-card">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="size-4 text-primary" />
              <CardTitle className="text-sm font-semibold">Connect</CardTitle>
            </div>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 text-xs gap-1"
              onClick={copyCurl}
            >
              {copiedCurl ? <Check className="size-3 text-success" /> : <Copy className="size-3" />}
              {copiedCurl ? "Tersalin" : "Salin cURL"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-2 text-xs">
          <p className="text-muted-foreground leading-relaxed">
            Kredensial agen adalah <strong>Key ID</strong> (<code>{keyId}</code>). Header yang dikenali gateway:{" "}
            <code>X-Cerberus-Key</code>, <code>X-Policy-Key</code>, <code>Proxy-Authorization</code>, atau{" "}
            <code>Authorization: Bearer &lt;key_id&gt;</code>. Admin API menggunakan token admin (<code>CERBERUS_ADMIN_TOKEN</code>).
          </p>
          <pre className="rounded bg-muted/50 p-2.5 font-mono text-xs overflow-x-auto select-all text-foreground border">
            {curlSnippet}
          </pre>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Identity</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <label className="space-y-1.5">
            <span className="text-sm font-medium">Name</span>
            <Input value={draft.name ?? ""} onChange={(e) => set({ name: e.target.value })} />
          </label>
          <label className="space-y-1.5">
            <span className="text-sm font-medium">Description</span>
            <Input
              value={draft.description ?? ""}
              onChange={(e) => set({ description: e.target.value })}
            />
          </label>
        </CardContent>
      </Card>

      <Tabs defaultValue="tools">
        <TabsList>
          <TabsTrigger value="tools">Tools</TabsTrigger>
          <TabsTrigger value="constraints">Constraints</TabsTrigger>
          <TabsTrigger value="masking">Masking</TabsTrigger>
          <TabsTrigger value="models">Models & Budget</TabsTrigger>
          <TabsTrigger value="decisions">Decisions</TabsTrigger>
        </TabsList>

        <TabsContent value="tools" className="space-y-4">
          <StringListEditor
            label="allowed_tools"
            hint="exact match, case-sensitive"
            values={list("allowed_tools")}
            onChange={(v) => set({ allowed_tools: v })}
            suggestions={KNOWN_TOOLS}
          />
          <StringListEditor
            label="restricted_tools"
            hint="exact match; restricted always wins"
            values={list("restricted_tools")}
            onChange={(v) => set({ restricted_tools: v })}
          />
          <StringListEditor
            label="allowed_tool_calls"
            hint="glob: trailing * = prefix, else substring (case-insensitive)"
            values={list("allowed_tool_calls")}
            onChange={(v) => set({ allowed_tool_calls: v })}
          />
          <StringListEditor
            label="restricted_tool_calls"
            hint="glob; restricted always wins"
            values={list("restricted_tool_calls")}
            onChange={(v) => set({ restricted_tool_calls: v })}
          />
        </TabsContent>

        <TabsContent value="constraints">
          <ConstraintsEditor
            value={draft.tool_argument_constraints ?? {}}
            onChange={(tool_argument_constraints) => set({ tool_argument_constraints })}
          />
        </TabsContent>

        <TabsContent value="masking" className="space-y-3">
          <MaskingEditor
            value={draft.masking ?? []}
            onChange={(masking) => set({ masking })}
          />
        </TabsContent>

        <TabsContent value="models" className="space-y-4">
          <StringListEditor
            label="allowed_models"
            hint="gates the llm stage alongside the team's list"
            values={list("allowed_models")}
            onChange={(v) => set({ allowed_models: v })}
            suggestions={KNOWN_MODELS}
          />
          <div className="grid gap-4 sm:grid-cols-3">
            <label className="space-y-1.5">
              <span className="text-sm font-medium">Budget limit</span>
              <Input
                type="number"
                value={draft.budget_limit ?? ""}
                onChange={(e) =>
                  set({
                    budget_limit:
                      e.target.value === "" ? undefined : Number(e.target.value),
                  })
                }
              />
            </label>
            <label className="space-y-1.5">
              <span className="text-sm font-medium">Risk tier</span>
              <Select
                value={draft.risk_tier ?? ""}
                onValueChange={(v) => set({ risk_tier: v })}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="—" />
                </SelectTrigger>
                <SelectContent>
                  {["low", "medium", "high"].map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </label>
            <label className="space-y-1.5">
              <span className="text-sm font-medium">Log level</span>
              <Select
                value={draft.log_level ?? ""}
                onValueChange={(v) => set({ log_level: v })}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="—" />
                </SelectTrigger>
                <SelectContent>
                  {["full", "basic", "off"].map((l) => (
                    <SelectItem key={l} value={l}>
                      {l}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </label>
          </div>
        </TabsContent>

        <TabsContent value="decisions">
          <AgentDecisionsTab keyId={keyId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// tool → arg → constraint form. Bare arrays and the three tagged forms get
// native editors; anything else (future form) edits as raw JSON so the
// round-trip never loses it. Computed-key spreads widen to unknown, so the
// two container boundaries carry a targeted cast.
function ConstraintsEditor({
  value,
  onChange,
}: {
  value: NonNullable<Agent["tool_argument_constraints"]>;
  onChange: (v: NonNullable<Agent["tool_argument_constraints"]>) => void;
}) {
  const [newTool, setNewTool] = useState("");
  const [newArg, setNewArg] = useState("");
  const add = () => {
    const tool = newTool.trim();
    const arg = newArg.trim();
    if (!tool || !arg) return;
    // New constraints start as the bare-array form; ConstraintRow's editor
    // takes it from there.
    onChange({ ...value, [tool]: { ...(value[tool] ?? {}), [arg]: [] } } as typeof value);
    setNewTool("");
    setNewArg("");
  };
  return (
    <div className="space-y-4">
      <div className="flex items-end gap-2">
        <label className="space-y-1.5">
          <span className="text-sm font-medium">Tool</span>
          <Input
            className="font-mono w-52"
            placeholder="tool_call"
            value={newTool}
            onChange={(e) => setNewTool(e.target.value)}
          />
        </label>
        <label className="space-y-1.5">
          <span className="text-sm font-medium">Argument</span>
          <Input
            className="font-mono w-52"
            placeholder="argument"
            value={newArg}
            onChange={(e) => setNewArg(e.target.value)}
          />
        </label>
        <Button variant="outline" size="sm" onClick={add} disabled={!newTool.trim() || !newArg.trim()}>
          <Plus />
          Add constraint
        </Button>
      </div>
      {Object.keys(value).length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No constraints — every argument of every tool is unconstrained.
        </p>
      ) : null}
      {Object.entries(value).map(([tool, args]) => (
        <Card key={tool}>
          <CardHeader>
            <CardTitle className="font-mono text-sm">{tool}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(args).map(([arg, form]) => (
              <ConstraintRow
                key={arg}
                arg={arg}
                form={form}
                onChange={(next) =>
                  onChange({ ...value, [tool]: { ...args, [arg]: next } } as typeof value)
                }
                onRemove={() => {
                  const { [arg]: _drop, ...rest } = args;
                  void _drop;
                  onChange({ ...value, [tool]: rest } as typeof value);
                }}
              />
            ))}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ConstraintRow({
  arg,
  form,
  onChange,
  onRemove,
}: {
  arg: string;
  form: unknown;
  onChange: (next: unknown) => void;
  onRemove: () => void;
}) {
  if (Array.isArray(form)) {
    return (
      <StringListEditor
        label={arg}
        hint="bare-array allowlist"
        values={form}
        onChange={onChange}
        onRemove={onRemove}
      />
    );
  }
  const t = (form as { type?: string })?.type;
  if (t === "allowlist" || t === "regex_allow") {
    return (
      <StringListEditor
        label={arg}
        hint={t}
        values={(form as { values?: string[]; patterns?: string[] }).values ??
          (form as { patterns?: string[] }).patterns ??
          []}
        onChange={(v) =>
          onChange(t === "allowlist" ? { type: "allowlist", values: v } : { type: "regex_allow", patterns: v })
        }
        onRemove={onRemove}
      />
    );
  }
  if (t === "range") {
    const r = form as { min: number; max: number };
    return (
      <div className="space-y-1.5">
        <div className="flex items-baseline justify-between">
          <label className="text-sm font-medium">{arg}</label>
          <button type="button" onClick={onRemove} className="text-xs text-muted-foreground">
            remove
          </button>
        </div>
        <div className="flex items-center gap-2">
          <Input
            type="number"
            value={r.min}
            onChange={(e) => onChange({ ...r, min: Number(e.target.value) })}
          />
          <span className="text-muted-foreground">…</span>
          <Input
            type="number"
            value={r.max}
            onChange={(e) => onChange({ ...r, max: Number(e.target.value) })}
          />
        </div>
      </div>
    );
  }
  // Unknown form: raw JSON editing, engine decides what it means.
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between">
        <label className="text-sm font-medium font-mono">{arg}</label>
        <button type="button" onClick={onRemove} className="text-xs text-muted-foreground">
          remove
        </button>
      </div>
      <Textarea
        className="font-mono text-xs"
        defaultValue={JSON.stringify(form, null, 2)}
        onBlur={(e) => {
          try {
            onChange(JSON.parse(e.target.value));
          } catch {
            // keep the last valid value; invalid JSON is not saved
          }
        }}
      />
    </div>
  );
}

function MaskingEditor({
  value,
  onChange,
}: {
  value: MaskingRule[];
  onChange: (v: MaskingRule[]) => void;
}) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        Regex rules applied to args/response before the decision leaves the engine
        (scope both = args + response).
      </p>
      {value.map((rule, i) => (
        <div key={i} className="flex items-center gap-2">
          <Input
            className="font-mono flex-1"
            value={rule.pattern}
            aria-label="pattern"
            onChange={(e) => {
              const next = [...value];
              next[i] = { ...rule, pattern: e.target.value };
              onChange(next);
            }}
          />
          <Select
            value={rule.transform}
            onValueChange={(v) => {
              const next = [...value];
              next[i] = { ...rule, transform: v as MaskingRule["transform"] };
              onChange(next);
            }}
          >
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TRANSFORMS.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={rule.scope === undefined || rule.scope === "" ? "both" : rule.scope}
            onValueChange={(v) => {
              const next = [...value];
              // "" (both) is stored as absent — the engine treats absence
              // and "" identically; absence round-trips cleaner.
              const scope = v === "both" ? undefined : (v as MaskingRule["scope"]);
              next[i] = scope ? { ...rule, scope } : { ...rule, scope: undefined };
              onChange(next);
            }}
          >
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SCOPES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Remove rule"
            onClick={() => onChange(value.filter((_, j) => j !== i))}
          >
            <X aria-hidden />
          </Button>
        </div>
      ))}
      <Button
        variant="outline"
        size="sm"
        onClick={() => onChange([...value, { pattern: "", transform: "redact" }])}
      >
        <Plus aria-hidden /> Add rule
      </Button>
    </div>
  );
}
