"use client";

import { useMemo, useState } from "react";
import { toast } from "sonner";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Plus,
  RotateCcw,
  Shield,
  Sparkles,
  X,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useSaveAgent } from "@/lib/queries";
import type { Agent, Team } from "@/lib/schema";

interface AddAgentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  teams?: Record<string, Team>;
}

type PolicyType = "open" | "readonly" | "custom";

function generateSuffix(): string {
  return Math.random().toString(36).substring(2, 6);
}

function toSlug(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function AddAgentDialog({ open, onOpenChange, teams }: AddAgentDialogProps) {
  const saveAgent = useSaveAgent();

  const [step, setStep] = useState<1 | 2 | 3 | "success">(1);
  const [name, setName] = useState("");
  const [teamId, setTeamId] = useState<string>("__none__");
  const [suffix, setSuffix] = useState<string>(generateSuffix);
  const [customKey, setCustomKey] = useState<string>("");
  const [isKeyManuallyEdited, setIsKeyManuallyEdited] = useState(false);

  // Step 2: Policy
  const [policyType, setPolicyType] = useState<PolicyType>("open");
  const [allowedToolCalls, setAllowedToolCalls] = useState<string[]>([]);
  const [toolInput, setToolInput] = useState("");
  const [budgetLimit, setBudgetLimit] = useState("");
  const [requestsPerMinute, setRequestsPerMinute] = useState("");

  const [saveError, setSaveError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);

  // Auto-generate key: k- + slug(name) + - + suffix
  const autoKey = useMemo(() => {
    const slug = toSlug(name) || "agent";
    return `k-${slug}-${suffix}`;
  }, [name, suffix]);

  const activeKeyId = isKeyManuallyEdited && customKey.trim() ? customKey.trim() : autoKey;

  const handleRegenerateSuffix = () => {
    const newSuffix = generateSuffix();
    setSuffix(newSuffix);
    if (!isKeyManuallyEdited) {
      // kept in sync via autoKey
    } else {
      const slug = toSlug(name) || "agent";
      setCustomKey(`k-${slug}-${newSuffix}`);
    }
  };

  const handleAddTool = () => {
    const trimmed = toolInput.trim();
    if (!trimmed) return;
    if (!allowedToolCalls.includes(trimmed)) {
      setAllowedToolCalls([...allowedToolCalls, trimmed]);
    }
    setToolInput("");
  };

  const handleRemoveTool = (tool: string) => {
    setAllowedToolCalls(allowedToolCalls.filter((t) => t !== tool));
  };

  const handleReset = () => {
    setStep(1);
    setName("");
    setTeamId("__none__");
    setSuffix(generateSuffix());
    setCustomKey("");
    setIsKeyManuallyEdited(false);
    setPolicyType("open");
    setAllowedToolCalls([]);
    setToolInput("");
    setBudgetLimit("");
    setRequestsPerMinute("");
    setSaveError(null);
    setCopiedKey(false);
    setCopiedCurl(false);
  };

  const handleOpenChange = (nextOpen: boolean) => {
    if (!nextOpen) {
      handleReset();
    }
    onOpenChange(nextOpen);
  };

  const curlSnippet = useMemo(() => {
    return `curl -X POST $CERBERUS_URL/v1/decide/tool \\
  -H "X-Cerberus-Key: ${activeKeyId}" \\
  -H "Content-Type: application/json" \\
  -d '{"stage":"tool","key_id":"${activeKeyId}","action":"read","resource":"x"}'`;
  }, [activeKeyId]);

  const handleCreateAgent = async () => {
    setSaveError(null);
    try {
      const newAgent: Agent = {
        name: name.trim(),
      };

      if (teamId && teamId !== "__none__") {
        newAgent.team_id = teamId;
      }

      if (policyType === "readonly") {
        newAgent.allowed_tool_calls = ["read*", "get*", "list*", "search*"];
      } else if (policyType === "custom") {
        if (allowedToolCalls.length > 0) {
          newAgent.allowed_tool_calls = allowedToolCalls;
        }
        if (budgetLimit.trim() && !isNaN(Number(budgetLimit))) {
          newAgent.budget_limit = Number(budgetLimit);
        }
        if (requestsPerMinute.trim() && !isNaN(Number(requestsPerMinute))) {
          newAgent.rate_limit = {
            requests_per_minute: Number(requestsPerMinute),
          };
        }
      }

      await saveAgent.mutateAsync({
        keyId: activeKeyId,
        agent: newAgent,
      });

      setStep("success");
      toast.success(`Agent ${name} berhasil didaftarkan!`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Gagal membuat agent";
      setSaveError(msg);
    }
  };

  const copyToClipboard = async (text: string, type: "key" | "curl") => {
    try {
      await navigator.clipboard.writeText(text);
      if (type === "key") {
        setCopiedKey(true);
        setTimeout(() => setCopiedKey(false), 2000);
        toast.success("Key ID disalin ke clipboard!");
      } else {
        setCopiedCurl(true);
        setTimeout(() => setCopiedCurl(false), 2000);
        toast.success("Snippet cURL disalin ke clipboard!");
      }
    } catch {
      toast.error("Gagal menyalin ke clipboard");
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-xl">
        {step !== "success" && (
          <DialogHeader>
            <div className="flex items-center justify-between pr-6">
              <DialogTitle>
                {step === 1 && "Tambah Agent — Langkah 1: Nama & Team"}
                {step === 2 && "Tambah Agent — Langkah 2: Kebijakan"}
                {step === 3 && "Tambah Agent — Langkah 3: Konfirmasi"}
              </DialogTitle>
            </div>
            <DialogDescription>
              {step === 1 && "Tentukan identitas agent dan key autentikasi unik."}
              {step === 2 && "Pilih cakupan kebijakan tool dan batas penggunaan agent."}
              {step === 3 && "Tinjau konfigurasi sebelum mendaftarkan agent ke gateway."}
            </DialogDescription>
            {/* Step indicator bar */}
            <div className="flex items-center gap-1.5 pt-1">
              {[1, 2, 3].map((s) => (
                <div
                  key={s}
                  className={`h-1.5 flex-1 rounded-full transition-colors ${
                    s <= step ? "bg-primary" : "bg-muted"
                  }`}
                />
              ))}
            </div>
          </DialogHeader>
        )}

        {/* STEP 1: Nama & Team */}
        {step === 1 && (
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="agent-name">Nama Agent <span className="text-destructive">*</span></Label>
              <Input
                id="agent-name"
                placeholder="misal: nightly-finder atau qa-test-agent"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (!isKeyManuallyEdited) {
                    setCustomKey("");
                  }
                }}
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                Nama deskriptif untuk mengenali tugas agent ini di dashboard.
              </p>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label htmlFor="agent-key">Key ID (Auto-generated Kredensial)</Label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-6 gap-1 px-1.5 text-xs text-muted-foreground hover:text-foreground"
                  onClick={handleRegenerateSuffix}
                  title="Acak ulang suffix 4 karakter"
                >
                  <RotateCcw className="size-3" />
                  Regenerate Suffix
                </Button>
              </div>
              <div className="relative">
                <Input
                  id="agent-key"
                  className="font-mono text-xs pr-8"
                  value={isKeyManuallyEdited ? customKey : autoKey}
                  placeholder={`k-${toSlug(name) || "agent"}-${suffix}`}
                  onChange={(e) => {
                    setIsKeyManuallyEdited(true);
                    setCustomKey(e.target.value);
                  }}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                Key name otomatis: <code className="font-mono text-primary font-semibold">{activeKeyId}</code>.
                Key ini berfungsi sebagai kredensial autentikasi.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="agent-team">Team (Opsional)</Label>
              <Select value={teamId} onValueChange={setTeamId}>
                <SelectTrigger id="agent-team" className="w-full">
                  <SelectValue placeholder="Pilih team..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none__">Tanpa Team (None)</SelectItem>
                  {teams &&
                    Object.entries(teams).map(([tid, team]) => (
                      <SelectItem key={tid} value={tid}>
                        {team.name ? `${team.name} (${tid})` : tid}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Agent dapat mewarisi batasan tool dan model dari team yang dipilih.
              </p>
            </div>
          </div>
        )}

        {/* STEP 2: Kebijakan */}
        {step === 2 && (
          <div className="space-y-4 py-2">
            <Label className="text-sm font-semibold">Tipe Kebijakan Akses Tool</Label>
            <div className="grid gap-2.5 sm:grid-cols-3">
              <Card
                className={`cursor-pointer transition-all hover:border-primary/50 ${
                  policyType === "open"
                    ? "border-primary bg-primary/5 shadow-xs"
                    : "border-border"
                }`}
                onClick={() => setPolicyType("open")}
              >
                <CardContent className="p-3.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm">Open</span>
                    <Sparkles className="size-4 text-primary" />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Akses terbuka penuh tanpa batasan tool.
                  </p>
                </CardContent>
              </Card>

              <Card
                className={`cursor-pointer transition-all hover:border-primary/50 ${
                  policyType === "readonly"
                    ? "border-primary bg-primary/5 shadow-xs"
                    : "border-border"
                }`}
                onClick={() => setPolicyType("readonly")}
              >
                <CardContent className="p-3.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm">Read-only</span>
                    <Shield className="size-4 text-emerald-600 dark:text-emerald-400" />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Hanya tool pembacaan (read*, get*, list*, search*).
                  </p>
                </CardContent>
              </Card>

              <Card
                className={`cursor-pointer transition-all hover:border-primary/50 ${
                  policyType === "custom"
                    ? "border-primary bg-primary/5 shadow-xs"
                    : "border-border"
                }`}
                onClick={() => setPolicyType("custom")}
              >
                <CardContent className="p-3.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm">Custom</span>
                    <Badge variant="outline" className="text-[10px] px-1 py-0">Custom</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Atur allowed tools, budget limit, dan rate limit.
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Custom fields */}
            {policyType === "custom" && (
              <div className="space-y-4 rounded-lg border p-3.5 bg-muted/20">
                <div className="space-y-2">
                  <Label className="text-xs font-semibold">
                    Allowed Tool Calls (Chips Input)
                  </Label>
                  <div className="flex flex-wrap gap-1.5 min-h-[32px] p-2 rounded-md border bg-background">
                    {allowedToolCalls.length === 0 ? (
                      <span className="text-xs text-muted-foreground italic px-1">
                        Belum ada pola tool (semua tool diizinkan jika kosong)
                      </span>
                    ) : (
                      allowedToolCalls.map((tool) => (
                        <Badge
                          key={tool}
                          variant="secondary"
                          className="font-mono text-xs gap-1 pr-1"
                        >
                          {tool}
                          <button
                            type="button"
                            onClick={() => handleRemoveTool(tool)}
                            className="rounded-full hover:bg-muted p-0.5"
                          >
                            <X className="size-3" />
                          </button>
                        </Badge>
                      ))
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="misal: web_search* atau bash"
                      value={toolInput}
                      onChange={(e) => setToolInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          handleAddTool();
                        }
                      }}
                      className="h-8 text-xs font-mono"
                    />
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={handleAddTool}
                      disabled={!toolInput.trim()}
                      className="h-8 text-xs shrink-0"
                    >
                      <Plus className="mr-1 size-3.5" />
                      Tambah
                    </Button>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    Gunakan pola glob (* untuk prefix atau substring match).
                  </p>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="agent-budget" className="text-xs">
                      Budget Limit (USD, opsional)
                    </Label>
                    <Input
                      id="agent-budget"
                      type="number"
                      placeholder="misal: 50"
                      value={budgetLimit}
                      onChange={(e) => setBudgetLimit(e.target.value)}
                      className="h-8 text-xs"
                      min={0}
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Label htmlFor="agent-rpm" className="text-xs">
                      Rate Limit (req/menit, opsional)
                    </Label>
                    <Input
                      id="agent-rpm"
                      type="number"
                      placeholder="misal: 60"
                      value={requestsPerMinute}
                      onChange={(e) => setRequestsPerMinute(e.target.value)}
                      className="h-8 text-xs"
                      min={1}
                    />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* STEP 3: Konfirmasi */}
        {step === 3 && (
          <div className="space-y-4 py-2">
            {saveError && (
              <Alert variant="destructive">
                <AlertTriangle className="size-4" />
                <AlertTitle>Gagal Menyimpan</AlertTitle>
                <AlertDescription className="text-xs font-mono">
                  {saveError}
                </AlertDescription>
              </Alert>
            )}

            <Card className="border">
              <CardContent className="p-4 space-y-3 text-sm">
                <div className="flex items-center justify-between pb-2 border-b">
                  <span className="text-muted-foreground text-xs">Key ID</span>
                  <code className="font-mono font-semibold text-primary text-xs">
                    {activeKeyId}
                  </code>
                </div>

                <div className="flex items-center justify-between pb-2 border-b">
                  <span className="text-muted-foreground text-xs">Nama Agent</span>
                  <span className="font-medium text-xs">{name}</span>
                </div>

                <div className="flex items-center justify-between pb-2 border-b">
                  <span className="text-muted-foreground text-xs">Team</span>
                  <span className="text-xs">
                    {teamId && teamId !== "__none__"
                      ? teams?.[teamId]?.name || teamId
                      : "Tanpa Team"}
                  </span>
                </div>

                <div className="flex items-center justify-between pb-2 border-b">
                  <span className="text-muted-foreground text-xs">Tipe Kebijakan</span>
                  <Badge variant="outline" className="capitalize text-xs font-semibold">
                    {policyType}
                  </Badge>
                </div>

                <div className="space-y-1 pb-2 border-b">
                  <span className="text-muted-foreground text-xs block">Tool Rules:</span>
                  <div className="text-xs">
                    {policyType === "open" && (
                      <span className="text-muted-foreground italic">
                        Semua tool diizinkan (Open Access)
                      </span>
                    )}
                    {policyType === "readonly" && (
                      <div className="flex flex-wrap gap-1">
                        {["read*", "get*", "list*", "search*"].map((t) => (
                          <Badge key={t} variant="secondary" className="font-mono text-[10px]">
                            {t}
                          </Badge>
                        ))}
                      </div>
                    )}
                    {policyType === "custom" && (
                      allowedToolCalls.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {allowedToolCalls.map((t) => (
                            <Badge key={t} variant="secondary" className="font-mono text-[10px]">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <span className="text-muted-foreground italic">
                          Semua tool diizinkan
                        </span>
                      )
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground block text-[11px]">Budget Limit</span>
                    <span className="font-medium">
                      {budgetLimit.trim() ? `$${budgetLimit}` : "Tidak dibatasi"}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block text-[11px]">Rate Limit</span>
                    <span className="font-medium">
                      {requestsPerMinute.trim()
                        ? `${requestsPerMinute} req/menit`
                        : "Tidak dibatasi"}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* STEP SUCCESS: Dialog Sukses */}
        {step === "success" && (
          <div className="space-y-4 py-2">
            <DialogHeader>
              <div className="flex items-center gap-2">
                <div className="rounded-full bg-success/15 p-1 text-success">
                  <CheckCircle2 className="size-5" />
                </div>
                <DialogTitle className="text-lg">Agent Berhasil Dibuat!</DialogTitle>
              </div>
              <DialogDescription>
                Agent <strong className="text-foreground">{name}</strong> telah terdaftar di engine gateway.
              </DialogDescription>
            </DialogHeader>

            <Alert className="border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200">
              <AlertTriangle className="size-4 text-amber-600 dark:text-amber-400" />
              <AlertTitle className="font-semibold text-xs">
                Simpan sekarang — key tidak akan ditampilkan lagi
              </AlertTitle>
              <AlertDescription className="text-xs">
                Key ID ini adalah kredensial autentikasi itu sendiri (header <code>X-Cerberus-Key</code> atau <code>Authorization: Bearer</code>). Tidak ada client_id atau client_secret OAuth terpisah.
              </AlertDescription>
            </Alert>

            {/* Key display box */}
            <div className="rounded-lg border bg-muted/40 p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground">Kredensial Agent (Key ID)</span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-7 text-xs gap-1"
                  onClick={() => copyToClipboard(activeKeyId, "key")}
                >
                  {copiedKey ? <Check className="size-3 text-success" /> : <Copy className="size-3" />}
                  {copiedKey ? "Tersalin" : "Salin Key"}
                </Button>
              </div>
              <div className="rounded bg-background p-2 border font-mono text-sm font-bold text-primary break-all select-all">
                {activeKeyId}
              </div>
            </div>

            {/* Ready to use curl snippet */}
            <div className="rounded-lg border bg-muted/40 p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-muted-foreground">Snippet cURL Siap Pakai</span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-7 text-xs gap-1"
                  onClick={() => copyToClipboard(curlSnippet, "curl")}
                >
                  {copiedCurl ? <Check className="size-3 text-success" /> : <Copy className="size-3" />}
                  {copiedCurl ? "Tersalin" : "Salin Snippet"}
                </Button>
              </div>
              <pre className="rounded bg-background p-2.5 border font-mono text-xs overflow-x-auto text-muted-foreground select-all">
                {curlSnippet}
              </pre>
            </div>

            <DialogFooter>
              <Button onClick={() => handleOpenChange(false)} className="w-full sm:w-auto">
                Selesai
              </Button>
            </DialogFooter>
          </div>
        )}

        {/* Standard Wizard Footers */}
        {step !== "success" && (
          <DialogFooter className="gap-2 sm:gap-0">
            {step === 1 && (
              <>
                <Button variant="outline" onClick={() => handleOpenChange(false)}>
                  Batal
                </Button>
                <Button
                  onClick={() => setStep(2)}
                  disabled={!name.trim() || !activeKeyId.trim()}
                >
                  Lanjut ke Kebijakan
                </Button>
              </>
            )}

            {step === 2 && (
              <>
                <Button variant="outline" onClick={() => setStep(1)}>
                  Kembali
                </Button>
                <Button onClick={() => setStep(3)}>
                  Lanjut ke Konfirmasi
                </Button>
              </>
            )}

            {step === 3 && (
              <>
                <Button
                  variant="outline"
                  onClick={() => setStep(2)}
                  disabled={saveAgent.isPending}
                >
                  Kembali
                </Button>
                <Button
                  onClick={handleCreateAgent}
                  disabled={saveAgent.isPending}
                >
                  {saveAgent.isPending ? "Menyimpan..." : "Buat Agent"}
                </Button>
              </>
            )}
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  );
}
