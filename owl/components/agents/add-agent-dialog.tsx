"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { toast } from "sonner";
import {
  AlertTriangle,
  Bookmark,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  ExternalLink,
  Plus,
  RotateCcw,
  Sliders,
  Trash2,
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
import {
  BUILTIN_TEMPLATES,
  deleteCustomTemplate,
  getCustomTemplates,
  getTemplateIcon,
  saveCustomTemplate,
  type PolicyTemplate,
} from "./policy-templates";

interface AddAgentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  teams?: Record<string, Team>;
  initialKeyId?: string;
}

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

export function AddAgentDialog({ open, onOpenChange, teams, initialKeyId }: AddAgentDialogProps) {
  const saveAgent = useSaveAgent();

  const [step, setStep] = useState<1 | 2 | 3 | "success">(1);
  const [name, setName] = useState("");
  const [teamId, setTeamId] = useState<string>("__none__");
  const [suffix, setSuffix] = useState<string>(generateSuffix);
  const [customKey, setCustomKey] = useState<string>("");
  const [isKeyManuallyEdited, setIsKeyManuallyEdited] = useState(false);

  useEffect(() => {
    if (initialKeyId && open) {
      setName(initialKeyId);
      setCustomKey(initialKeyId);
      setIsKeyManuallyEdited(true);
    }
  }, [initialKeyId, open]);

  // Step 2: Policy & Templates
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>("open");
  const [customTemplates, setCustomTemplates] = useState<PolicyTemplate[]>([]);

  // Draft editable fields (starts with selected template payload)
  const [allowedToolCalls, setAllowedToolCalls] = useState<string[]>([]);
  const [restrictedToolCalls, setRestrictedToolCalls] = useState<string[]>([]);
  const [allowedModels, setAllowedModels] = useState<string[]>([]);
  const [budgetLimit, setBudgetLimit] = useState("");
  const [requestsPerMinute, setRequestsPerMinute] = useState("");
  const [prodAccess, setProdAccess] = useState<boolean | undefined>(undefined);

  // Inline input states
  const [allowedToolInput, setAllowedToolInput] = useState("");
  const [restrictedToolInput, setRestrictedToolInput] = useState("");
  const [modelInput, setModelInput] = useState("");
  const [isDetailsOpen, setIsDetailsOpen] = useState(false);

  // Step 3: Save as custom template state
  const [isSavingCustom, setIsSavingCustom] = useState(false);
  const [customTemplateName, setCustomTemplateName] = useState("");
  const [savedTemplateSuccess, setSavedTemplateSuccess] = useState<string | null>(null);

  const [saveError, setSaveError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);

  // Sync custom templates from localStorage when dialog opens
  useEffect(() => {
    if (open) {
      setCustomTemplates(getCustomTemplates());
    }
  }, [open]);

  // Auto-generate key: k- + slug(name) + - + suffix
  const autoKey = useMemo(() => {
    const slug = toSlug(name) || "agent";
    return `k-${slug}-${suffix}`;
  }, [name, suffix]);

  const activeKeyId = isKeyManuallyEdited && customKey.trim() ? customKey.trim() : autoKey;

  const handleRegenerateSuffix = () => {
    const newSuffix = generateSuffix();
    setSuffix(newSuffix);
    if (isKeyManuallyEdited) {
      const slug = toSlug(name) || "agent";
      setCustomKey(`k-${slug}-${newSuffix}`);
    }
  };

  const handleSelectTemplate = (template: PolicyTemplate) => {
    setSelectedTemplateId(template.id);
    const p = template.payload;
    setAllowedToolCalls(p.allowed_tool_calls ? [...p.allowed_tool_calls] : []);
    setRestrictedToolCalls(p.restricted_tool_calls ? [...p.restricted_tool_calls] : []);
    setAllowedModels(p.allowed_models ? [...p.allowed_models] : []);
    setBudgetLimit(p.budget_limit !== undefined ? String(p.budget_limit) : "");
    setRequestsPerMinute(
      p.rate_limit?.requests_per_minute !== undefined
        ? String(p.rate_limit.requests_per_minute)
        : ""
    );
    setProdAccess(p.prod_access);
    setSavedTemplateSuccess(null);
  };

  const handleAddAllowedTool = () => {
    const trimmed = allowedToolInput.trim();
    if (!trimmed) return;
    if (!allowedToolCalls.includes(trimmed)) {
      setAllowedToolCalls([...allowedToolCalls, trimmed]);
    }
    setAllowedToolInput("");
  };

  const handleRemoveAllowedTool = (tool: string) => {
    setAllowedToolCalls(allowedToolCalls.filter((t) => t !== tool));
  };

  const handleAddRestrictedTool = () => {
    const trimmed = restrictedToolInput.trim();
    if (!trimmed) return;
    if (!restrictedToolCalls.includes(trimmed)) {
      setRestrictedToolCalls([...restrictedToolCalls, trimmed]);
    }
    setRestrictedToolInput("");
  };

  const handleRemoveRestrictedTool = (tool: string) => {
    setRestrictedToolCalls(restrictedToolCalls.filter((t) => t !== tool));
  };

  const handleAddModel = () => {
    const trimmed = modelInput.trim();
    if (!trimmed) return;
    if (!allowedModels.includes(trimmed)) {
      setAllowedModels([...allowedModels, trimmed]);
    }
    setModelInput("");
  };

  const handleRemoveModel = (m: string) => {
    setAllowedModels(allowedModels.filter((item) => item !== m));
  };

  const handleDeleteCustom = (id: string) => {
    deleteCustomTemplate(id);
    const updated = getCustomTemplates();
    setCustomTemplates(updated);
    if (selectedTemplateId === id) {
      handleSelectTemplate(BUILTIN_TEMPLATES[0]);
    }
    toast.success("Template kustom dihapus.");
  };

  const handleSaveAsTemplate = () => {
    if (!customTemplateName.trim()) {
      toast.error("Nama template wajib diisi");
      return;
    }

    const payload: Partial<Agent> = {};
    if (allowedToolCalls.length > 0) payload.allowed_tool_calls = allowedToolCalls;
    if (restrictedToolCalls.length > 0) payload.restricted_tool_calls = restrictedToolCalls;
    if (allowedModels.length > 0) payload.allowed_models = allowedModels;
    if (budgetLimit.trim() && !isNaN(Number(budgetLimit))) payload.budget_limit = Number(budgetLimit);
    if (requestsPerMinute.trim() && !isNaN(Number(requestsPerMinute))) {
      payload.rate_limit = { requests_per_minute: Number(requestsPerMinute) };
    }
    if (prodAccess !== undefined) payload.prod_access = prodAccess;

    const saved = saveCustomTemplate(customTemplateName, payload);
    setCustomTemplates(getCustomTemplates());
    setSelectedTemplateId(saved.id);
    setSavedTemplateSuccess(saved.name);
    setIsSavingCustom(false);
    setCustomTemplateName("");
    toast.success(`Template "${saved.name}" berhasil disimpan!`);
  };

  const handleReset = () => {
    setStep(1);
    setName("");
    setTeamId("__none__");
    setSuffix(generateSuffix());
    setCustomKey("");
    setIsKeyManuallyEdited(false);
    setSelectedTemplateId("open");
    setAllowedToolCalls([]);
    setRestrictedToolCalls([]);
    setAllowedModels([]);
    setBudgetLimit("");
    setRequestsPerMinute("");
    setProdAccess(undefined);
    setAllowedToolInput("");
    setRestrictedToolInput("");
    setModelInput("");
    setIsDetailsOpen(false);
    setIsSavingCustom(false);
    setCustomTemplateName("");
    setSavedTemplateSuccess(null);
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

  const selectedTemplate = useMemo(() => {
    const custom = customTemplates.find((t) => t.id === selectedTemplateId);
    if (custom) return custom;
    return BUILTIN_TEMPLATES.find((t) => t.id === selectedTemplateId) || BUILTIN_TEMPLATES[0];
  }, [selectedTemplateId, customTemplates]);

  const handleCreateAgent = async () => {
    setSaveError(null);
    try {
      const newAgent: Agent = {
        name: name.trim(),
      };

      if (teamId && teamId !== "__none__") {
        newAgent.team_id = teamId;
      }

      if (allowedToolCalls.length > 0) {
        newAgent.allowed_tool_calls = allowedToolCalls;
      }

      if (restrictedToolCalls.length > 0) {
        newAgent.restricted_tool_calls = restrictedToolCalls;
      }

      if (allowedModels.length > 0) {
        newAgent.allowed_models = allowedModels;
      }

      if (budgetLimit.trim() && !isNaN(Number(budgetLimit))) {
        newAgent.budget_limit = Number(budgetLimit);
      }

      if (requestsPerMinute.trim() && !isNaN(Number(requestsPerMinute))) {
        newAgent.rate_limit = {
          requests_per_minute: Number(requestsPerMinute),
        };
      }

      if (prodAccess !== undefined) {
        newAgent.prod_access = prodAccess;
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
      <DialogContent className="sm:max-w-2xl max-h-[92vh] flex flex-col p-6">
        {step !== "success" && (
          <DialogHeader className="shrink-0">
            <div className="flex items-center justify-between pr-6">
              <DialogTitle>
                {step === 1 && "Tambah Agent — Langkah 1: Nama & Team"}
                {step === 2 && "Tambah Agent — Langkah 2: Template Kebijakan"}
                {step === 3 && "Tambah Agent — Langkah 3: Konfirmasi"}
              </DialogTitle>
            </div>
            <DialogDescription>
              {step === 1 && "Tentukan identitas agent dan key autentikasi unik."}
              {step === 2 && "Pilih galeri preset kebijakan atau sesuaikan parameter secara inline."}
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

        <div className="flex-1 overflow-y-auto pr-1">
          {/* STEP 1: Nama & Team */}
          {step === 1 && (
            <div className="space-y-4 py-2">
              <div className="space-y-1.5">
                <Label htmlFor="agent-name">
                  Nama Agent <span className="text-destructive">*</span>
                </Label>
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
                  Key name otomatis:{" "}
                  <code className="font-mono text-primary font-semibold">{activeKeyId}</code>. Key ini
                  berfungsi sebagai kredensial autentikasi.
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

          {/* STEP 2: Template Gallery & Inline Edit */}
          {step === 2 && (
            <div className="space-y-4 py-2">
              {/* Section 1: Template Kamu (jika ada custom templates) */}
              {customTemplates.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      Template Kamu ({customTemplates.length})
                    </Label>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {customTemplates.map((template) => {
                      const Icon = getTemplateIcon(template.icon);
                      const isSelected = selectedTemplateId === template.id;
                      return (
                        <Card
                          key={template.id}
                          className={`cursor-pointer transition-all hover:border-primary/60 ${
                            isSelected
                              ? "border-primary bg-primary/5 shadow-xs ring-1 ring-primary"
                              : "border-border"
                          }`}
                          onClick={() => handleSelectTemplate(template)}
                        >
                          <CardContent className="p-3 space-y-1">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-1.5">
                                <Icon className="size-4 text-primary shrink-0" />
                                <span className="font-semibold text-xs text-foreground">
                                  {template.name}
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleDeleteCustom(template.id);
                                }}
                                className="text-muted-foreground hover:text-destructive p-1 rounded transition-colors"
                                title="Hapus template kustom"
                              >
                                <Trash2 className="size-3.5" />
                              </button>
                            </div>
                            <p className="text-[11px] text-muted-foreground line-clamp-1">
                              {template.description}
                            </p>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Section 2: Galeri Template Bawaan (Built-in) */}
              <div className="space-y-2">
                <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Template Galeri ({BUILTIN_TEMPLATES.length} bawaan)
                </Label>
                <div className="grid gap-2 sm:grid-cols-2 max-h-[220px] overflow-y-auto pr-1">
                  {BUILTIN_TEMPLATES.map((template) => {
                    const Icon = getTemplateIcon(template.icon);
                    const isSelected = selectedTemplateId === template.id;
                    return (
                      <Card
                        key={template.id}
                        className={`cursor-pointer transition-all hover:border-primary/60 ${
                          isSelected
                            ? "border-primary bg-primary/5 shadow-xs ring-1 ring-primary"
                            : "border-border"
                        }`}
                        onClick={() => handleSelectTemplate(template)}
                      >
                        <CardContent className="p-3 space-y-1">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-1.5">
                              <Icon className="size-4 text-primary shrink-0" />
                              <span className="font-semibold text-xs text-foreground">
                                {template.name}
                              </span>
                            </div>
                            {isSelected && <Badge variant="secondary" className="text-[10px] py-0 px-1 font-normal">Dipilih</Badge>}
                          </div>
                          <p className="text-[11px] text-muted-foreground line-clamp-2">
                            {template.description}
                          </p>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              </div>

              {/* Collapsible: Lihat / Ubah Detail */}
              <div className="rounded-lg border bg-muted/20">
                <button
                  type="button"
                  onClick={() => setIsDetailsOpen(!isDetailsOpen)}
                  className="w-full flex items-center justify-between p-3 text-xs font-medium hover:bg-muted/40 transition-colors rounded-lg"
                >
                  <div className="flex items-center gap-2 text-left">
                    <Sliders className="size-3.5 text-primary" />
                    <span className="font-semibold text-foreground">Lihat / ubah detail kebijakan</span>
                    <span className="text-[11px] text-muted-foreground hidden sm:inline">
                      ({allowedToolCalls.length} allow, {restrictedToolCalls.length} restricted,{" "}
                      {requestsPerMinute ? `${requestsPerMinute} rpm` : "unlimited rpm"},{" "}
                      {budgetLimit ? `$${budgetLimit}` : "no budget"})
                    </span>
                  </div>
                  {isDetailsOpen ? (
                    <ChevronUp className="size-4 text-muted-foreground shrink-0" />
                  ) : (
                    <ChevronDown className="size-4 text-muted-foreground shrink-0" />
                  )}
                </button>

                {isDetailsOpen && (
                  <div className="p-3.5 pt-0 space-y-3.5 border-t mt-1">
                    {/* Allowed Tool Calls */}
                    <div className="space-y-1.5 pt-2">
                      <Label className="text-xs font-semibold">Allowed Tool Calls (Allowlist)</Label>
                      <div className="flex flex-wrap gap-1 min-h-[30px] p-2 rounded-md border bg-background">
                        {allowedToolCalls.length === 0 ? (
                          <span className="text-xs text-muted-foreground italic px-1">
                            Semua tool diizinkan jika daftar kosong.
                          </span>
                        ) : (
                          allowedToolCalls.map((tool) => (
                            <Badge key={tool} variant="secondary" className="font-mono text-xs gap-1 pr-1">
                              {tool}
                              <button
                                type="button"
                                onClick={() => handleRemoveAllowedTool(tool)}
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
                          placeholder="misal: http_get atau search*"
                          value={allowedToolInput}
                          onChange={(e) => setAllowedToolInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              handleAddAllowedTool();
                            }
                          }}
                          className="h-8 text-xs font-mono"
                        />
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={handleAddAllowedTool}
                          disabled={!allowedToolInput.trim()}
                          className="h-8 text-xs shrink-0"
                        >
                          <Plus className="mr-1 size-3.5" />
                          Tambah
                        </Button>
                      </div>
                    </div>

                    {/* Restricted Tool Calls */}
                    <div className="space-y-1.5">
                      <Label className="text-xs font-semibold">Restricted Tool Calls (Denylist)</Label>
                      <div className="flex flex-wrap gap-1 min-h-[30px] p-2 rounded-md border bg-background">
                        {restrictedToolCalls.length === 0 ? (
                          <span className="text-xs text-muted-foreground italic px-1">
                            Tidak ada pola tool yang diblokir khusus.
                          </span>
                        ) : (
                          restrictedToolCalls.map((tool) => (
                            <Badge
                              key={tool}
                              variant="destructive"
                              className="font-mono text-xs gap-1 pr-1"
                            >
                              {tool}
                              <button
                                type="button"
                                onClick={() => handleRemoveRestrictedTool(tool)}
                                className="rounded-full hover:bg-destructive/80 p-0.5 text-destructive-foreground"
                              >
                                <X className="size-3" />
                              </button>
                            </Badge>
                          ))
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <Input
                          placeholder="misal: *exec* atau ssh*"
                          value={restrictedToolInput}
                          onChange={(e) => setRestrictedToolInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              handleAddRestrictedTool();
                            }
                          }}
                          className="h-8 text-xs font-mono"
                        />
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={handleAddRestrictedTool}
                          disabled={!restrictedToolInput.trim()}
                          className="h-8 text-xs shrink-0"
                        >
                          <Plus className="mr-1 size-3.5" />
                          Tambah
                        </Button>
                      </div>
                    </div>

                    {/* Allowed Models */}
                    <div className="space-y-1.5">
                      <Label className="text-xs font-semibold">Allowed Models (Allowlist LLM)</Label>
                      <div className="flex flex-wrap gap-1 min-h-[30px] p-2 rounded-md border bg-background">
                        {allowedModels.length === 0 ? (
                          <span className="text-xs text-muted-foreground italic px-1">
                            Semua model LLM diizinkan.
                          </span>
                        ) : (
                          allowedModels.map((m) => (
                            <Badge key={m} variant="outline" className="font-mono text-xs gap-1 pr-1">
                              {m}
                              <button
                                type="button"
                                onClick={() => handleRemoveModel(m)}
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
                          placeholder="misal: *mini*, *flash*, atau *"
                          value={modelInput}
                          onChange={(e) => setModelInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              handleAddModel();
                            }
                          }}
                          className="h-8 text-xs font-mono"
                        />
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={handleAddModel}
                          disabled={!modelInput.trim()}
                          className="h-8 text-xs shrink-0"
                        >
                          <Plus className="mr-1 size-3.5" />
                          Tambah
                        </Button>
                      </div>
                    </div>

                    {/* Budget & Rate & Prod Access */}
                    <div className="grid gap-3 sm:grid-cols-3">
                      <div className="space-y-1">
                        <Label htmlFor="agent-budget" className="text-xs">
                          Budget Limit (USD)
                        </Label>
                        <Input
                          id="agent-budget"
                          type="number"
                          placeholder="misal: 10"
                          value={budgetLimit}
                          onChange={(e) => setBudgetLimit(e.target.value)}
                          className="h-8 text-xs"
                          min={0}
                        />
                      </div>

                      <div className="space-y-1">
                        <Label htmlFor="agent-rpm" className="text-xs">
                          Rate Limit (rpm)
                        </Label>
                        <Input
                          id="agent-rpm"
                          type="number"
                          placeholder="misal: 120"
                          value={requestsPerMinute}
                          onChange={(e) => setRequestsPerMinute(e.target.value)}
                          className="h-8 text-xs"
                          min={1}
                        />
                      </div>

                      <div className="space-y-1">
                        <Label htmlFor="agent-prod-access" className="text-xs">
                          Prod Access
                        </Label>
                        <Select
                          value={
                            prodAccess === true ? "true" : prodAccess === false ? "false" : "default"
                          }
                          onValueChange={(val) => {
                            if (val === "true") setProdAccess(true);
                            else if (val === "false") setProdAccess(false);
                            else setProdAccess(undefined);
                          }}
                        >
                          <SelectTrigger id="agent-prod-access" className="h-8 text-xs w-full">
                            <SelectValue placeholder="Default" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="default">Default (Sesuai Gate)</SelectItem>
                            <SelectItem value="true">Diizinkan (true)</SelectItem>
                            <SelectItem value="false">Dilarang (false)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* 11D — Rego hint jujur */}
              <div className="text-xs text-muted-foreground pt-1 border-t leading-relaxed">
                Template mengatur data kebijakan (tool allowlist, budget, rate, model). Logika baru (stage/host/database) tetap lewat file rego — lihat{" "}
                <code className="text-[11px] font-mono font-medium">docs/INTEGRATION.md</code> atau kunjungi{" "}
                <Link
                  href="/docs-intro"
                  target="_blank"
                  className="underline text-primary hover:text-primary/80 font-medium inline-flex items-center gap-0.5"
                >
                  /docs-intro
                  <ExternalLink className="size-2.5 inline" />
                </Link>.
              </div>
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
                    <span className="text-muted-foreground text-xs">Basis Template</span>
                    <Badge variant="outline" className="capitalize text-xs font-semibold gap-1">
                      {selectedTemplate.name}
                    </Badge>
                  </div>

                  {/* Allowed Tool Calls */}
                  <div className="space-y-1 pb-2 border-b">
                    <span className="text-muted-foreground text-xs block">Tool Allowlist:</span>
                    <div className="text-xs">
                      {allowedToolCalls.length === 0 ? (
                        <span className="text-muted-foreground italic">
                          Semua tool diizinkan (Open Access)
                        </span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {allowedToolCalls.map((t) => (
                            <Badge key={t} variant="secondary" className="font-mono text-[10px]">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Restricted Tool Calls */}
                  <div className="space-y-1 pb-2 border-b">
                    <span className="text-muted-foreground text-xs block">Tool Denylist (Restricted):</span>
                    <div className="text-xs">
                      {restrictedToolCalls.length === 0 ? (
                        <span className="text-muted-foreground italic">
                          Tidak ada pola tool yang dibatasi khusus
                        </span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {restrictedToolCalls.map((t) => (
                            <Badge key={t} variant="destructive" className="font-mono text-[10px]">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Allowed Models */}
                  {allowedModels.length > 0 && (
                    <div className="space-y-1 pb-2 border-b">
                      <span className="text-muted-foreground text-xs block">Allowed Models:</span>
                      <div className="flex flex-wrap gap-1">
                        {allowedModels.map((m) => (
                          <Badge key={m} variant="outline" className="font-mono text-[10px]">
                            {m}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-3 gap-2 text-xs">
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
                    <div>
                      <span className="text-muted-foreground block text-[11px]">Prod Access</span>
                      <span className="font-medium">
                        {prodAccess === true ? "Diizinkan" : prodAccess === false ? "Dilarang" : "Default"}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 11C: Simpan sebagai Template Custom */}
              <div className="rounded-lg border p-3 bg-muted/20 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <Bookmark className="size-4 text-primary" />
                    <span className="text-xs font-semibold">Simpan Konfigurasi sebagai Template</span>
                  </div>
                  {!isSavingCustom && !savedTemplateSuccess && (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setIsSavingCustom(true)}
                      className="h-7 text-xs gap-1"
                    >
                      <Plus className="size-3" />
                      Simpan sebagai Template
                    </Button>
                  )}
                </div>

                {isSavingCustom && (
                  <div className="flex items-center gap-2 pt-1">
                    <Input
                      placeholder="Nama template (mis: Coder Staging)..."
                      value={customTemplateName}
                      onChange={(e) => setCustomTemplateName(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          handleSaveAsTemplate();
                        }
                      }}
                      className="h-8 text-xs"
                      autoFocus
                    />
                    <Button
                      type="button"
                      size="sm"
                      onClick={handleSaveAsTemplate}
                      disabled={!customTemplateName.trim()}
                      className="h-8 text-xs shrink-0"
                    >
                      Simpan
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setIsSavingCustom(false);
                        setCustomTemplateName("");
                      }}
                      className="h-8 text-xs shrink-0"
                    >
                      Batal
                    </Button>
                  </div>
                )}

                {savedTemplateSuccess && (
                  <div className="flex items-center gap-1.5 text-xs text-success font-medium pt-1">
                    <Check className="size-3.5" />
                    Tersimpan ke &quot;Template Kamu&quot; sebagai: <strong>{savedTemplateSuccess}</strong>
                  </div>
                )}
                <p className="text-[11px] text-muted-foreground">
                  Template disimpan ke localStorage browser untuk digunakan kembali di wizard selanjutnya.
                </p>
              </div>
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
        </div>

        {/* Standard Wizard Footers */}
        {step !== "success" && (
          <DialogFooter className="gap-2 sm:gap-0 shrink-0 pt-2 border-t">
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
