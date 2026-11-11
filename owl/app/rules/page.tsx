"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Plus,
  RefreshCcw,
  RotateCcw,
  Save,
  Search,
  ShieldAlert,
  Trash2,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useData, usePutData, useRevisions, useRollback } from "@/lib/queries";
import type { CerberusData, DangerousCmdPattern } from "@/lib/schema";

export default function RulesPage() {
  const { data: serverData, isLoading, refetch } = useData();
  const putData = usePutData();
  const rollback = useRollback();
  const { data: revisions, refetch: refetchRevisions } = useRevisions();

  const [draft, setDraft] = useState<CerberusData | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);

  // Sync initial draft from server data
  useEffect(() => {
    if (serverData?.data && !draft) {
      setDraft(structuredClone(serverData.data));
    }
  }, [serverData, draft]);

  // Sync draft when server epoch updates after save or rollback
  const handleResetToLive = () => {
    if (serverData?.data) {
      setDraft(structuredClone(serverData.data));
      setSaveError(null);
      setSaveSuccess("Draft dikembalikan sesuai konfigurasi aktif.");
    }
  };

  // State for adding a new dangerous pattern
  const [newPatternId, setNewPatternId] = useState("");
  const [newPatternDesc, setNewPatternDesc] = useState("");
  const [newPatternRegex, setNewPatternRegex] = useState("");
  const [newPatternRegexValid, setNewPatternRegexValid] = useState<boolean | null>(null);
  const [newPatternRegexErr, setNewPatternRegexErr] = useState("");

  // Pattern live test row state: patternId -> { testCmd: string, matches: boolean | null, testing: boolean }
  const [patternTests, setPatternTests] = useState<
    Record<string, { testCmd: string; matches: boolean | null }>
  >({});

  // Validate regex live
  const checkRegexLive = async (regex: string) => {
    if (!regex) {
      setNewPatternRegexValid(null);
      setNewPatternRegexErr("");
      return;
    }
    try {
      const res = await fetch("/api/admin/regex/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regex, test_string: "" }),
      });
      const data = (await res.json()) as { valid: boolean; error?: string };
      setNewPatternRegexValid(data.valid);
      setNewPatternRegexErr(data.error ?? "");
    } catch {
      setNewPatternRegexValid(false);
      setNewPatternRegexErr("Gagal menghubungi endpoint validasi");
    }
  };

  // Run pattern test against sample cmd
  const runPatternTest = async (id: string, regex: string, cmd: string) => {
    if (!regex || !cmd) return;
    try {
      const res = await fetch("/api/admin/regex/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regex, test_string: cmd }),
      });
      const data = (await res.json()) as { valid: boolean; matches: boolean };
      setPatternTests((prev) => ({
        ...prev,
        [id]: { testCmd: cmd, matches: data.matches },
      }));
    } catch {
      // ignore
    }
  };

  if (isLoading || !draft) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <RefreshCcw className="size-4 animate-spin" />
          Memuat konfigurasi aturan...
        </div>
      </div>
    );
  }

  const prodShield = draft.prod_shield ?? {};
  const dangerousPatterns: DangerousCmdPattern[] = prodShield.dangerous_cmd_patterns ?? [];

  // Update prod_shield in draft
  const updateProdShield = (patch: Partial<NonNullable<CerberusData["prod_shield"]>>) => {
    setDraft((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        prod_shield: {
          ...prev.prod_shield,
          ...patch,
        },
      };
    });
  };

  // Add dangerous pattern
  const handleAddPattern = () => {
    if (!newPatternId.trim() || !newPatternRegex.trim()) return;
    const item: DangerousCmdPattern = {
      id: newPatternId.trim(),
      description: newPatternDesc.trim() || undefined,
      regex: newPatternRegex.trim(),
      enabled: true,
    };
    updateProdShield({
      dangerous_cmd_patterns: [...dangerousPatterns, item],
    });
    setNewPatternId("");
    setNewPatternDesc("");
    setNewPatternRegex("");
    setNewPatternRegexValid(null);
  };

  // Remove dangerous pattern
  const handleRemovePattern = (idx: number) => {
    const next = [...dangerousPatterns];
    next.splice(idx, 1);
    updateProdShield({ dangerous_cmd_patterns: next });
  };

  // Toggle pattern enabled/disabled
  const handleTogglePattern = (idx: number, active: boolean) => {
    const next = [...dangerousPatterns];
    next[idx] = { ...next[idx], enabled: active };
    updateProdShield({ dangerous_cmd_patterns: next });
  };

  // Save & Activate Handler
  const handleSaveAndActivate = async () => {
    setSaveError(null);
    setSaveSuccess(null);
    try {
      const res = await putData.mutateAsync(draft);
      setSaveSuccess(`Aturan berhasil disimpan dan diaktifkan (Epoch ${res.epoch})`);
      refetch();
      refetchRevisions();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setSaveError(msg);
    }
  };

  // Rollback Handler
  const handleRollback = async (revId?: number) => {
    setSaveError(null);
    setSaveSuccess(null);
    try {
      const res = await rollback.mutateAsync(revId);
      setSaveSuccess(`Rollback berhasil! Konfigurasi dikembalikan ke revisi #${res.revision_id ?? "sebelumnya"} (Epoch ${res.epoch})`);
      await refetch();
      await refetchRevisions();
      setDraft(null); // will re-sync from serverData
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setSaveError(`Rollback gagal: ${msg}`);
    }
  };

  return (
    <div className="mx-auto max-w-6xl space-y-8 px-4 py-8">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b pb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Policy Studio — Editor Aturan</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Edit aturan keamanan, Production Shield, dan pola perintah berbahaya dengan proteksi safety net otomatis.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleResetToLive}
            title="Kembalikan draft lokal ke status server aktif"
          >
            <RefreshCcw className="mr-1.5 size-3.5" />
            Reset Draft
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleRollback()}
            disabled={rollback.isPending}
            className="text-amber-600 border-amber-300 hover:bg-amber-50 dark:text-amber-400 dark:border-amber-700 dark:hover:bg-amber-950/50"
          >
            <RotateCcw className="mr-1.5 size-3.5" />
            Rollback 1-Klik
          </Button>
          <Button
            size="sm"
            onClick={handleSaveAndActivate}
            disabled={putData.isPending}
            className="bg-emerald-600 hover:bg-emerald-700 text-white"
          >
            <Save className="mr-1.5 size-3.5" />
            {putData.isPending ? "Menguji & Mengaktifkan..." : "Simpan & Aktivasi"}
          </Button>
        </div>
      </div>

      {/* Status Alerts */}
      {saveSuccess && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-800 dark:text-emerald-200">
          <CheckCircle2 className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
          <span>{saveSuccess}</span>
        </div>
      )}

      {saveError && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          <div className="flex items-start gap-2">
            <XCircle className="size-5 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-semibold">Aktivasi Ditolak oleh Safety Net OPA</p>
              <p className="font-mono text-xs opacity-90">{saveError}</p>
              <p className="text-xs text-muted-foreground mt-2">
                Perubahan ditolak untuk melindungi sistem. Snapshot lama tetap aktif dan aman.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 1: Dangerous Command Patterns */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <ShieldAlert className="size-5 text-red-500" />
            Pola Perintah Berbahaya (Dangerous Command Patterns)
          </CardTitle>
          <CardDescription>
            Pola regex Linux/shell berbahaya yang otomatis ditolak di stage tool/bash.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[140px]">ID Aturan</TableHead>
                  <TableHead>Deskripsi</TableHead>
                  <TableHead className="w-[300px]">Regex Pattern</TableHead>
                  <TableHead className="w-[100px]">Status</TableHead>
                  <TableHead className="w-[240px]">Uji Coba Cepat</TableHead>
                  <TableHead className="w-[60px] text-right">Aksi</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dangerousPatterns.map((pat, idx) => {
                  const isEnabled = pat.enabled !== false;
                  const testState = patternTests[pat.id];
                  return (
                    <TableRow key={pat.id || idx}>
                      <TableCell className="font-mono text-xs font-semibold">
                        {pat.id}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {pat.description || "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs max-w-[280px] truncate" title={pat.regex}>
                        {pat.regex}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <Switch
                            checked={isEnabled}
                            onCheckedChange={(checked) => handleTogglePattern(idx, checked)}
                          />
                          <span className="text-xs">{isEnabled ? "Aktif" : "Mati"}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-1.5">
                          <div className="flex items-center gap-1">
                            <Input
                              placeholder="contoh: rm -rf /"
                              className="h-7 text-xs font-mono"
                              value={testState?.testCmd ?? ""}
                              onChange={(e) => {
                                const val = e.target.value;
                                setPatternTests((prev) => ({
                                  ...prev,
                                  [pat.id]: { testCmd: val, matches: null },
                                }));
                              }}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") {
                                  runPatternTest(pat.id, pat.regex, testState?.testCmd ?? "");
                                }
                              }}
                            />
                            <Button
                              variant="secondary"
                              size="sm"
                              className="h-7 px-2 text-xs"
                              onClick={() => runPatternTest(pat.id, pat.regex, testState?.testCmd ?? "")}
                              title="Uji apakah perintah ini cocok dengan pola regex"
                            >
                              <Search className="size-3" />
                            </Button>
                          </div>
                          {testState?.matches !== null && testState?.matches !== undefined && (
                            <div>
                              {testState.matches ? (
                                <Badge variant="destructive" className="text-[10px] py-0">
                                  Cocok (Bahaya!)
                                </Badge>
                              ) : (
                                <Badge variant="outline" className="text-[10px] py-0 text-emerald-600 border-emerald-300 dark:text-emerald-400">
                                  Aman (Tidak Cocok)
                                </Badge>
                              )}
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7 text-muted-foreground hover:text-destructive"
                          onClick={() => handleRemovePattern(idx)}
                          title="Hapus pattern ini"
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>

          {/* Form Tambah Pattern Baru */}
          <div className="rounded-lg border bg-muted/30 p-4 space-y-3">
            <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Plus className="size-4 text-primary" />
              Tambah Pola Perintah Berbahaya Baru
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">ID Pola</label>
                <Input
                  placeholder="contoh: curl_pipe_bash"
                  value={newPatternId}
                  onChange={(e) => setNewPatternId(e.target.value)}
                  className="h-8 text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Deskripsi</label>
                <Input
                  placeholder="contoh: Blok eksekusi script remote piping"
                  value={newPatternDesc}
                  onChange={(e) => setNewPatternDesc(e.target.value)}
                  className="h-8 text-xs"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">
                  Regex Pattern (Validasi Live)
                </label>
                <div className="space-y-1">
                  <Input
                    placeholder="contoh: curl.*\|.*bash"
                    value={newPatternRegex}
                    onChange={(e) => {
                      const v = e.target.value;
                      setNewPatternRegex(v);
                      checkRegexLive(v);
                    }}
                    className="h-8 text-xs font-mono"
                  />
                  {newPatternRegexValid === false && (
                    <p className="text-[11px] text-destructive">{newPatternRegexErr || "Regex tidak valid"}</p>
                  )}
                  {newPatternRegexValid === true && (
                    <p className="text-[11px] text-emerald-600 dark:text-emerald-400">✓ Regex valid</p>
                  )}
                </div>
              </div>
            </div>
            <div className="flex justify-end pt-1">
              <Button
                size="sm"
                onClick={handleAddPattern}
                disabled={!newPatternId.trim() || !newPatternRegex.trim() || newPatternRegexValid === false}
                className="h-8 text-xs"
              >
                <Plus className="mr-1 size-3.5" />
                Tambahkan ke Draft
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* SECTION 2: Shield Lists (Chip Editors) */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* Protected Containers */}
        <ChipEditorCard
          title="Container Terlindungi (protected_containers)"
          description="Container Docker yang tidak boleh dihapus/dihentikan tanpa izin khusus."
          placeholder="contoh: teknikalidnew-db-1"
          items={prodShield.protected_containers ?? []}
          onUpdate={(items) => updateProdShield({ protected_containers: items })}
        />

        {/* CIDRs */}
        <ChipEditorCard
          title="Rentang IP Produksi (cidrs)"
          description="Subnet jaringan produksi yang terlindungi dari koneksi liar."
          placeholder="10.0.0.0/8"
          items={prodShield.cidrs ?? []}
          onUpdate={(items) => updateProdShield({ cidrs: items })}
        />

        {/* Host Keywords */}
        <ChipEditorCard
          title="Kata Kunci Host (host_keywords)"
          description="Kata kunci pada hostname target yang dianggap lingkungan produksi."
          placeholder="contoh: prod, production"
          items={prodShield.host_keywords ?? []}
          onUpdate={(items) => updateProdShield({ host_keywords: items })}
        />

        {/* DB Keywords */}
        <ChipEditorCard
          title="Kata Kunci Database (db_keywords)"
          description="Kata kunci pada koneksi database yang dianggap database produksi."
          placeholder="contoh: prod-db, postgres-prod"
          items={prodShield.db_keywords ?? []}
          onUpdate={(items) => updateProdShield({ db_keywords: items })}
        />
      </div>

      {/* SECTION 3: Exempt Keys & Prod Access */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <AlertTriangle className="size-5 text-amber-500" />
            Pengecualian Shield & Akses Produksi (Exempt Keys & Prod Access)
          </CardTitle>
          <CardDescription>
            Konfigurasi kunci agen yang memiliki hak istimewa untuk melewati Production Shield.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Exempt Keys */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-semibold">Exempt Keys (Bypass Penuh Shield)</h4>
                <p className="text-xs text-muted-foreground">
                  Kunci agen di bawah ini dapat melewati semua pemeriksaan Production Shield.
                </p>
              </div>
              <Badge variant="destructive" className="flex items-center gap-1 text-xs">
                <AlertTriangle className="size-3" />
                Risiko Tinggi
              </Badge>
            </div>

            <ChipEditor
              placeholder="contoh: k-owner"
              items={prodShield.exempt_keys ?? []}
              onUpdate={(items) => updateProdShield({ exempt_keys: items })}
            />
          </div>

          <div className="border-t pt-4 space-y-3">
            <h4 className="text-sm font-semibold">Akses Produksi per Agen (data.agents.*.prod_access)</h4>
            <p className="text-xs text-muted-foreground">
              Memberikan izin kepada agen terdaftar untuk mengakses alamat IP dan Database produksi.
            </p>

            <div className="rounded-md border divide-y">
              {Object.entries(draft.agents ?? {}).map(([keyId, agent]) => {
                const hasProdAccess = Boolean(agent.prod_access);
                return (
                  <div key={keyId} className="flex items-center justify-between p-3 text-sm">
                    <div className="flex items-center gap-3">
                      <div>
                        <div className="font-medium font-mono text-xs">{keyId}</div>
                        <div className="text-xs text-muted-foreground">{agent.name || "Tanpa nama"}</div>
                      </div>
                      {hasProdAccess && (
                        <Badge variant="outline" className="text-amber-600 border-amber-300 dark:text-amber-400 text-[10px]">
                          Akses Prod Aktif
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">
                        {hasProdAccess ? "Diizinkan" : "Diblokir"}
                      </span>
                      <Switch
                        checked={hasProdAccess}
                        onCheckedChange={(checked) => {
                          setDraft((prev) => {
                            if (!prev) return prev;
                            const nextAgents = { ...prev.agents };
                            nextAgents[keyId] = {
                              ...nextAgents[keyId],
                              prod_access: checked,
                            };
                            return { ...prev, agents: nextAgents };
                          });
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* SECTION 4: Histori Perubahan (Revisions) */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <RotateCcw className="size-5 text-primary" />
            Histori Perubahan & Snapshot Revisi (Read-Only)
          </CardTitle>
          <CardDescription>
            Setiap aktivasi disimpan secara otomatis di SQLite audit table revisions untuk rollback aman 1-klik.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">Revisi</TableHead>
                  <TableHead className="w-[180px]">Waktu</TableHead>
                  <TableHead className="w-[140px]">Admin</TableHead>
                  <TableHead>Ringkasan Perubahan</TableHead>
                  <TableHead className="w-[130px] text-right">Aksi</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {!revisions || revisions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-6 text-xs text-muted-foreground">
                      Belum ada snapshot histori revisi.
                    </TableCell>
                  </TableRow>
                ) : (
                  revisions.map((rev) => {
                    const timeStr = new Date(rev.time).toLocaleString("id-ID", {
                      dateStyle: "medium",
                      timeStyle: "medium",
                    });
                    return (
                      <TableRow key={rev.id}>
                        <TableCell className="font-mono text-xs font-semibold">
                          #{rev.id}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                          {timeStr}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {rev.author}
                        </TableCell>
                        <TableCell className="text-xs">
                          {rev.summary || "Pembaruan konfigurasi"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => handleRollback(rev.id)}
                            disabled={rollback.isPending}
                            title="Pulihkan konfigurasi ke versi ini"
                          >
                            Kembalikan
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Reusable Chip Editor Card Component
function ChipEditorCard({
  title,
  description,
  placeholder,
  items,
  onUpdate,
}: {
  title: string;
  description: string;
  placeholder: string;
  items: string[];
  onUpdate: (items: string[]) => void;
}) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold">{title}</CardTitle>
        <CardDescription className="text-xs">{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <ChipEditor placeholder={placeholder} items={items} onUpdate={onUpdate} />
      </CardContent>
    </Card>
  );
}

// Reusable Chip Editor Input & List
function ChipEditor({
  placeholder,
  items,
  onUpdate,
}: {
  placeholder: string;
  items: string[];
  onUpdate: (items: string[]) => void;
}) {
  const [inputVal, setInputVal] = useState("");

  const handleAdd = () => {
    const val = inputVal.trim();
    if (!val || items.includes(val)) return;
    onUpdate([...items, val]);
    setInputVal("");
  };

  const handleRemove = (index: number) => {
    const next = [...items];
    next.splice(index, 1);
    onUpdate(next);
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5 min-h-[36px] p-2 rounded-md border bg-muted/20">
        {items.length === 0 ? (
          <span className="text-xs text-muted-foreground italic px-1">Tidak ada item</span>
        ) : (
          items.map((item, idx) => (
            <span
              key={item + idx}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono bg-background border shadow-xs"
            >
              <span>{item}</span>
              <button
                type="button"
                onClick={() => handleRemove(idx)}
                className="text-muted-foreground hover:text-destructive rounded-full"
              >
                ×
              </button>
            </span>
          ))
        )}
      </div>
      <div className="flex items-center gap-2">
        <Input
          placeholder={placeholder}
          value={inputVal}
          onChange={(e) => setInputVal(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              handleAdd();
            }
          }}
          className="h-8 text-xs font-mono"
        />
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={handleAdd}
          disabled={!inputVal.trim()}
          className="h-8 text-xs shrink-0"
        >
          <Plus className="mr-1 size-3.5" />
          Tambah
        </Button>
      </div>
    </div>
  );
}
