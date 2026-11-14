"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { AlertCircle, CheckCircle2, Loader2, PlugZap } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
async function getUpstream() {
  const res = await fetch("/api/admin/upstream");
  if (!res.ok) throw new Error((await res.json()).error ?? `HTTP ${res.status}`);
  return res.json();
}

async function putUpstream(payload: { endpoint: string; api_key?: string }) {
  const res = await fetch("/api/admin/upstream", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json()).error ?? `HTTP ${res.status}`);
  return res.json();
}

async function testUpstream(payload: { endpoint: string; api_key?: string }) {
  const res = await fetch("/api/admin/upstream/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}

const PRESETS = [
  { id: "litellm", label: "LiteLLM", endpoint: "http://localhost:4000/v1" },
  { id: "zai", label: "z.ai", endpoint: "https://api.z.ai/api/anthropic" },
  { id: "custom", label: "Custom", endpoint: "" },
] as const;

export function UpstreamCard() {
  const [endpoint, setEndpoint] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [hint, setHint] = useState("");
  const [updatedAt, setUpdatedAt] = useState("");
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; latency_ms?: number; error?: string } | null>(null);

  useEffect(() => {
    getUpstream()
      .then((cfg) => {
        setEndpoint(cfg.endpoint ?? "");
        setHint(cfg.key_hint ?? "");
        setUpdatedAt(cfg.updated_at ?? "");
      })
      .catch(() => setEndpoint(""));
  }, []);

  const payload = useCallback((): { endpoint: string; api_key?: string } => {
    const p: { endpoint: string; api_key?: string } = { endpoint: endpoint.trim() };
    if (apiKey.trim()) p.api_key = apiKey.trim();
    return p;
  }, [endpoint, apiKey]);

  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await testUpstream(payload()));
    } catch (e) {
      setTestResult({ ok: false, error: e instanceof Error ? e.message : "gagal" });
    } finally {
      setTesting(false);
    }
  };

  const runSave = async () => {
    setSaving(true);
    try {
      const cfg = await putUpstream(payload());
      setHint(cfg.key_hint ?? "");
      setUpdatedAt(cfg.updated_at ?? "");
      setApiKey("");
      toast.success("Upstream tersimpan — trafik LLM agent otomatis diarahkan tanpa restart");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Gagal menyimpan upstream");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <PlugZap className="size-4" /> Upstream LLM
        </CardTitle>
        <CardDescription>
          Endpoint tujuan trafik LLM agent (tap). Trafik otomatis diarahkan ke
          upstream ini — tanpa restart. Mode default: pass-through — agent
          memakai kredensialnya sendiri, Cerberus hanya inspect/decide/mask.
          {updatedAt ? ` Diperbarui ${new Date(updatedAt).toLocaleString("id-ID")}.` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {PRESETS.map((p) => (
            <Button
              key={p.id}
              type="button"
              size="sm"
              variant={endpoint === p.endpoint && p.endpoint !== "" ? "default" : "outline"}
              onClick={() => setEndpoint(p.endpoint)}
            >
              {p.label}
            </Button>
          ))}
        </div>
        <div className="space-y-2">
          <Label htmlFor="upstream-endpoint">Endpoint (OpenAI/Anthropic-compatible)</Label>
          <Input
            id="upstream-endpoint"
            placeholder="http://litellm.company.internal:4000/v1"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            spellCheck={false}
          />
        </div>
        <details className="group rounded-md border border-border/60 bg-muted/30 px-3 py-2">
          <summary className="cursor-pointer select-none text-xs font-medium text-muted-foreground hover:text-foreground">
            Opsi lanjutan: central key custody (menimpa kredensial agent)
          </summary>
          <div className="mt-3 space-y-2">
            <p className="text-xs text-muted-foreground">
              Opsional. Bila diisi, tap mengganti Authorization agent dengan key
              ini sebelum meneruskan (agent jadi zero-key; revoke satu tempat).
              Kosongkan untuk pass-through.
            </p>
            <div className="space-y-2">
              <Label htmlFor="upstream-key">API key{hint ? " (kosong = pakai key lama)" : ""}</Label>
              <Input
                id="upstream-key"
                type="password"
                placeholder={hint ? "biarkan kosong untuk memakai key lama" : "sk-…"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                autoComplete="new-password"
              />
            </div>
          </div>
        </details>
        {testResult ? (
          testResult.ok ? (
            <Alert>
              <CheckCircle2 />
              <AlertTitle>Koneksi berhasil{typeof testResult.latency_ms === "number" ? ` — ${testResult.latency_ms} ms` : ""}</AlertTitle>
              <AlertDescription>Endpoint merespons dengan baik.</AlertDescription>
            </Alert>
          ) : (
            <Alert variant="destructive">
              <AlertCircle />
              <AlertTitle>Koneksi gagal</AlertTitle>
              <AlertDescription className="font-mono text-xs">{testResult.error ?? "unknown"}</AlertDescription>
            </Alert>
          )
        ) : null}
        <div className="flex gap-2">
          <Button type="button" variant="outline" onClick={runTest} disabled={testing || !endpoint.trim()}>
            {testing ? <Loader2 className="size-4 animate-spin" /> : null}
            Test Koneksi
          </Button>
          <Button type="button" onClick={runSave} disabled={saving || !endpoint.trim()}>
            {saving ? <Loader2 className="size-4 animate-spin" /> : null}
            Simpan
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
