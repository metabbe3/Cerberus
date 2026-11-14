"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { KeyRound, Loader2, CheckCircle2, AlertCircle } from "lucide-react";

export function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    setErr(null);
    setDone(null);
    if (next !== confirm) {
      setErr("Konfirmasi password baru tidak sama");
      return;
    }
    if (next.length < 12) {
      setErr("Password baru minimal 12 karakter");
      return;
    }
    setBusy(true);
    try {
      const res = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      const body = (await res.json().catch(() => ({}))) as { message?: string; error?: string };
      if (!res.ok) {
        setErr(body.error ?? `gagal (${res.status})`);
        return;
      }
      setDone(body.message ?? "password diganti");
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch {
      setErr("jaringan error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="size-4" /> Ganti Password
        </CardTitle>
        <CardDescription>
          Ganti password akunmu sendiri. Password lama diverifikasi; semua sesi
          lain otomatis dicabut (kecuali sesi ini).
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="pw-current">Password saat ini</Label>
          <Input
            id="pw-current"
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="pw-new">Password baru (min. 12 karakter)</Label>
          <Input
            id="pw-new"
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="new-password"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="pw-confirm">Konfirmasi password baru</Label>
          <Input
            id="pw-confirm"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
          />
        </div>
        {err ? (
          <p className="text-sm text-destructive flex items-center gap-1.5">
            <AlertCircle className="size-4" /> {err}
          </p>
        ) : null}
        {done ? (
          <p className="text-sm text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
            <CheckCircle2 className="size-4" /> {done}
          </p>
        ) : null}
        <Button type="button" onClick={submit} disabled={busy || !current || !next}>
          {busy ? <Loader2 className="size-4 animate-spin" /> : null}
          Ganti Password
        </Button>
      </CardContent>
    </Card>
  );
}
