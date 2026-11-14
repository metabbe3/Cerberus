"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, Flame, ShieldAlert, XCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { useBreakGlassStatus, useData, useRevokeBreakGlass } from "@/lib/queries";

export function GlobalSafetyBanner() {
  const { data: owlData } = useData();
  const { data: bgData } = useBreakGlassStatus();
  const revoke = useRevokeBreakGlass();

  const [timeLeft, setTimeLeft] = useState<string>("");

  const config = owlData?.data?.config;
  const isFailOpen = Boolean(config?.bypass_unknown_keys || config?.bypass_unknown_teams);
  const isGlobalKill = Boolean(config?.kill_switch?.global);
  const isBreakGlass = Boolean(bgData?.active);

  // Countdown timer for break-glass
  useEffect(() => {
    if (!isBreakGlass) {
      setTimeLeft("");
      return;
    }
    const expiresAtStr = bgData?.global_expires_at || bgData?.key_expires_at;
    if (!expiresAtStr) {
      setTimeLeft("aktif");
      return;
    }

    const target = new Date(expiresAtStr).getTime();
    const updateCountdown = () => {
      const now = Date.now();
      const diff = Math.max(0, Math.floor((target - now) / 1000));
      if (diff <= 0) {
        setTimeLeft("kedaluwarsa");
        return;
      }
      const m = Math.floor(diff / 60);
      const s = diff % 60;
      setTimeLeft(`${m}:${s.toString().padStart(2, "0")}`);
    };

    updateCountdown();
    const timer = setInterval(updateCountdown, 1000);
    return () => clearInterval(timer);
  }, [isBreakGlass, bgData?.global_expires_at, bgData?.key_expires_at]);

  if (!isFailOpen && !isGlobalKill && !isBreakGlass) {
    return null;
  }

  const handleRevoke = async () => {
    try {
      await revoke.mutateAsync();
      toast.success("Break-glass darurat berhasil dicabut");
    } catch (e) {
      toast.error((e as Error).message || "Gagal mencabut break-glass");
    }
  };

  return (
    <div className="sticky top-14 z-30 flex flex-col gap-1 border-b border-destructive/40 bg-destructive/15 px-4 py-2.5 text-xs text-destructive-foreground backdrop-blur-md">
      {isBreakGlass && (
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between gap-3 font-medium">
          <div className="flex items-center gap-2">
            <Flame className="size-4 shrink-0 text-red-500 animate-pulse" aria-hidden />
            <span>
              <strong className="font-semibold text-red-400">BREAK-GLASS DARURAT AKTIF</strong>
              {" — "}
              {bgData?.reason ? `"${bgData.reason}"` : "Kebijakan keamanan ditangguhkan sementara."}
              {timeLeft && (
                <span className="ml-2 font-mono tabular-nums text-red-300">
                  (Sisa: {timeLeft})
                </span>
              )}
            </span>
          </div>
          <Button
            size="sm"
            variant="destructive"
            className="h-6 px-2.5 text-[11px] font-semibold"
            disabled={revoke.isPending}
            onClick={handleRevoke}
          >
            <XCircle className="mr-1 size-3" />
            Cabut Sekarang
          </Button>
        </div>
      )}

      {isFailOpen && (
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between gap-3 font-medium">
          <div className="flex items-center gap-2">
            <AlertTriangle className="size-4 shrink-0 text-amber-500" aria-hidden />
            <span>
              <strong className="font-semibold text-amber-400">MODE FAIL-OPEN AKTIF</strong>
              {" — "}
              Kunci atau tim tidak dikenal dilewati (
              {config?.bypass_unknown_keys ? "bypass_unknown_keys" : ""}
              {config?.bypass_unknown_keys && config?.bypass_unknown_teams ? ", " : ""}
              {config?.bypass_unknown_teams ? "bypass_unknown_teams" : ""}
              : true). Kunci asing diizinkan mengakses LLM.
            </span>
          </div>
          <Link
            href="/settings"
            className="shrink-0 underline underline-offset-2 hover:text-foreground text-amber-300 hover:text-amber-200"
          >
            Ubah di Settings &rarr;
          </Link>
        </div>
      )}

      {isGlobalKill && (
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between gap-3 font-medium">
          <div className="flex items-center gap-2">
            <ShieldAlert className="size-4 shrink-0 text-red-500" aria-hidden />
            <span>
              <strong className="font-semibold text-red-400">GLOBAL KILL-SWITCH AKTIF</strong>
              {" — "}
              Seluruh request dari semua agen diblokir total oleh gateway.
            </span>
          </div>
          <Link
            href="/settings"
            className="shrink-0 underline underline-offset-2 hover:text-foreground text-red-300 hover:text-red-200"
          >
            Kelola di Settings &rarr;
          </Link>
        </div>
      )}
    </div>
  );
}
