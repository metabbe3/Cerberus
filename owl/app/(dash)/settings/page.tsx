"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { toast } from "sonner";
import { AlertCircle, ShieldAlert, ShieldCheck, Users } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { PageHeader } from "@/components/page-header";
import { useData, usePutData } from "@/lib/queries";

type FlagKey = "teams" | "keys";

// Bypass flags from config. Absent = false = fail-closed (authz.rego reads
// `== true`).
export default function SettingsPage() {
  const { data, isPending, isError, error } = useData();
  const put = usePutData();
  const [draft, setDraft] = useState({ teams: true, keys: true });
  const [saveConfirmOpen, setSaveConfirmOpen] = useState(false);
  const [savedError, setSavedError] = useState<string | null>(null);

  useEffect(() => {
    if (data) {
      setDraft({
        teams: data.data.config.bypass_unknown_teams ?? false,
        keys: data.data.config.bypass_unknown_keys ?? false,
      });
    }
  }, [data]);

  const flip = (key: FlagKey, value: boolean) => {
    setDraft((d) => ({ ...d, [key]: value }));
  };

  const executeSave = async () => {
    if (!data) return;
    setSavedError(null);
    setSaveConfirmOpen(false);
    const next = structuredClone(data.data);
    next.config.bypass_unknown_teams = draft.teams;
    next.config.bypass_unknown_keys = draft.keys;
    put.mutate(next, {
      onSuccess: (out) => toast.success(`Data installed (epoch ${out.epoch})`),
      onError: (e) => setSavedError(e.message),
    });
  };

  if (isPending) {
    return (
      <div className="max-w-2xl space-y-4">
        <Skeleton className="h-8 w-40" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }
  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle />
        <AlertTitle>Engine unreachable</AlertTitle>
        <AlertDescription>{error.message}</AlertDescription>
      </Alert>
    );
  }

  const isFailOpen = draft.keys || draft.teams;

  const flagRow = (key: FlagKey, title: string, body: string) => (
    <div className="flex items-start justify-between gap-6 py-3">
      <div>
        <p className="font-medium text-sm">{title}</p>
        <p className="text-xs text-muted-foreground">{body}</p>
      </div>
      <Switch checked={draft[key]} onCheckedChange={(v) => flip(key, v)} />
    </div>
  );

  return (
    <div className="max-w-2xl space-y-4">
      <PageHeader
        title="Settings"
        description="Gateway-wide switches. Changes take effect on save (epoch +1)."
      />

      {savedError ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Engine rejected the document — nothing was changed</AlertTitle>
          <AlertDescription className="font-mono text-xs">{savedError}</AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Bypass flags (onboarding)</CardTitle>
          <CardDescription>
            Fail-open lets unregistered keys/teams through while you onboard.
            Flip both off once every key below is registered.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 9D Destructive alert when fail-open is ON; Blue alert when OFF */}
          {isFailOpen ? (
            <Alert variant="destructive">
              <ShieldAlert className="size-4" />
              <AlertTitle>Fail-open aktif</AlertTitle>
              <AlertDescription>
                Fail-open aktif: kunci tak dikenal LOLOS. Matikan saat semua key terdaftar.
              </AlertDescription>
            </Alert>
          ) : (
            <Alert className="border-blue-500/30 bg-blue-500/10 text-blue-800 dark:text-blue-300">
              <ShieldCheck className="size-4 text-blue-600 dark:text-blue-400" />
              <AlertTitle>Fail-closed aktif</AlertTitle>
              <AlertDescription>
                Semua kunci tak dikenal akan ditolak. Gateway terlindungi.
              </AlertDescription>
            </Alert>
          )}

          <div className="divide-y border-t pt-1">
            {flagRow(
              "keys",
              "Bypass unknown keys",
              draft.keys
                ? "Unregistered key_ids are ALLOWED (fail-open)."
                : "Unregistered key_ids are DENIED (fail-closed).",
            )}
            {flagRow(
              "teams",
              "Bypass unknown teams",
              draft.teams
                ? "Unregistered team_ids are ALLOWED (fail-open)."
                : "Unregistered team_ids are DENIED (fail-closed).",
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>Pengelolaan Pengguna</CardTitle>
              <CardDescription>
                Kelola akun pengguna database-backed, hak akses peran (admin atau viewer), dan reset kata sandi.
              </CardDescription>
            </div>
            <Link href="/users">
              <Button variant="outline" className="gap-1.5 self-start sm:self-auto">
                <Users className="size-4" />
                Kelola Pengguna
              </Button>
            </Link>
          </div>
        </CardHeader>
      </Card>

      {/* 9D Save flags triggers confirmation dialog */}
      <Button onClick={() => setSaveConfirmOpen(true)} disabled={put.isPending}>
        Save flags
      </Button>

      {/* 9D Confirmation Dialog */}
      <AlertDialog
        open={saveConfirmOpen}
        onOpenChange={setSaveConfirmOpen}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="text-destructive">
              Ubah mode keamanan gateway?
            </AlertDialogTitle>
            <AlertDialogDescription className="space-y-2 text-sm">
              <p>
                Perubahan flag bypass akan langsung mempengaruhi seluruh evaluasi otorisasi di gateway (epoch +1).
              </p>
              {isFailOpen ? (
                <span className="block font-medium text-destructive">
                  Peringatan: Satu atau lebih flag bypass aktif (Fail-open). Permintaan dari agen yang belum terdaftar akan diloloskan.
                </span>
              ) : (
                <span className="block font-medium text-foreground">
                  Mode Fail-closed aktif: Setiap permintaan dengan key atau team yang belum terdaftar akan langsung DITOLAK.
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Batal</AlertDialogCancel>
            <AlertDialogAction
              className={isFailOpen ? "bg-destructive text-destructive-foreground hover:bg-destructive/90" : ""}
              onClick={executeSave}
            >
              Ya, simpan perubahan
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
