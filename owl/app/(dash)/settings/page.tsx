"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";
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
// `== true`). Flipping fail-open → fail-closed denies every unregistered
// key/team, so it demands a red confirm before the draft changes.
export default function SettingsPage() {
  const { data, isPending, isError, error } = useData();
  const put = usePutData();
  const [draft, setDraft] = useState({ teams: true, keys: true });
  const [confirming, setConfirming] = useState<FlagKey | null>(null);
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
    if (value === false && draft[key] === true) {
      setConfirming(key);
      return;
    }
    setDraft((d) => ({ ...d, [key]: value }));
  };

  const confirm = () => {
    if (confirming) setDraft((d) => ({ ...d, [confirming]: false }));
    setConfirming(null);
  };

  const save = async () => {
    if (!data) return;
    setSavedError(null);
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

  const flagRow = (key: FlagKey, title: string, body: string) => (
    <div className="flex items-start justify-between gap-6 py-3">
      <div>
        <p className="font-medium">{title}</p>
        <p className="text-sm text-muted-foreground">{body}</p>
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
        <CardContent className="divide-y">
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
        </CardContent>
      </Card>

      <Button onClick={save} disabled={put.isPending}>
        Save flags
      </Button>

      <AlertDialog
        open={confirming !== null}
        onOpenChange={(open) => !open && setConfirming(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="text-destructive">
              Turn on fail-closed?
            </AlertDialogTitle>
            <AlertDialogDescription>
              Every key/team not registered in the data document will be DENIED.
              Requests from unregistered agents start failing immediately.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-white hover:bg-destructive/90"
              onClick={confirm}
            >
              Yes, deny unknown
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
