"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle, CheckCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";

type PolicyFiles = { files: { path: string; content: string }[] };

type Validation = { ok: boolean; errors?: string[] };

export default function PolicyPage() {
  const policy = useQuery<PolicyFiles>({
    queryKey: ["policy"],
    queryFn: async () => {
      const res = await fetch("/api/policy");
      const body = await res.json();
      if (!res.ok) throw new Error((body as { error?: string }).error);
      return body as PolicyFiles;
    },
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [candidate, setCandidate] = useState("");
  const [validation, setValidation] = useState<Validation | null>(null);
  const [busy, setBusy] = useState(false);

  const files = policy.data?.files ?? [];
  const current = files.find((f) => f.path === selected) ?? files[0];

  const validate = async () => {
    setBusy(true);
    setValidation(null);
    try {
      const res = await fetch("/api/policy/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rego: candidate }),
      });
      const body = (await res.json()) as Validation & { error?: string };
      if (!res.ok && body.error) throw new Error(body.error);
      setValidation({ ok: body.ok, errors: body.errors });
    } catch (e) {
      setValidation({ ok: false, errors: [(e as Error).message] });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Policy</h1>

      {policy.isPending ? <Skeleton className="h-64 w-full" /> : null}
      {policy.isError ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>Policy sources unreadable</AlertTitle>
          <AlertDescription>
            {(policy.error as Error).message} — set OWL_POLICY_DIR to the
            directory holding the engine&apos;s *.rego files.
          </AlertDescription>
        </Alert>
      ) : null}

      {current ? (
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <Select value={current.path} onValueChange={setSelected}>
              <SelectTrigger className="w-72">
                <SelectValue placeholder="module" />
              </SelectTrigger>
              <SelectContent>
                {files.map((f) => (
                  <SelectItem key={f.path} value={f.path}>
                    {f.path}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Badge variant="secondary">read-only</Badge>
          </div>
          <pre className="max-h-96 overflow-auto rounded-md border bg-muted/50 p-4 font-mono text-xs leading-relaxed">
            {current.content}
          </pre>
        </div>
      ) : null}

      <div className="space-y-2">
        <h2 className="text-lg font-medium">Validate a module</h2>
        <p className="text-sm text-muted-foreground">
          Parses and compiles a candidate module against the policies currently
          on the engine — nothing is installed.
        </p>
        <Textarea
          className="min-h-40 font-mono text-xs"
          placeholder={"package stages.example\n\nallow if {\n  …\n}"}
          value={candidate}
          onChange={(e) => setCandidate(e.target.value)}
        />
        <Button onClick={validate} disabled={busy || !candidate.trim()}>
          Validate
        </Button>
        {validation ? (
          validation.ok ? (
            <Alert>
              <CheckCircle2 />
              <AlertTitle>Compiles against the live policy set</AlertTitle>
            </Alert>
          ) : (
            <Alert variant="destructive">
              <AlertCircle />
              <AlertTitle>Does not compile</AlertTitle>
              <AlertDescription>
                <ul className="list-inside list-disc font-mono text-xs">
                  {(validation.errors ?? []).map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )
        ) : null}
      </div>
    </div>
  );
}
