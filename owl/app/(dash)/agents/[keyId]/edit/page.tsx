"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { AgentEditor } from "@/components/agents/agent-editor";
import { EmptyState } from "@/components/empty-state";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { AlertCircle, ArrowLeft } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { useData } from "@/lib/queries";

export default function EditAgentPage() {
  const { keyId } = useParams<{ keyId: string }>();
  const { data, isPending, isError, error } = useData();

  if (isPending) return <Skeleton className="h-64 w-full" />;
  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="size-4" />
        <AlertTitle>Engine unreachable</AlertTitle>
        <AlertDescription>{error.message}</AlertDescription>
      </Alert>
    );
  }

  const agent = data.data.agents[keyId];
  if (!agent) {
    return (
      <EmptyState
        title="Unregistered key — governed by config flags"
        hint={`No agent record for ${keyId}. Register it to give it its own policy.`}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" asChild className="text-xs">
          <Link href={`/agents/${keyId}`}>
            <ArrowLeft className="mr-1.5 size-3.5" />
            Kembali ke Observability View
          </Link>
        </Button>
      </div>
      <AgentEditor key={keyId} keyId={keyId} agent={agent} />
    </div>
  );
}
