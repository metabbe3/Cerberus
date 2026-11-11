"use client";

import { useParams } from "next/navigation";
import { AgentEditor } from "@/components/agents/agent-editor";
import { EmptyState } from "@/components/empty-state";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { useData } from "@/lib/queries";

export default function AgentPage() {
  const { keyId } = useParams<{ keyId: string }>();
  const { data, isPending, isError, error } = useData();

  if (isPending) return <Skeleton className="h-64 w-full" />;
  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle />
        <AlertTitle>Engine unreachable</AlertTitle>
        <AlertDescription>{error.message}</AlertDescription>
      </Alert>
    );
  }

  const agent = data.data.agents[keyId];
  // Matches the engine's unknown-key policy: governed by the config bypass
  // flags, not by an agent record.
  if (!agent) {
    return (
      <EmptyState
        title="Unregistered key — governed by config flags"
        hint={`No agent record for ${keyId}. Register it to give it its own policy.`}
      />
    );
  }

  return <AgentEditor key={keyId} keyId={keyId} agent={agent} />;
}
