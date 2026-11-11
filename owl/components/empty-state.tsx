import { Inbox } from "lucide-react";

// The one empty-state every page renders through (ROADMAP §4).
export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 rounded-md border border-dashed p-10 text-center">
      <Inbox className="mb-2 size-8 text-muted-foreground" aria-hidden />
      <p className="text-sm font-medium">{title}</p>
      {hint ? <p className="text-sm text-muted-foreground">{hint}</p> : null}
    </div>
  );
}
