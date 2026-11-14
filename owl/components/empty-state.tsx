import { Inbox, SearchX, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";

export type EmptyStateType = "zero-data" | "filtered-out" | "clean-security";

interface EmptyStateProps {
  type?: EmptyStateType;
  title: string;
  hint?: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export function EmptyState({
  type = "zero-data",
  title,
  hint,
  actionLabel,
  onAction,
  className = "",
}: EmptyStateProps) {
  if (type === "clean-security") {
    return (
      <div
        className={`flex flex-col items-center justify-center gap-1.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-8 text-center ${className}`}
      >
        <div className="rounded-full bg-emerald-500/10 p-3 mb-1">
          <ShieldCheck className="size-6 text-emerald-500" aria-hidden />
        </div>
        <p className="text-sm font-semibold text-foreground">{title}</p>
        {hint ? <p className="text-xs text-muted-foreground max-w-md">{hint}</p> : null}
      </div>
    );
  }

  if (type === "filtered-out") {
    return (
      <div
        className={`flex flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed p-8 text-center ${className}`}
      >
        <div className="rounded-full bg-muted p-3 mb-1">
          <SearchX className="size-6 text-muted-foreground" aria-hidden />
        </div>
        <p className="text-sm font-semibold text-foreground">{title}</p>
        {hint ? <p className="text-xs text-muted-foreground max-w-md">{hint}</p> : null}
        {actionLabel && onAction ? (
          <Button variant="outline" size="sm" onClick={onAction} className="mt-2 text-xs">
            {actionLabel}
          </Button>
        ) : null}
      </div>
    );
  }

  return (
    <div
      className={`flex flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed p-8 text-center ${className}`}
    >
      <div className="rounded-full bg-muted p-3 mb-1">
        <Inbox className="size-6 text-muted-foreground" aria-hidden />
      </div>
      <p className="text-sm font-semibold text-foreground">{title}</p>
      {hint ? <p className="text-xs text-muted-foreground max-w-md">{hint}</p> : null}
      {actionLabel && onAction ? (
        <Button variant="outline" size="sm" onClick={onAction} className="mt-2 text-xs">
          {actionLabel}
        </Button>
      ) : null}
    </div>
  );
}
