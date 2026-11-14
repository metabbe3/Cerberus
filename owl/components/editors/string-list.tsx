"use client";

import { Check, X } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

// One string-list editor used by every tab: chips with remove + Enter-to-add
// input. Duplicate entries are dropped silently — the engine treats them as
// one anyway.
// `suggestions` renders click-to-add quick picks under the chips so common
// values never require typing.
export function StringListEditor({
  label,
  hint,
  values,
  onChange,
  onRemove,
  placeholder,
  suggestions,
}: {
  label: string;
  hint?: string;
  values: string[];
  onChange: (values: string[]) => void;
  onRemove?: () => void;
  placeholder?: string;
  suggestions?: string[];
}) {
  const [draft, setDraft] = useState("");
  const [showAll, setShowAll] = useState(false);
  const add = (raw?: string) => {
    const v = (raw ?? draft).trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    if (raw === undefined) setDraft("");
  };
  const picks = (suggestions ?? [])
    .filter((s) => showAll || !values.includes(s))
    .filter((s) => showAll || s.toLowerCase().includes(draft.trim().toLowerCase()));
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between">
        <label className="text-sm font-medium">{label}</label>
        <div className="flex items-center gap-2">
          {hint ? <span className="text-xs text-muted-foreground">{hint}</span> : null}
          {onRemove ? (
            <button
              type="button"
              onClick={onRemove}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              remove
            </button>
          ) : null}
        </div>
      </div>
      <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded-md border p-1.5">
        {values.map((v) => (
          <Badge key={v} variant="secondary" className="gap-1 pr-1">
            {v}
            <button
              type="button"
              aria-label={`Remove ${v}`}
              onClick={() => onChange(values.filter((x) => x !== v))}
              className="rounded-sm hover:bg-muted"
            >
              <X className="size-3" />
            </button>
          </Badge>
        ))}
        <Input
          value={draft}
          placeholder={placeholder ?? "Add… (Enter)"}
          className="h-7 min-w-32 flex-1 border-0 shadow-none focus-visible:ring-0"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
          onBlur={() => add()}
        />
      </div>
      {suggestions && suggestions.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          {picks.slice(0, showAll ? picks.length : 8).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => add(s)}
              className="inline-flex items-center gap-1 rounded-full border bg-muted/40 px-2 py-0.5 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              <Check className="size-3" aria-hidden />
              {s}
            </button>
          ))}
          {picks.length > 8 && !showAll ? (
            <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => setShowAll(true)}>
              +{picks.length - 8} lagi
            </Button>
          ) : null}
          {picks.length === 0 && values.length > 0 ? (
            <span className="text-xs text-muted-foreground/70">semua saran sudah dipilih</span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
