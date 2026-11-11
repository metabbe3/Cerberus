"use client";

import { X } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

// One string-list editor used by every tab: chips with remove + Enter-to-add
// input. Duplicate entries are dropped silently — the engine treats them as
// one anyway.
export function StringListEditor({
  label,
  hint,
  values,
  onChange,
  onRemove,
  placeholder,
}: {
  label: string;
  hint?: string;
  values: string[];
  onChange: (values: string[]) => void;
  onRemove?: () => void;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const v = draft.trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    setDraft("");
  };
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
          onBlur={add}
        />
      </div>
    </div>
  );
}
