"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

// 64-hex key IDs: truncated display, full ID on click-to-copy. Used by the
// agents table and the decisions table.
export function KeyCell({ id }: { id: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={`${id} — click to copy`}
      className="flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(id).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
    >
      {id.length > 14 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id}
      {copied ? (
        <Check className="size-3" aria-hidden />
      ) : (
        <Copy className="size-3" aria-hidden />
      )}
    </button>
  );
}
