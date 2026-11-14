"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

export function ActivitySubNav() {
  const pathname = usePathname();
  const tabs = [
    { href: "/decisions", label: "Keputusan (Decisions)" },
    { href: "/breaches", label: "Pelanggaran (Breaches)" },
    { href: "/turns", label: "LLM Turns" },
  ];

  return (
    <div className="flex items-center gap-1 border-b pb-2 mb-6 overflow-x-auto text-xs">
      {tabs.map((tab) => {
        const active = pathname.startsWith(tab.href);
        return (
          <Link
            key={tab.href}
            href={tab.href}
            className={cn(
              "px-3 py-1.5 font-medium rounded-md transition-colors shrink-0",
              active
                ? "bg-secondary text-foreground font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
            )}
          >
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}

export function PoliciesSubNav() {
  const pathname = usePathname();
  const tabs = [
    { href: "/rules", label: "Aturan (Rules)" },
    { href: "/shield", label: "Prod Shield" },
    { href: "/policy", label: "Policy Explorer" },
    { href: "/policies", label: "Bundle & Revisions" },
  ];

  return (
    <div className="flex items-center gap-1 border-b pb-2 mb-6 overflow-x-auto text-xs">
      {tabs.map((tab) => {
        const active = pathname.startsWith(tab.href);
        return (
          <Link
            key={tab.href}
            href={tab.href}
            className={cn(
              "px-3 py-1.5 font-medium rounded-md transition-colors shrink-0",
              active
                ? "bg-secondary text-foreground font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
            )}
          >
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}
