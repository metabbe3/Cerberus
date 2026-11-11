"use client";

import { Activity, Bot, LayoutDashboard, LogOut, Radio, ScrollText, Settings, ShieldAlert, SlidersHorizontal } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const links = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/monitoring", label: "Monitoring", icon: Activity },
  { href: "/agents", label: "Agents", icon: Bot },
  { href: "/decisions", label: "Decisions", icon: Radio },
  { href: "/shield", label: "Shield", icon: ShieldAlert },
  { href: "/rules", label: "Rules", icon: SlidersHorizontal },
  { href: "/policies", label: "Policies", icon: ScrollText },
  { href: "/settings", label: "Settings", icon: Settings },
];

async function logout() {
  await fetch("/api/auth/logout", { method: "POST" });
  window.location.href = "/login";
}

export function Nav() {
  const pathname = usePathname();
  return (
    <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4">
        <Link href="/" className="flex shrink-0 items-center gap-2">
          <span className="grid size-7 place-items-center rounded-md bg-primary/15 text-base" aria-hidden>
            🦉
          </span>
          <span className="font-semibold tracking-tight">Owl</span>
          <span className="hidden text-xs text-muted-foreground sm:inline">Cerberus</span>
        </Link>
        <nav className="-mx-1 flex min-w-0 flex-1 items-center gap-1 overflow-x-auto px-1">
          {links.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  "flex shrink-0 items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
                  active && "bg-accent text-accent-foreground",
                )}
              >
                <Icon className="size-4" aria-hidden />
                {label}
              </Link>
            );
          })}
        </nav>
        <div className="flex shrink-0 items-center gap-1">
          <ThemeToggle />
          <Button variant="ghost" size="icon" aria-label="Sign out" title="Sign out" onClick={logout}>
            <LogOut className="size-4" />
          </Button>
        </div>
      </div>
    </header>
  );
}
