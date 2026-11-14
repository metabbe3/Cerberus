"use client";

import { Activity, Bot, LayoutDashboard, LogOut, Settings, SlidersHorizontal, UserRound } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const pillars = [
  {
    href: "/overview",
    label: "Overview",
    icon: LayoutDashboard,
    isActive: (pathname: string) =>
      pathname === "/overview" || pathname === "/" || pathname.startsWith("/monitoring"),
  },
  {
    href: "/agents",
    label: "Agents",
    icon: Bot,
    isActive: (pathname: string) => pathname.startsWith("/agents"),
  },
  {
    href: "/decisions",
    label: "Activity",
    icon: Activity,
    isActive: (pathname: string) =>
      pathname.startsWith("/decisions") ||
      pathname.startsWith("/breaches") ||
      pathname.startsWith("/turns"),
  },
  {
    href: "/rules",
    label: "Policies",
    icon: SlidersHorizontal,
    isActive: (pathname: string) =>
      pathname.startsWith("/rules") ||
      pathname.startsWith("/shield") ||
      pathname.startsWith("/policy") ||
      pathname.startsWith("/policies"),
  },
  {
    href: "/settings",
    label: "Settings",
    icon: Settings,
    isActive: (pathname: string) => pathname.startsWith("/settings"),
  },
  {
    href: "/account",
    label: "Akun",
    icon: UserRound,
    isActive: (pathname: string) => pathname.startsWith("/account"),
  },
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
        <Link href="/overview" className="flex shrink-0 items-center gap-2">
          <span className="grid size-7 place-items-center rounded-md bg-primary/15 text-base" aria-hidden>
            🦉
          </span>
          <span className="font-semibold tracking-tight">Owl</span>
          <span className="hidden text-xs text-muted-foreground sm:inline">Cerberus</span>
        </Link>
        <nav className="-mx-1 flex min-w-0 flex-1 items-center gap-1 overflow-x-auto px-1">
          {pillars.map(({ href, label, icon: Icon, isActive }) => {
            const active = isActive(pathname);
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  "flex shrink-0 items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
                  active && "bg-accent text-accent-foreground font-semibold",
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
          <Button variant="ghost" size="icon" aria-label="Keluar" title="Keluar" onClick={logout}>
            <LogOut className="size-4" />
          </Button>
        </div>
      </div>
    </header>
  );
}
