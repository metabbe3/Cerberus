"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  Activity,
  Bot,
  LayoutDashboard,
  LogOut,
  Settings,
  SlidersHorizontal,
  UserRound,
  type LucideIcon,
} from "lucide-react";

type Pillar = {
  href: string;
  label: string;
  icon: LucideIcon;
  isActive: (pathname: string) => boolean;
};

const groups: { title: string; items: Pillar[] }[] = [
  {
    title: "Cerberus",
    items: [
      {
        href: "/overview",
        label: "Overview",
        icon: LayoutDashboard,
        isActive: (pathname: string) =>
          pathname === "/" || pathname.startsWith("/overview") || pathname.startsWith("/monitoring"),
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
    ],
  },
  {
    title: "Personal",
    items: [
      {
        href: "/account",
        label: "Akun",
        icon: UserRound,
        isActive: (pathname: string) => pathname.startsWith("/account"),
      },
    ],
  },
];

async function logout() {
  await fetch("/api/auth/logout", { method: "POST" });
  window.location.href = "/login";
}

export function Nav() {
  const pathname = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <div className="flex h-14 items-center gap-2 border-b px-4">
        <Link href="/overview" className="flex items-center gap-2">
          <span className="grid size-7 place-items-center rounded-md bg-primary/15 text-base" aria-hidden>
            🦉
          </span>
          <span className="font-semibold tracking-tight">Owl</span>
          <span className="hidden text-xs text-muted-foreground sm:inline">Cerberus</span>
        </Link>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {groups.map((group) => (
          <div key={group.title} className="mb-5">
            <p className="mb-1.5 px-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">
              {group.title}
            </p>
            <ul className="space-y-0.5">
              {group.items.map(({ href, label, icon: Icon, isActive }) => {
                const active = isActive(pathname);
                return (
                  <li key={href}>
                    <Link
                      href={href}
                      className={cn(
                        "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
                        active && "bg-accent font-semibold text-accent-foreground",
                      )}
                    >
                      <Icon className="size-4 shrink-0" aria-hidden />
                      {label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="flex items-center justify-between border-t px-3 py-2.5">
        <ThemeToggle />
        <Button variant="ghost" size="icon" aria-label="Keluar" title="Keluar" onClick={logout}>
          <LogOut className="size-4" />
        </Button>
      </div>
    </aside>
  );
}
