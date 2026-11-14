"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Menu, X } from "lucide-react";
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
  UsersRound,
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
        href: "/users",
        label: "Users",
        icon: UsersRound,
        isActive: (pathname: string) => pathname.startsWith("/users"),
      },
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
  const [open, setOpen] = useState(false);

  // Tutup drawer setelah navigasi.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <>
      {/* Bar atas mobile: hamburger + logo — dashboard tetap usable di 375px */}
      <header className="sticky top-0 z-40 flex h-12 items-center gap-2 border-b bg-background/95 px-3 backdrop-blur lg:hidden">
        <button
          type="button"
          aria-label="Buka menu navigasi"
          aria-expanded={open}
          onClick={() => setOpen(true)}
          className="inline-flex size-9 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          <Menu className="size-5" aria-hidden />
        </button>
        <Link href="/overview" className="flex items-center gap-2">
          <span className="grid size-6 place-items-center rounded-md bg-primary/15 text-sm" aria-hidden>
            🦉
          </span>
          <span className="text-sm font-semibold tracking-tight">Owl</span>
        </Link>
      </header>
      {/* Overlay klik-untuk-tutup */}
      {open ? (
        <button
          type="button"
          aria-label="Tutup menu"
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setOpen(false)}
        />
      ) : null}
    <aside className={`fixed inset-y-0 left-0 z-50 flex w-60 max-w-[85vw] flex-col border-r bg-background/95 backdrop-blur transition-transform duration-200 supports-[backdrop-filter]:bg-background/80 ${open ? "translate-x-0" : "-translate-x-full"} lg:translate-x-0`}>
      <div className="flex h-14 items-center gap-2 border-b px-4">
        <button
          type="button"
          aria-label="Tutup menu"
          onClick={() => setOpen(false)}
          className="mr-1 inline-flex size-9 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground lg:hidden"
        >
          <X className="size-5" aria-hidden />
        </button>
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
    </>
  );
}
