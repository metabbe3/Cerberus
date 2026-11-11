import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";

export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="grid size-7 place-items-center rounded-md bg-primary/15 text-base" aria-hidden>
              🦉
            </span>
            <div className="flex items-baseline gap-1.5">
              <span className="font-semibold tracking-tight text-sm">Cerberus</span>
              <span className="text-[11px] text-muted-foreground">Gateway</span>
            </div>
          </Link>

          <nav className="flex items-center gap-3">
            <Link
              href="/docs-intro"
              className="text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              Dokumentasi
            </Link>
            <ThemeToggle />
            <Button asChild size="sm" variant="default" className="h-8 gap-1.5 text-xs font-medium">
              <Link href="/login">
                Live Dashboard
                <ArrowRight className="size-3" />
              </Link>
            </Button>
          </nav>
        </div>
      </header>

      <main className="flex-1">{children}</main>

      <footer className="border-t bg-muted/20 py-8">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-4 text-xs text-muted-foreground sm:flex-row">
          <p>
            Cerberus Policy Engine &bull; Benchmark Mac Mini M4 (~85.000 TPS @2048 conc) &bull;{" "}
            <Link href="/docs-intro" className="underline hover:text-foreground">
              Dokumentasi
            </Link>
          </p>
          <div className="flex items-center gap-4">
            <Link href="/login" className="hover:underline">
              Coba Live Dashboard &rarr;
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
