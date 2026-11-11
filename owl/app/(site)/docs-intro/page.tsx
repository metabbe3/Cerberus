import Link from "next/link";
import { ArrowLeft, Code2, ShieldCheck, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function DocsIntroPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-12 space-y-8">
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="sm" className="gap-1.5 text-xs">
          <Link href="/">
            <ArrowLeft className="size-3.5" />
            Kembali ke Beranda
          </Link>
        </Button>
      </div>

      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Dokumentasi & Integrasi Cerberus</h1>
        <p className="text-muted-foreground text-sm">
          Panduan integrasi policy engine untuk AI agent tools dalam Go, Python, dan TypeScript.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Terminal className="size-4 text-primary" />
              Go SDK
            </CardTitle>
            <CardDescription className="text-xs font-mono">sdk/go</CardDescription>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground space-y-2">
            <p>GuardedExecutor & Client teruji tinggi dengan retry otomatis dan in-memory cache.</p>
            <pre className="p-2 bg-muted rounded font-mono text-[11px] overflow-x-auto">
              guard.Execute(ctx, tool, args, fn)
            </pre>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Code2 className="size-4 text-emerald-500" />
              Python SDK
            </CardTitle>
            <CardDescription className="text-xs font-mono">sdk/python</CardDescription>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground space-y-2">
            <p>Zero dependency (urllib stdlib), kompatibel Python 3.9+, mendukung argument masking.</p>
            <pre className="p-2 bg-muted rounded font-mono text-[11px] overflow-x-auto">
              guard.execute(tool, args, fn)
            </pre>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldCheck className="size-4 text-amber-500" />
              TypeScript SDK
            </CardTitle>
            <CardDescription className="text-xs font-mono">sdk/ts</CardDescription>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground space-y-2">
            <p>ESM murni berbasis global fetch, typed decision objects, dan wrapper middleware.</p>
            <pre className="p-2 bg-muted rounded font-mono text-[11px] overflow-x-auto">
              await guard.execute(tool, args, fn)
            </pre>
          </CardContent>
        </Card>
      </div>

      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <CardTitle className="text-base">Panduan Integrasi Lengkap</CardTitle>
          <CardDescription className="text-xs">
            Spesifikasi API, tabel stage, schema data.json, dan model autentikasi.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm space-y-3">
          <p className="text-xs text-muted-foreground">
            Buka file panduan lengkap di repositori pada file:
          </p>
          <code className="block p-3 rounded bg-muted font-mono text-xs">
            docs/INTEGRATION.md
          </code>
          <div className="pt-2">
            <Button asChild size="sm">
              <Link href="/login">Buka Live Dashboard &rarr;</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
