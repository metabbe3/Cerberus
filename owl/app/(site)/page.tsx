import Link from "next/link";
import {
  Activity,
  ArrowRight,
  BookOpen,
  FileCode,
  Layers,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function LandingPage() {
  return (
    <div className="flex flex-col space-y-16 pb-16">
      {/* Hero Section */}
      <section className="relative overflow-hidden pt-12 md:pt-20">
        <div className="mx-auto max-w-5xl px-4 text-center">
          <div className="mb-4 flex justify-center">
            <Badge
              variant="outline"
              className="gap-1.5 py-1 px-3 border-primary/30 bg-primary/5 text-primary text-xs font-mono"
            >
              <ShieldCheck className="size-3.5" />
              Cerberus v1.0 &bull; OPA Gatekeeper for LLM Tools
            </Badge>
          </div>

          <h1 className="text-3xl font-extrabold tracking-tight sm:text-5xl md:text-6xl text-foreground max-w-4xl mx-auto leading-tight">
            Cerberus — Policy engine untuk AI agents.
          </h1>

          <p className="mt-6 text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
            Setiap tool call dievaluasi sebelum dieksekusi. Proteksi deterministik,
            inspeksi argument berbahaya, masking otomatis, dan audit real-time untuk autonomous agents.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <Button asChild size="lg" className="h-11 px-6 font-semibold gap-2">
              <Link href="/login">
                Coba Live Dashboard
                <ArrowRight className="size-4" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline" className="h-11 px-6 font-medium gap-2">
              <Link href="/docs-intro">
                <BookOpen className="size-4" />
                Lihat Docs
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Metrics Section */}
      <section className="mx-auto max-w-5xl px-4 w-full">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Card className="border-border/60 bg-card/60 backdrop-blur">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardDescription className="text-xs uppercase tracking-wider font-mono">
                  Peak Throughput
                </CardDescription>
                <Zap className="size-4 text-amber-500" />
              </div>
              <CardTitle className="text-3xl font-bold tracking-tight text-foreground font-mono">
                ~85.000 TPS
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Sustained @2048 concurrency benchmarked pada Mac Mini M4.
              </p>
            </CardContent>
          </Card>

          <Card className="border-border/60 bg-card/60 backdrop-blur">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardDescription className="text-xs uppercase tracking-wider font-mono">
                  Coverage
                </CardDescription>
                <Layers className="size-4 text-primary" />
              </div>
              <CardTitle className="text-3xl font-bold tracking-tight text-foreground font-mono">
                5 Stage
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Evaluasi komprehensif: LLM prompt, Tool call, HTTP egress, Docker, dan SSH.
              </p>
            </CardContent>
          </Card>

          <Card className="border-border/60 bg-card/60 backdrop-blur">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardDescription className="text-xs uppercase tracking-wider font-mono">
                  Developer First
                </CardDescription>
                <Terminal className="size-4 text-emerald-500" />
              </div>
              <CardTitle className="text-3xl font-bold tracking-tight text-foreground font-mono">
                3 SDK Resmi
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Library Go, Python, dan TypeScript tanpa dependency eksternal (stdlib only).
              </p>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* 3 Kolom Fitur */}
      <section className="mx-auto max-w-5xl px-4 w-full">
        <div className="text-center mb-10">
          <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">
            Arsitektur Keamanan Zero-Trust untuk Agent Runtime
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Tiga pilar perlindungan untuk mencegah exploit prompt injection dan destructive command execution.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
          <Card className="flex flex-col border-border/80">
            <CardHeader>
              <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <FileCode className="size-5" />
              </div>
              <CardTitle className="text-lg font-semibold">Policy as Data</CardTitle>
              <CardDescription className="text-xs font-mono">Rego + Dynamic JSON</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 text-sm text-muted-foreground space-y-2">
              <p>
                Seluruh aturan otorisasi didefinisikan secara deklaratif menggunakan Open Policy Agent (OPA).
              </p>
              <p>
                Konfigurasi agen, batas token/budget, dan batasan argumen dimuat dari JSON in-memory store yang mendukung hot-reload dinamis tanpa restart server.
              </p>
            </CardContent>
          </Card>

          <Card className="flex flex-col border-border/80">
            <CardHeader>
              <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
                <ShieldAlert className="size-5" />
              </div>
              <CardTitle className="text-lg font-semibold">Fail-Closed</CardTitle>
              <CardDescription className="text-xs font-mono">Deny by Default</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 text-sm text-muted-foreground space-y-2">
              <p>
                Prinsip keamanan ketat: jika terjadi kegagalan sistem, rule tidak terdefinisi, atau parsing error, verdict otomatis <strong>DENY</strong>.
              </p>
              <p>
                Proteksi bawaan terhadap pola bahaya seperti <code>rm -rf</code>, wildcard grep pada file kredensial sensitif, dan akses IP subnet privat.
              </p>
            </CardContent>
          </Card>

          <Card className="flex flex-col border-border/80">
            <CardHeader>
              <div className="mb-2 flex size-10 items-center justify-center rounded-lg bg-amber-500/10 text-amber-500">
                <Activity className="size-5" />
              </div>
              <CardTitle className="text-lg font-semibold">Full Audit Trail</CardTitle>
              <CardDescription className="text-xs font-mono">SQLite + Live SSE</CardDescription>
            </CardHeader>
            <CardContent className="flex-1 text-sm text-muted-foreground space-y-2">
              <p>
                Setiap evaluasi dicatat secara asinkron ke database SQLite dengan zero overhead pada latency keputusan utama.
              </p>
              <p>
                Menyediakan streaming event langsung melalui Server-Sent Events (SSE) ke dashboard analitik Owl untuk pemantauan realtime.
              </p>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Cara Kerja: 3 Langkah */}
      <section className="mx-auto max-w-5xl px-4 w-full">
        <div className="rounded-2xl border border-border/80 bg-muted/20 p-6 sm:p-10">
          <div className="text-center mb-8">
            <Badge variant="secondary" className="mb-2 font-mono text-[11px]">
              Alur Evaluasi
            </Badge>
            <h2 className="text-2xl font-bold tracking-tight">Cara Kerja Cerberus</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Tiga langkah inspeksi deterministik sebelum aksi fisik dieksekusi oleh mesin agen.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
            <div className="flex flex-col p-5 rounded-xl border bg-card/80 space-y-3">
              <div className="flex items-center gap-2">
                <span className="flex size-7 items-center justify-center rounded-full bg-primary text-primary-foreground text-xs font-bold font-mono">
                  1
                </span>
                <h3 className="font-semibold text-sm">Agent Tool Call</h3>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Agen AI (Claude, GPT-4, Llama) menghasilkan tool call (misal: eksekusi bash script, query database, atau panggilan curl HTTP).
              </p>
              <div className="rounded bg-muted/70 p-2 font-mono text-[11px] text-muted-foreground">
                POST /v1/decide
              </div>
            </div>

            <div className="flex flex-col p-5 rounded-xl border bg-card/80 space-y-3">
              <div className="flex items-center gap-2">
                <span className="flex size-7 items-center justify-center rounded-full bg-primary text-primary-foreground text-xs font-bold font-mono">
                  2
                </span>
                <h3 className="font-semibold text-sm">Cerberus Decide (≤20ms)</h3>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Cerberus OPA engine mengevaluasi context permintaan, izin key agent, dangerous command patterns, dan rate-limit dalam latency p50 &le; 20ms.
              </p>
              <div className="rounded bg-muted/70 p-2 font-mono text-[11px] text-muted-foreground">
                OPA Rego Rules + Data
              </div>
            </div>

            <div className="flex flex-col p-5 rounded-xl border bg-card/80 space-y-3">
              <div className="flex items-center gap-2">
                <span className="flex size-7 items-center justify-center rounded-full bg-primary text-primary-foreground text-xs font-bold font-mono">
                  3
                </span>
                <h3 className="font-semibold text-sm">Eksekusi atau Blokir</h3>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Aksi aman dijalankan (dengan argument masking bila ada rahasia). Aksi berbahaya langsung diblokir seketika tanpa kompromi.
              </p>
              <div className="rounded bg-muted/70 p-2 font-mono text-[11px] text-emerald-500 font-semibold">
                allow / deny + masked_args
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Benchmark CTA Card */}
      <section className="mx-auto max-w-5xl px-4 w-full">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-6 rounded-xl border border-primary/20 bg-primary/5 p-6 sm:p-8">
          <div className="space-y-1 text-center sm:text-left">
            <h3 className="text-lg font-bold text-foreground">Siap Mengamankan Tool Agent Anda?</h3>
            <p className="text-sm text-muted-foreground max-w-xl">
              Lihat panduan integrasi lengkap untuk Go, Python, dan TypeScript, atau pantau metrik audit langsung di Owl Dashboard.
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-3">
            <Button asChild variant="outline" size="sm">
              <Link href="/docs-intro">Dokumentasi</Link>
            </Button>
            <Button asChild size="sm">
              <Link href="/login">Buka Dashboard &rarr;</Link>
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
