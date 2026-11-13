import Link from "next/link";
import { CerberusMark } from "@/components/cerberus-logo";
import {
  ArrowLeft,
  ArrowRight,
  Code2,
  ExternalLink,
  FileText,
  Layers,
  ShieldCheck,
  Terminal,
} from "lucide-react";

export default function DocsIntroPage() {
  return (
    <div className="flex flex-col min-h-screen">
      {/* Capsule Nav Pill */}
      <header className="sticky top-4 z-50 px-4">
        <nav className="max-w-5xl mx-auto clay-card px-4 py-2.5 flex items-center justify-between gap-3">
          <Link href="/" className="flex items-center gap-2.5 min-w-0">
            <span className="clay-chip clay-chip-coral size-9 shrink-0 grid place-items-center"><CerberusMark size={22} className="text-[var(--clay-accent)]" /></span>
            <span className="font-extrabold text-base sm:text-lg tracking-tight text-[var(--clay-ink)]">
              Cerberus
            </span>
            <span className="hidden sm:inline text-xs font-semibold text-[var(--clay-ink-muted)] truncate">
              Docs
            </span>
          </Link>
          <div className="flex items-center gap-1 sm:gap-2 shrink-0">
            <Link
              href="/"
              className="clay-btn clay-btn-ghost clay-btn-sm px-2.5 sm:px-3 text-[13px] sm:text-sm font-semibold whitespace-nowrap"
            >
              Beranda
            </Link>
            <Link
              href="/login"
              className="clay-btn clay-btn-ghost clay-btn-sm px-2.5 sm:px-3 text-[13px] sm:text-sm font-semibold whitespace-nowrap"
            >
              Dashboard
            </Link>
            <a
              href="https://github.com/metabbe3/Cerberus"
              target="_blank"
              rel="noreferrer"
              title="GitHub"
              className="clay-btn clay-btn-accent clay-btn-sm px-2.5 sm:px-3 text-[13px] sm:text-sm font-semibold whitespace-nowrap"
            >
              GH
            </a>
          </div>
        </nav>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-4xl w-full mx-auto px-4 py-8 sm:py-12 space-y-8">
        {/* Back navigation */}
        <div className="flex items-center">
          <Link href="/" className="clay-btn clay-btn-ghost clay-btn-sm text-xs gap-1.5">
            <ArrowLeft className="size-3.5" />
            Kembali ke Beranda
          </Link>
        </div>

        {/* Page Header */}
        <div className="space-y-3">
          <div className="inline-flex">
            <span className="clay-chip clay-chip-surface px-3 py-1 font-mono text-xs font-semibold text-[var(--clay-ink-muted)]">
              Developer Documentation
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[var(--clay-ink)]">
            Dokumentasi &amp; Integrasi Cerberus
          </h1>
          <p className="text-base text-[var(--clay-ink-muted)] max-w-2xl leading-relaxed">
            Panduan integrasi policy engine untuk AI agent tools dalam Go, Python, dan TypeScript dengan arsitektur fail-closed.
          </p>
        </div>

        {/* 3 SDK Cards */}
        <div className="grid gap-6 md:grid-cols-3">
          {/* Go SDK */}
          <div className="clay-card clay-card-press p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="clay-chip clay-chip-mint size-10">
                  <Terminal className="size-5 text-[#155E40]" />
                </div>
                <span className="font-mono text-xs font-semibold text-[#155E40] bg-[#BFE8D9]/40 px-2 py-0.5 rounded-full">
                  sdk/go
                </span>
              </div>
              <h2 className="text-lg font-bold text-[var(--clay-ink)]">Go SDK</h2>
              <p className="mt-2 text-xs sm:text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                GuardedExecutor &amp; Client teruji tinggi dengan retry otomatis, hot cache, dan low-latency context cancelation.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--clay-border)]">
              <pre className="p-2.5 bg-[#F0EBE1] rounded-xl font-mono text-[11px] text-[var(--clay-ink)] overflow-x-auto">
                guard.Execute(ctx, tool, args, fn)
              </pre>
            </div>
          </div>

          {/* Python SDK */}
          <div className="clay-card clay-card-press p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="clay-chip clay-chip-lilac size-10">
                  <Code2 className="size-5 text-[#382B68]" />
                </div>
                <span className="font-mono text-xs font-semibold text-[#382B68] bg-[#E3DBFF]/50 px-2 py-0.5 rounded-full">
                  sdk/python
                </span>
              </div>
              <h2 className="text-lg font-bold text-[var(--clay-ink)]">Python SDK</h2>
              <p className="mt-2 text-xs sm:text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                Zero dependency (urllib stdlib murni), kompatibel Python 3.9+, mendukung argument masking dan decorator wrapper.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--clay-border)]">
              <pre className="p-2.5 bg-[#F0EBE1] rounded-xl font-mono text-[11px] text-[var(--clay-ink)] overflow-x-auto">
                guard.execute(tool, args, fn)
              </pre>
            </div>
          </div>

          {/* TypeScript SDK */}
          <div className="clay-card clay-card-press p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="clay-chip clay-chip-coral size-10">
                  <ShieldCheck className="size-5 text-[#8C2C0B]" />
                </div>
                <span className="font-mono text-xs font-semibold text-[#8C2C0B] bg-[#FFD9CC]/50 px-2 py-0.5 rounded-full">
                  sdk/ts
                </span>
              </div>
              <h2 className="text-lg font-bold text-[var(--clay-ink)]">TypeScript SDK</h2>
              <p className="mt-2 text-xs sm:text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                ESM murni berbasis global fetch, typed decision objects, dan wrapper middleware untuk LangChain &amp; Vercel AI SDK.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--clay-border)]">
              <pre className="p-2.5 bg-[#F0EBE1] rounded-xl font-mono text-[11px] text-[var(--clay-ink)] overflow-x-auto">
                await guard.execute(tool, args, fn)
              </pre>
            </div>
          </div>
        </div>

        {/* Instalasi & Env Reference Card */}
        <div className="clay-card p-6 sm:p-8 space-y-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="clay-chip clay-chip-mint size-8">
                <Layers className="size-4 text-[#155E40]" />
              </div>
              <h2 className="text-xl font-bold text-[var(--clay-ink)]">
                Instalasi &amp; Env Reference
              </h2>
            </div>
            <p className="text-sm text-[var(--clay-ink-muted)]">
              Arsitektur unified multi-stage container (<code className="font-mono text-xs">ghcr.io/metabbe3/cerberus:latest</code>), 5 enforcement services, dan referensi environment variables lengkap.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 pt-2">
            <div className="p-3 bg-[#F0EBE1] rounded-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[var(--clay-ink)]">1. Engine (:8089)</span>
                <span className="font-mono text-[10px] text-[var(--clay-ink-muted)]">internal</span>
              </div>
              <p className="text-[11px] text-[var(--clay-ink-muted)] leading-snug">
                Policy engine central, evaluasi OPA Rego, admin API, dan audit trail.
              </p>
            </div>

            <div className="p-3 bg-[#F0EBE1] rounded-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[var(--clay-ink)]">2. LLM Tap (:8090)</span>
                <span className="font-mono text-[10px] text-[var(--clay-ink-muted)]">127.0.0.1</span>
              </div>
              <p className="text-[11px] text-[var(--clay-ink-muted)] leading-snug">
                In-path LLM proxy, stream inspection, masking at-rest, dan fail-closed deny.
              </p>
            </div>

            <div className="p-3 bg-[#F0EBE1] rounded-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[var(--clay-ink)]">3. Docker Proxy (:2377)</span>
                <span className="font-mono text-[10px] text-[var(--clay-ink-muted)]">127.0.0.1</span>
              </div>
              <p className="text-[11px] text-[var(--clay-ink-muted)] leading-snug">
                Socket proxy shield melindungi docker.sock dari escape atau abuse agent.
              </p>
            </div>

            <div className="p-3 bg-[#F0EBE1] rounded-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[var(--clay-ink)]">4. Egress Proxy (:8088)</span>
                <span className="font-mono text-[10px] text-[var(--clay-ink-muted)]">127.0.0.1</span>
              </div>
              <p className="text-[11px] text-[var(--clay-ink-muted)] leading-snug">
                HTTP CONNECT outbound proxy memblokir akses ke CIDR prod &amp; DNS spoofing.
              </p>
            </div>

            <div className="p-3 bg-[#F0EBE1] rounded-xl space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs text-[var(--clay-ink)]">5. SSH Bastion (:2222)</span>
                <span className="font-mono text-[10px] text-[var(--clay-ink-muted)]">127.0.0.1</span>
              </div>
              <p className="text-[11px] text-[var(--clay-ink-muted)] leading-snug">
                Audit gate inspeksi perintah shell SSH via engine sebelum dieksekusi.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-3 pt-2">
            <a
              href="https://github.com/metabbe3/Cerberus/blob/main/docs/SETUP.md"
              target="_blank"
              rel="noreferrer"
              className="clay-btn clay-btn-accent clay-btn-sm font-semibold text-xs gap-1.5"
            >
              Buka Panduan SETUP.md &amp; Env Reference
              <ExternalLink className="size-3.5" />
            </a>
          </div>
        </div>

        {/* Panduan Integrasi Lengkap Card */}
        <div className="clay-card p-6 sm:p-8 space-y-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="clay-chip clay-chip-coral size-8">
                <FileText className="size-4 text-[var(--clay-accent)]" />
              </div>
              <h2 className="text-xl font-bold text-[var(--clay-ink)]">
                Panduan Integrasi Lengkap
              </h2>
            </div>
            <p className="text-sm text-[var(--clay-ink-muted)]">
              Spesifikasi API HTTP, tabel stage evaluasi OPA, format schema data.json, dan model otentikasi Bearer token.
            </p>
          </div>

          <div className="space-y-3">
            <p className="text-xs font-medium text-[var(--clay-ink-muted)]">
              Buka file panduan lengkap di repositori pada file:
            </p>
            <div className="p-3 bg-[#F0EBE1] rounded-2xl font-mono text-xs text-[var(--clay-ink)] flex items-center justify-between">
              <code>docs/INTEGRATION.md</code>
            </div>
            <div className="flex flex-wrap gap-3 pt-2">
              <a
                href="https://raw.githubusercontent.com/metabbe3/Cerberus/main/docs/INTEGRATION.md"
                target="_blank"
                rel="noreferrer"
                className="clay-btn clay-btn-ghost clay-btn-sm font-semibold text-xs gap-1.5"
              >
                Baca INTEGRATION.md (raw)
                <ExternalLink className="size-3.5" />
              </a>
              <Link href="/login" className="clay-btn clay-btn-accent clay-btn-sm font-semibold text-xs gap-1.5">
                Buka Live Dashboard
                <ArrowRight className="size-3.5" />
              </Link>
            </div>
          </div>

          <div className="pt-6 border-t border-[var(--clay-border)] space-y-3">
            <h3 className="text-sm font-bold text-[var(--clay-ink)]">
              Perintah Instalasi SDK
            </h3>
            <p className="text-xs text-[var(--clay-ink-muted)]">
              SDK tersedia di repositori publik{" "}
              <a
                className="underline underline-offset-2 font-semibold hover:text-[var(--clay-ink)]"
                href="https://github.com/metabbe3/Cerberus"
                target="_blank"
                rel="noreferrer"
              >
                github.com/metabbe3/Cerberus
              </a>
              :
            </p>
            <pre className="p-4 rounded-2xl bg-[#2D2A26] text-[#F6F1E9] font-mono text-[13px] sm:text-sm leading-relaxed whitespace-pre-wrap break-words">{`# Go
go get github.com/metabbe3/cerberus/sdk/go

# Python (copy single-file package, zero dependency)
pip install git+https://github.com/metabbe3/Cerberus.git#subdirectory=sdk/python

# TypeScript / Node 18+
npm install github:metabbe3/Cerberus#main --prefix .  # atau copy sdk/ts/src`}</pre>
          </div>
        </div>
      </main>

      {/* Footer rounded-top */}
      <footer className="clay-footer px-6 py-12 sm:py-14 mt-auto">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6 text-center sm:text-left">
          <div className="space-y-1">
            <div className="flex items-center justify-center sm:justify-start gap-2">
              <span className="clay-chip clay-chip-coral size-6 shrink-0 grid place-items-center"><CerberusMark size={15} /></span>
              <span className="font-bold text-sm text-[var(--clay-ink)]">
                Cerberus Policy Engine
              </span>
            </div>
            <p className="text-xs text-[var(--clay-ink-muted)]">
              Cerberus v1.0 &bull; Policy engine untuk AI agent &bull; Fail-closed by design
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 text-xs font-semibold text-[var(--clay-ink-muted)]">
            <Link href="/" className="hover:text-[var(--clay-ink)] transition-colors">
              Beranda
            </Link>
            <Link href="/login" className="hover:text-[var(--clay-ink)] transition-colors">
              Dashboard
            </Link>
            <a
              href="https://github.com/metabbe3/Cerberus"
              target="_blank"
              rel="noreferrer"
              className="hover:text-[var(--clay-ink)] transition-colors inline-flex items-center gap-1"
            >
              GitHub Repo
              <ExternalLink className="size-3" />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
