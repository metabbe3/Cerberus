"use client";

import Link from "next/link";
import { useState } from "react";
import {
  Activity,
  ArrowRight,
  Check,
  ChevronRight,
  Code2,
  Copy,
  ExternalLink,
  FileCode,
  Layers,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";

type SdkTab = "go" | "python" | "ts";

export default function LandingPage() {
  const [activeTab, setActiveTab] = useState<SdkTab>("go");
  const [copied, setCopied] = useState(false);

  const sdkSnippets: Record<SdkTab, { install: string; code: string; ext: string }> = {
    go: {
      install: "go get github.com/metabbe3/cerberus/sdk/go",
      ext: "main.go",
      code: `package main

import (
    "context"
    "log"
    "github.com/metabbe3/cerberus/sdk/go"
)

func main() {
    guard := cerberus.NewGuard(cerberus.Config{
        URL:   "http://localhost:8080",
        Agent: "agent-prod-01",
    })

    // Fail-closed execution: evaluasi OPA p50 <= 20ms
    res, err := guard.Execute(context.Background(), "shell_run", map[string]any{
        "cmd": "git status --porcelain",
    })
    if err != nil {
        log.Fatalf("Policy violation or blocked: %v", err)
    }
    log.Printf("Allowed verdict: %s", res.Verdict)
}`,
    },
    python: {
      install: "pip install git+https://github.com/metabbe3/Cerberus.git#subdirectory=sdk/python",
      ext: "agent.py",
      code: `from cerberus import CerberusGuard

# Zero external dependency (stdlib only)
guard = CerberusGuard(
    url="http://localhost:8080",
    agent="agent-prod-01",
)

# Deterministic safety check
decision = guard.execute(
    tool="shell_run",
    args={"cmd": "git status --porcelain"},
)

if decision.allowed:
    print(f"Executing with sanitized args: {decision.masked_args}")
else:
    print(f"Action blocked: {decision.reason}")`,
    },
    ts: {
      install: "npm install github:metabbe3/Cerberus#main",
      ext: "guard.ts",
      code: `import { CerberusGuard } from "@cerberus/sdk";

// Native fetch ESM runtime
const guard = new CerberusGuard({
  url: "http://localhost:8080",
  agent: "agent-prod-01",
});

const decision = await guard.execute("shell_run", {
  cmd: "git status --porcelain",
});

if (decision.allowed) {
  console.log("Verdict ALLOW:", decision.maskedArgs);
} else {
  console.error("Verdict DENY:", decision.reason);
}`,
    },
  };

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex flex-col min-h-screen">
      {/* ===================================================================
          1. CAPSULE NAV — identitas + menu utama
          =================================================================== */}
      <header className="sticky top-4 z-50 px-4">
        <nav className="max-w-5xl mx-auto clay-card px-4 py-2.5 flex items-center justify-between gap-3">
          <Link href="/" className="flex items-center gap-2.5 min-w-0">
            <span className="clay-chip clay-chip-coral size-9 text-lg shrink-0">🦉</span>
            <span className="font-extrabold text-base sm:text-lg tracking-tight text-[var(--clay-ink)]">
              Cerberus
            </span>
            <span className="hidden sm:inline text-xs font-semibold text-[var(--clay-ink-muted)] truncate">
              Policy Engine untuk AI Agent
            </span>
          </Link>
          <div className="flex items-center gap-1 sm:gap-2 shrink-0">
            <Link
              href="/docs-intro"
              className="clay-btn clay-btn-ghost clay-btn-sm px-2.5 sm:px-3 text-[13px] sm:text-sm font-semibold whitespace-nowrap"
            >
              Docs
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

      {/* ===================================================================
          2. HERO — klaim utama + demo decision card
          =================================================================== */}
      <section className="relative max-w-5xl mx-auto px-4 w-full pt-14 pb-10 sm:pt-20 sm:pb-14 overflow-hidden">
        <div className="clay-blob clay-blob-mint" aria-hidden="true" />
        <div className="clay-blob clay-blob-lilac" aria-hidden="true" />
        <div className="relative grid gap-10 lg:grid-cols-2 lg:items-center">
          <div>
            <span className="clay-chip clay-chip-surface px-4 py-1 text-xs font-semibold uppercase tracking-wider text-[var(--clay-ink-muted)]">
              Keamanan Deterministik
            </span>
            <h1 className="mt-4 text-4xl sm:text-5xl font-extrabold tracking-tight leading-[1.08] text-[var(--clay-ink)]">
              Setiap tool call dievaluasi sebelum dieksekusi.
            </h1>
            <p className="mt-4 text-sm sm:text-base text-[var(--clay-ink-muted)] leading-relaxed max-w-md">
              Cerberus adalah policy engine untuk AI agent: izinkan, tolak, dan audit
              setiap aksi — fail-closed by design, tanpa bergantung pada janji probabilistik LLM.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Link href="/docs-intro" className="clay-btn clay-btn-accent px-5 py-2.5 text-sm font-semibold">
                Lihat Dokumentasi
              </Link>
              <Link href="/login" className="clay-btn clay-btn-ghost px-5 py-2.5 text-sm font-semibold">
                Live Dashboard
              </Link>
            </div>
          </div>

          <div className="clay-card p-5 sm:p-6">
            <div className="flex items-center gap-2 mb-4">
              <span className="clay-chip clay-chip-mint size-8">
                <Terminal className="size-4 text-[#155E40]" />
              </span>
              <span className="text-xs font-bold uppercase tracking-wider text-[var(--clay-ink-muted)]">
                Decision Stream
              </span>
            </div>
            <div className="space-y-2.5 font-mono text-[13px] sm:text-sm">
              <div className="rounded-xl bg-[var(--clay-bg)] px-3.5 py-2.5 flex items-center justify-between gap-2">
                <span className="text-[var(--clay-ink)] truncate">tool: grep ERROR app.log</span>
                <span className="shrink-0 font-bold text-[#155E40]">ALLOW</span>
              </div>
              <div className="rounded-xl bg-[var(--clay-bg)] px-3.5 py-2.5 flex items-center justify-between gap-2">
                <span className="text-[var(--clay-ink)] truncate">ssh: deploy@git.teknikal.id</span>
                <span className="shrink-0 font-bold text-[#155E40]">ALLOW</span>
              </div>
              <div className="rounded-xl bg-[var(--clay-bg)] px-3.5 py-2.5 flex items-center justify-between gap-2">
                <span className="text-[var(--clay-ink)] truncate">tool: rm -rf /</span>
                <span className="shrink-0 font-bold text-[#B3261E]">DENY</span>
              </div>
              <div className="rounded-xl bg-[var(--clay-bg)] px-3.5 py-2.5 flex items-center justify-between gap-2">
                <span className="text-[var(--clay-ink)] truncate">llm: &quot;koneksi ke 10.0.3.7&quot;</span>
                <span className="shrink-0 font-bold text-[#B3261E]">DENY</span>
              </div>
            </div>
            <p className="mt-4 text-[11px] text-[var(--clay-ink-muted)] leading-relaxed">
              Contoh nyata kebijakan: allowlist tool, whitelist host SSH, shield perintah
              destruktif, dan blocked-pattern pada prompt LLM.
            </p>
          </div>
        </div>
      </section>

      {/* ===================================================================
          3. (stats band dihapus — internal tools, tanpa angka marketing)
          =================================================================== */}
      <span className="hidden" />

      {/* ===================================================================
          4. FITUR: 3 Puffy Cards dengan pressed-in icon chips
          =================================================================== */}
      <section className="max-w-5xl mx-auto px-4 w-full py-12 sm:py-16">
        <div className="text-center max-w-2xl mx-auto mb-10 sm:mb-12">
          <span className="clay-chip clay-chip-surface px-4 py-1 text-xs font-semibold uppercase tracking-wider text-[var(--clay-ink-muted)]">
            Keamanan Deterministik
          </span>
          <h2 className="mt-3 text-2xl sm:text-3xl md:text-4xl font-extrabold tracking-tight text-[var(--clay-ink)]">
            Arsitektur Zero-Trust untuk Agent Runtime
          </h2>
          <p className="mt-3 text-sm sm:text-base text-[var(--clay-ink-muted)] leading-relaxed">
            Menolak eksekusi destruktif dan eksfiltrasi data tanpa bergantung pada janji probabilistik model LLM.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1: Policy as Data */}
          <div className="clay-card clay-card-press p-7 flex flex-col justify-between">
            <div>
              <div className="clay-chip clay-chip-mint size-12 mb-5">
                <FileCode className="size-6 text-[#155E40]" />
              </div>
              <h3 className="text-xl font-bold text-[var(--clay-ink)]">
                Policy as Data
              </h3>
              <div className="mt-1 inline-block font-mono text-xs font-semibold text-[#155E40]">
                Rego + Dynamic JSON
              </div>
              <p className="mt-3 text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                Seluruh otorisasi didefinisikan secara deklaratif menggunakan Open Policy Agent. Batas token, budget, dan konfigurasi agen dimuat in-memory dengan hot-reload dinamis tanpa restart gateway.
              </p>
            </div>
          </div>

          {/* Card 2: Fail-Closed */}
          <div className="clay-card clay-card-press p-7 flex flex-col justify-between">
            <div>
              <div className="clay-chip clay-chip-butter size-12 mb-5">
                <ShieldAlert className="size-6 text-[#634E14]" />
              </div>
              <h3 className="text-xl font-bold text-[var(--clay-ink)]">
                Fail-Closed by Design
              </h3>
              <div className="mt-1 inline-block font-mono text-xs font-semibold text-[#634E14]">
                Deny by Default
              </div>
              <p className="mt-3 text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                Bila terjadi rule error, parsing gagal, atau service terputus, verdict seketika <strong>DENY</strong>. Proteksi otomatis terhadap variasi destructive command, traversal file, dan subnet IP privat.
              </p>
            </div>
          </div>

          {/* Card 3: Audit Real-Time */}
          <div className="clay-card clay-card-press p-7 flex flex-col justify-between">
            <div>
              <div className="clay-chip clay-chip-lilac size-12 mb-5">
                <Activity className="size-6 text-[#382B68]" />
              </div>
              <h3 className="text-xl font-bold text-[var(--clay-ink)]">
                Audit Real-Time
              </h3>
              <div className="mt-1 inline-block font-mono text-xs font-semibold text-[#382B68]">
                SQLite + Live SSE
              </div>
              <p className="mt-3 text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                Setiap evaluasi dicatat secara asinkron ke database SQLite dengan zero overhead pada latency keputusan utama. Stream Server-Sent Events (SSE) langsung memberi visibilitas ke Owl Dashboard.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          5. CARA KERJA: 3 langkah horizontal bernomor besar + connector
          =================================================================== */}
      <section className="max-w-5xl mx-auto px-4 w-full py-12 sm:py-16">
        <div className="clay-card p-6 sm:p-10">
          <div className="text-center max-w-xl mx-auto mb-10">
            <span className="clay-chip clay-chip-surface px-3 py-1 font-mono text-xs font-semibold text-[var(--clay-ink-muted)]">
              Alur Evaluasi Deterministic
            </span>
            <h2 className="mt-3 text-2xl sm:text-3xl font-extrabold text-[var(--clay-ink)]">
              Cara Kerja Cerberus
            </h2>
            <p className="mt-2 text-sm text-[var(--clay-ink-muted)]">
              Tiga langkah inspeksi deterministik sebelum perintah menyentuh shell atau sistem fisik.
            </p>
          </div>

          <div className="relative grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
            {/* Step 1 */}
            <div className="clay-card p-6 flex flex-col justify-between border border-[var(--clay-border)]">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="clay-chip clay-chip-mint size-11 font-mono font-extrabold text-base text-[#155E40]">
                    1
                  </div>
                  <span className="font-mono text-[11px] font-semibold text-[var(--clay-ink-muted)]">
                    Step 01
                  </span>
                </div>
                <h3 className="font-bold text-base text-[var(--clay-ink)]">
                  Agent Tool Call
                </h3>
                <p className="mt-2 text-xs sm:text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                  AI Agent (Claude, OpenAI, Llama) menginisiasi perintah alat seperti bash command, query SQL, atau request HTTP.
                </p>
              </div>
              <div className="mt-5 pt-3 border-t border-[var(--clay-border)]">
                <span className="font-mono text-[11px] font-bold text-[var(--clay-ink)] bg-[#F0EBE1] px-2.5 py-1 rounded-md">
                  POST /v1/decide
                </span>
              </div>
            </div>

            {/* Step 2 */}
            <div className="clay-card p-6 flex flex-col justify-between border border-[var(--clay-border)]">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="clay-chip clay-chip-butter size-11 font-mono font-extrabold text-base text-[#634E14]">
                    2
                  </div>
                  <span className="font-mono text-[11px] font-semibold text-[var(--clay-ink-muted)]">
                    Step 02
                  </span>
                </div>
                <h3 className="font-bold text-base text-[var(--clay-ink)]">
                  Cerberus Decide (&le;20ms)
                </h3>
                <p className="mt-2 text-xs sm:text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                  Engine OPA mengevaluasi konteks payload terhadap OPA Rego rules, batasan token rate-limit, dan pola regex berbahaya.
                </p>
              </div>
              <div className="mt-5 pt-3 border-t border-[var(--clay-border)]">
                <span className="font-mono text-[11px] font-bold text-[var(--clay-ink)] bg-[#F0EBE1] px-2.5 py-1 rounded-md">
                  OPA Rego Rules &bull; p50 &le; 20ms
                </span>
              </div>
            </div>

            {/* Step 3 */}
            <div className="clay-card p-6 flex flex-col justify-between border border-[var(--clay-border)]">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="clay-chip clay-chip-coral size-11 font-mono font-extrabold text-base text-[#8C2C0B]">
                    3
                  </div>
                  <span className="font-mono text-[11px] font-semibold text-[var(--clay-ink-muted)]">
                    Step 03
                  </span>
                </div>
                <h3 className="font-bold text-base text-[var(--clay-ink)]">
                  Jalan atau Ditolak
                </h3>
                <p className="mt-2 text-xs sm:text-sm text-[var(--clay-ink-muted)] leading-relaxed">
                  Aksi aman dieksekusi dengan secret masking otomatis. Perintah destructive seketika dibatalkan secara fail-closed.
                </p>
              </div>
              <div className="mt-5 pt-3 border-t border-[var(--clay-border)]">
                <span className="font-mono text-[11px] font-bold text-[#155E40] bg-[#BFE8D9]/40 px-2.5 py-1 rounded-md">
                  ALLOW / DENY + masked_args
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          6. SDK SECTION: 3 chip bahasa + code snippet install mini
          =================================================================== */}
      <section className="max-w-5xl mx-auto px-4 w-full py-12 sm:py-16">
        <div className="clay-card p-6 sm:p-10">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
            <div>
              <span className="clay-chip clay-chip-surface px-3 py-1 font-mono text-xs font-semibold text-[var(--clay-ink-muted)]">
                Developer First
              </span>
              <h2 className="mt-2 text-2xl sm:text-3xl font-extrabold text-[var(--clay-ink)]">
                Integrasi SDK Sederhana
              </h2>
              <p className="mt-1 text-xs sm:text-sm text-[var(--clay-ink-muted)]">
                Semua library dirancang tanpa dependency runtime pihak ketiga.
              </p>
            </div>

            {/* 3 Chip Bahasa */}
            <div className="flex items-center gap-2 self-start sm:self-center bg-[#ECE5DA] p-1.5 rounded-full">
              <button
                type="button"
                onClick={() => setActiveTab("go")}
                className={`clay-btn clay-btn-sm font-mono font-semibold transition-all ${
                  activeTab === "go"
                    ? "bg-[var(--clay-surface)] text-[var(--clay-ink)] shadow-sm"
                    : "bg-transparent text-[var(--clay-ink-muted)] hover:text-[var(--clay-ink)]"
                }`}
              >
                Go
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("python")}
                className={`clay-btn clay-btn-sm font-mono font-semibold transition-all ${
                  activeTab === "python"
                    ? "bg-[var(--clay-surface)] text-[var(--clay-ink)] shadow-sm"
                    : "bg-transparent text-[var(--clay-ink-muted)] hover:text-[var(--clay-ink)]"
                }`}
              >
                Python
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("ts")}
                className={`clay-btn clay-btn-sm font-mono font-semibold transition-all ${
                  activeTab === "ts"
                    ? "bg-[var(--clay-surface)] text-[var(--clay-ink)] shadow-sm"
                    : "bg-transparent text-[var(--clay-ink-muted)] hover:text-[var(--clay-ink)]"
                }`}
              >
                TypeScript
              </button>
            </div>
          </div>

          {/* Snippet Install mini */}
          <div className="space-y-4">
            <div className="clay-card p-4 bg-[#F2EDE5] border border-[var(--clay-border)] flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 min-w-0 font-mono text-[13px] sm:text-sm font-medium text-[var(--clay-ink)]">
                <span className="text-[var(--clay-accent)] select-none font-bold">$</span>
                <code className="break-all">{sdkSnippets[activeTab].install}</code>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(sdkSnippets[activeTab].install)}
                className="clay-btn clay-btn-ghost clay-btn-sm shrink-0 gap-1.5 text-xs"
                title="Salin perintah install"
              >
                {copied ? <Check className="size-3.5 text-[#155E40]" /> : <Copy className="size-3.5" />}
                {copied ? "Disalin" : "Salin"}
              </button>
            </div>

            {/* Code Snippet Box */}
            <div className="clay-card p-5 sm:p-6 bg-[#2D2A26] text-[#F6F1E9] border-none">
              <div className="flex items-center justify-between pb-3 mb-3 border-b border-white/10 font-mono text-xs">
                <span className="text-white/60">{sdkSnippets[activeTab].ext}</span>
                <span className="text-white/40">stdlib only</span>
              </div>
              <pre className="font-mono text-[13px] sm:text-sm leading-relaxed text-[#F6F1E9] whitespace-pre-wrap break-words">
                {sdkSnippets[activeTab].code}
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          7. CTA BAND: Kartu band clay besar accent-tinted
          =================================================================== */}
      <section className="max-w-5xl mx-auto px-4 w-full py-12 sm:py-16">
        <div className="clay-card p-8 sm:p-12 text-center bg-[#FFF7F3] border-[#FFD9CC] relative overflow-hidden">
          <div
            aria-hidden="true"
            className="clay-blob absolute -top-10 -right-10 w-48 h-48 bg-[#FFD9CC] opacity-60 blur-2xl"
          />
          <div className="relative z-10 max-w-2xl mx-auto space-y-4">
            <span className="clay-chip clay-chip-coral px-4 py-1 text-xs font-semibold uppercase tracking-wider">
              Siap Mengamankan Agent Anda?
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-[var(--clay-ink)] tracking-tight">
              Coba Cerberus di dashboard
            </h2>
            <p className="text-sm sm:text-base text-[var(--clay-ink-muted)] leading-relaxed">
              Pantau audit log secara real-time melalui stream SSE, kelola token otorisasi, dan jalankan simulasi evaluasi tool sekarang.
            </p>
            <div className="pt-4 flex flex-wrap items-center justify-center gap-4">
              <Link href="/login" className="clay-btn clay-btn-accent">
                Coba Live Dashboard
                <ArrowRight className="size-4" />
              </Link>
              <Link href="/docs-intro" className="clay-btn clay-btn-ghost">
                Pelajari Dokumentasi
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ===================================================================
          8. FOOTER ROUNDED-TOP: Cream lebih gelap sedikit
          =================================================================== */}
      <footer className="clay-footer px-6 py-12 sm:py-14 mt-auto">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-6 text-center sm:text-left">
          {/* Logo & Microcopy */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-center sm:justify-start gap-2">
              <span className="clay-chip clay-chip-coral text-sm size-6">🦉</span>
              <span className="font-bold text-sm text-[var(--clay-ink)] tracking-tight">
                Cerberus Policy Engine
              </span>
            </div>
            <p className="text-xs text-[var(--clay-ink-muted)]">
              Cerberus v1.0 &bull; Policy engine untuk AI agent &bull; Fail-closed by design
            </p>
          </div>

          {/* Links */}
          <div className="flex flex-wrap items-center justify-center gap-4 text-xs font-semibold text-[var(--clay-ink-muted)]">
            <Link href="/docs-intro" className="hover:text-[var(--clay-ink)] transition-colors">
              Dokumentasi
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
