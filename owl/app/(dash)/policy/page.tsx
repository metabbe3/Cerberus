"use client";

import { useMemo, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { usePolicyModules, useRunPolicyTests } from "@/lib/queries";
import type { TestRunResponse } from "@/lib/schema";
import {
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  FileCode2,
  Play,
  RotateCw,
  Search,
  ShieldCheck,
  XCircle,
} from "lucide-react";

export default function PolicyExplorerPage() {
  const { data: modules, isPending, isError, error } = usePolicyModules();
  const runTestsMutation = useRunPolicyTests();
  const [testResult, setTestResult] = useState<TestRunResponse | null>(null);
  const [search, setSearch] = useState("");
  const [showTests, setShowTests] = useState(false);

  const filteredModules = useMemo(() => {
    if (!modules) return [];
    if (!search.trim()) return modules;
    const q = search.toLowerCase();
    return modules.filter(
      (m) =>
        m.file.toLowerCase().includes(q) ||
        m.package.toLowerCase().includes(q) ||
        m.sha256.toLowerCase().includes(q),
    );
  }, [modules, search]);

  const packageCount = useMemo(() => {
    if (!modules) return 0;
    const pkgs = new Set(modules.map((m) => m.package).filter(Boolean));
    return pkgs.size;
  }, [modules]);

  const handleRunTests = async () => {
    try {
      const res = await runTestsMutation.mutateAsync();
      setTestResult(res);
      setShowTests(true);
    } catch {
      // handled by mutation error
    }
  };

  if (isPending) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="size-4" />
        <AlertTitle>Gagal memuat modul kebijakan</AlertTitle>
        <AlertDescription>{error.message}</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Policy Explorer"
        description="Inventaris modul Rego read-only dan eksekusi test verification suite."
      >
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            asChild
            className="text-xs"
          >
            <a
              href="https://github.com/metabbe3/cerberus/blob/main/docs/INTEGRATION.md"
              target="_blank"
              rel="noreferrer"
            >
              <ExternalLink className="mr-1.5 size-3.5" />
              Edit via bundle
            </a>
          </Button>

          <Button
            onClick={handleRunTests}
            disabled={runTestsMutation.isPending}
            className="text-xs"
          >
            {runTestsMutation.isPending ? (
              <>
                <RotateCw className="mr-1.5 size-3.5 animate-spin" />
                Running tests…
              </>
            ) : (
              <>
                <Play className="mr-1.5 size-3.5" />
                Run tests
              </>
            )}
          </Button>
        </div>
      </PageHeader>

      {/* KPI Cards / Summary */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="text-xs">Modul Rego</CardDescription>
            <CardTitle className="text-2xl font-bold tabular-nums">
              {modules.length}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            {packageCount} unique packages
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="text-xs">Status Verifikasi Test</CardDescription>
            <CardTitle className="text-2xl font-bold flex items-center gap-2">
              {testResult ? (
                testResult.failed === 0 ? (
                  <Badge variant="outline" className="bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-sm font-semibold py-0.5">
                    <CheckCircle2 className="mr-1 size-3.5 inline" />
                    {testResult.passed}/{testResult.total} passing
                  </Badge>
                ) : (
                  <Badge variant="destructive" className="text-sm font-semibold py-0.5">
                    <XCircle className="mr-1 size-3.5 inline" />
                    {testResult.failed} failed
                  </Badge>
                )
              ) : (
                <span className="text-muted-foreground text-base font-normal">
                  Belum diuji turn ini
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            {testResult ? (
              <span className="tabular-nums font-mono">
                Durasi: {testResult.duration_ms.toFixed(1)}ms
              </span>
            ) : (
              "Klik 'Run tests' untuk menjalankan OPA suite"
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="text-xs">Mode Kebijakan</CardDescription>
            <CardTitle className="text-base font-semibold flex items-center gap-2 pt-1">
              <ShieldCheck className="size-4 text-primary" />
              READ-ONLY
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            Perubahan hanya melalui signed tar.gz bundle release.
          </CardContent>
        </Card>
      </div>

      {runTestsMutation.isError && (
        <Alert variant="destructive">
          <AlertCircle className="size-4" />
          <AlertTitle>Eksekusi test gagal</AlertTitle>
          <AlertDescription>{runTestsMutation.error.message}</AlertDescription>
        </Alert>
      )}

      {/* Test Results Drawer / Section */}
      {testResult && (
        <Card className="border-border">
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                Hasil Test Rego
                <Badge
                  variant={testResult.failed === 0 ? "outline" : "destructive"}
                  className={
                    testResult.failed === 0
                      ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 font-mono text-xs"
                      : "font-mono text-xs"
                  }
                >
                  {testResult.passed}/{testResult.total} PASS
                </Badge>
              </CardTitle>
              <CardDescription className="text-xs">
                Total {testResult.total} test case dievaluasi dalam{" "}
                <span className="font-mono tabular-nums">{testResult.duration_ms.toFixed(1)}ms</span>.
              </CardDescription>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowTests(!showTests)}
              className="text-xs"
            >
              {showTests ? "Sembunyikan detail" : "Lihat detail test"}
            </Button>
          </CardHeader>
          {showTests && (
            <CardContent className="pt-0">
              <div className="max-h-72 overflow-y-auto rounded-md border text-xs">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-16">Status</TableHead>
                      <TableHead>Test Name</TableHead>
                      <TableHead>Package</TableHead>
                      <TableHead className="text-right w-24">Latency</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {testResult.tests.map((t, idx) => (
                      <TableRow key={`${t.package}.${t.name}-${idx}`}>
                        <TableCell>
                          {t.pass ? (
                            <Badge variant="outline" className="bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-[10px]">
                              PASS
                            </Badge>
                          ) : (
                            <Badge variant="destructive" className="text-[10px]">
                              FAIL
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="font-mono font-medium">
                          {t.name}
                          {t.msg && (
                            <div className="text-destructive text-[11px] font-sans mt-0.5">
                              {t.msg}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-muted-foreground">
                          {t.package}
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums text-muted-foreground">
                          {t.duration_ms.toFixed(2)}ms
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {/* Modules Table Filter */}
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-4">
          <div className="relative w-72">
            <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
            <Input
              placeholder="Cari file atau package…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 text-xs"
            />
          </div>
          <span className="text-xs text-muted-foreground tabular-nums">
            Menampilkan {filteredModules.length} dari {modules.length} modul
          </span>
        </div>

        {/* Modules Table */}
        <div className="rounded-md border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-80">File</TableHead>
                <TableHead>Package</TableHead>
                <TableHead className="w-28 text-right">Size</TableHead>
                <TableHead className="w-36">SHA-256</TableHead>
                <TableHead className="w-44 text-right">Last Modified</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredModules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="h-24 text-center text-muted-foreground text-xs">
                    Tidak ada modul yang cocok dengan kueri pencarian.
                  </TableCell>
                </TableRow>
              ) : (
                filteredModules.map((m) => (
                  <TableRow key={m.file} className="hover:bg-muted/50">
                    <TableCell className="font-mono text-xs font-medium flex items-center gap-2">
                      <FileCode2 className="size-3.5 text-muted-foreground shrink-0" />
                      <span className="truncate" title={m.file}>
                        {m.file}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {m.package || "—"}
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                      {m.size > 1024 ? `${(m.size / 1024).toFixed(1)} KB` : `${m.size} B`}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <span
                        className="bg-muted px-1.5 py-0.5 rounded text-[11px] text-muted-foreground"
                        title={m.sha256}
                      >
                        {m.sha256.slice(0, 8)}…{m.sha256.slice(-4)}
                      </span>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">
                      {new Date(m.mtime).toLocaleString("id-ID", {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  );
}
