"use client";

import { useState } from "react";
import { toast } from "sonner";
import { Check, ChevronDown, ChevronUp, Copy, HelpCircle, Terminal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export function ConnectInfoCard() {
  const [isOpen, setIsOpen] = useState(true);
  const [copiedEnv, setCopiedEnv] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);

  const envSnippet = `CERBERUS_URL=http://localhost:8089
CERBERUS_KEY=k-your-agent-id`;

  const curlSnippet = `curl -X POST $CERBERUS_URL/v1/decide/tool \\
  -H "X-Cerberus-Key: $CERBERUS_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"stage":"tool","key_id":"'$CERBERUS_KEY'","action":"read","resource":"x"}'`;

  const copyToClipboard = async (text: string, type: "env" | "curl") => {
    try {
      await navigator.clipboard.writeText(text);
      if (type === "env") {
        setCopiedEnv(true);
        setTimeout(() => setCopiedEnv(false), 2000);
        toast.success("Konfigurasi ENV berhasil disalin!");
      } else {
        setCopiedCurl(true);
        setTimeout(() => setCopiedCurl(false), 2000);
        toast.success("Snippet cURL berhasil disalin!");
      }
    } catch {
      toast.error("Gagal menyalin ke clipboard");
    }
  };

  return (
    <Card className="border-primary/20 bg-card">
      <CardHeader className="cursor-pointer py-3 px-4" onClick={() => setIsOpen(!isOpen)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <HelpCircle className="size-4 text-primary" />
            <CardTitle className="text-sm font-semibold">
              Bagaimana agent memanggil Cerberus?
            </CardTitle>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="size-7 text-muted-foreground"
            onClick={(e) => {
              e.stopPropagation();
              setIsOpen(!isOpen);
            }}
            aria-label={isOpen ? "Sembunyikan panduan" : "Tampilkan panduan"}
          >
            {isOpen ? <ChevronUp className="size-4" /> : <ChevronDown className="size-4" />}
          </Button>
        </div>
      </CardHeader>

      {isOpen && (
        <CardContent className="px-4 pb-4 pt-1 space-y-3 text-xs border-t bg-muted/10">
          {/* 3 Baris Penjelasan Singkat */}
          <div className="space-y-1.5 text-muted-foreground leading-relaxed pt-2">
            <p>
              1. <strong>Tanpa OAuth Secret:</strong> Kredensial agen adalah <strong>Key ID</strong> itu sendiri — tidak ada <code>client_id</code> atau <code>client_secret</code> terpisah.
            </p>
            <p>
              2. <strong>Header yang Dikenali:</strong> Kirim key melalui <code>X-Cerberus-Key</code>, <code>X-Policy-Key</code>, <code>Proxy-Authorization</code>, atau <code>Authorization: Bearer &lt;key_id&gt;</code>.
            </p>
            <p>
              3. <strong>Admin vs Agent:</strong> Dashboard admin menggunakan <code>CERBERUS_ADMIN_TOKEN</code> via proxy <code>/api/*</code>, sedangkan agent memanggil endpoint evaluasi seperti <code>/v1/decide/tool</code>.
            </p>
          </div>

          {/* Snippets Grid */}
          <div className="grid gap-3 sm:grid-cols-2 pt-1">
            {/* Snippet ENV */}
            <div className="rounded-md border bg-background p-2.5 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-[11px] text-muted-foreground flex items-center gap-1">
                  <Terminal className="size-3" /> Environment Variables
                </span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-5 px-1.5 text-[10px] gap-1 text-muted-foreground hover:text-foreground"
                  onClick={() => copyToClipboard(envSnippet, "env")}
                >
                  {copiedEnv ? <Check className="size-2.5 text-success" /> : <Copy className="size-2.5" />}
                  {copiedEnv ? "Tersalin" : "Salin ENV"}
                </Button>
              </div>
              <pre className="font-mono text-[11px] bg-muted/40 p-1.5 rounded select-all overflow-x-auto text-foreground">
                {envSnippet}
              </pre>
            </div>

            {/* Snippet cURL */}
            <div className="rounded-md border bg-background p-2.5 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-[11px] text-muted-foreground flex items-center gap-1">
                  <Terminal className="size-3" /> Contoh Panggilan cURL
                </span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-5 px-1.5 text-[10px] gap-1 text-muted-foreground hover:text-foreground"
                  onClick={() => copyToClipboard(curlSnippet, "curl")}
                >
                  {copiedCurl ? <Check className="size-2.5 text-success" /> : <Copy className="size-2.5" />}
                  {copiedCurl ? "Tersalin" : "Salin cURL"}
                </Button>
              </div>
              <pre className="font-mono text-[11px] bg-muted/40 p-1.5 rounded select-all overflow-x-auto text-foreground">
                {curlSnippet}
              </pre>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  );
}
