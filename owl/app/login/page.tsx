"use client";

import { AlertCircle, Loader2, LogIn } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { ThemeToggle } from "@/components/theme-toggle";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { safeNext } from "@/lib/session";

function LoginForm() {
  const params = useSearchParams();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setPending(true);
    setError(null);
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }).catch(() => null);
    if (res?.ok) {
      // Full navigation so middleware sees the fresh cookie.
      window.location.href = safeNext(params.get("next"));
      return;
    }
    const body = (await res?.json().catch(() => null)) as { error?: string } | null;
    setError(body?.error ?? "Gagal terhubung ke engine Cerberus");
    setPassword("");
    setPending(false);
  };

  return (
    <form onSubmit={submit} className="space-y-4">
      {error ? (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <div className="space-y-2">
        <Label htmlFor="username">Nama pengguna (Username)</Label>
        <Input
          id="username"
          type="text"
          autoComplete="username"
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Kata sandi</Label>
        <Input
          id="password"
          aria-label="Kata sandi"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <Button type="submit" className="w-full" size="lg" disabled={pending || !password}>
        {pending ? <Loader2 className="animate-spin" /> : <LogIn />}
        Masuk
      </Button>
    </form>
  );
}

export default function LoginPage() {
  return (
    <div className="relative grid min-h-svh place-items-center bg-[radial-gradient(ellipse_at_top,var(--accent),transparent_60%)] px-4">
      <h1 className="sr-only">Masuk ke Owl</h1>
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <Card className="w-full max-w-sm shadow-lg">
        <CardHeader className="items-center text-center">
          <div
            className="mx-auto mb-2 grid size-12 place-items-center rounded-xl bg-primary/15 text-2xl"
            aria-hidden
          >
            🦉
          </div>
          <CardTitle className="text-xl">Sign in to Owl</CardTitle>
          <CardDescription>Cerberus policy dashboard</CardDescription>
        </CardHeader>
        <CardContent>
          {/* useSearchParams needs a Suspense boundary for static prerender. */}
          <Suspense>
            <LoginForm />
          </Suspense>
        </CardContent>
      </Card>
    </div>
  );
}
