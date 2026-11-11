import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_TTL_SEC,
  authEnv,
  checkPassword,
  signSession,
} from "@/lib/session";

// Brute-force defence, Grafana-style: flat delay on failure PLUS a
// per-IP sliding-window limiter with lockout. In-memory is correct for the
// single-process standalone server; a multi-node Owl would move this to the
// engine (which already rate-limits /v1/decide with the same pattern).
const FAIL_DELAY_MS = 500;
const MAX_FAILS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 5 fails within 15 minutes…
const LOCK_MS = 15 * 60 * 1000;   // …locks the IP out for 15 minutes.

type Attempt = { fails: number[]; lockedUntil: number };
const attempts = new Map<string, Attempt>();

function clientIP(req: Request): string {
  // Cloudflare → engine loopback; x-forwarded-for first hop is the client.
  const xff = req.headers.get("x-forwarded-for");
  return (xff ? xff.split(",")[0].trim() : null) ?? "local";
}

function lockoutRemaining(ip: string, now: number): number {
  const a = attempts.get(ip);
  if (!a) return 0;
  if (a.lockedUntil > now) return a.lockedUntil - now;
  if (a.lockedUntil !== 0 && a.lockedUntil <= now) attempts.delete(ip);
  return 0;
}

function recordFail(ip: string, now: number): void {
  const a = attempts.get(ip) ?? { fails: [], lockedUntil: 0 };
  a.fails = a.fails.filter((t) => now - t < WINDOW_MS);
  a.fails.push(now);
  if (a.fails.length >= MAX_FAILS) {
    a.lockedUntil = now + LOCK_MS;
    a.fails = [];
  }
  attempts.set(ip, a);
}

export async function POST(req: Request) {
  const env = authEnv();
  if (!env) {
    return NextResponse.json(
      { error: "Owl auth not configured: set OWL_PASSWORD and OWL_SESSION_SECRET" },
      { status: 503 },
    );
  }
  const now = Date.now();
  const ip = clientIP(req);
  const waitMs = lockoutRemaining(ip, now);
  if (waitMs > 0) {
    return NextResponse.json(
      { error: `Too many failed attempts — try again in ${Math.ceil(waitMs / 60000)} min` },
      { status: 429, headers: { "Retry-After": String(Math.ceil(waitMs / 1000)) } },
    );
  }
  const body = (await req.json().catch(() => null)) as { password?: unknown } | null;
  const password = typeof body?.password === "string" ? body.password : "";
  if (!(await checkPassword(password, env.password))) {
    recordFail(ip, now);
    await new Promise((r) => setTimeout(r, FAIL_DELAY_MS));
    return NextResponse.json({ error: "Wrong password" }, { status: 401 });
  }
  attempts.delete(ip); // success clears the slate
  const res = new NextResponse(null, { status: 204 });
  res.cookies.set(SESSION_COOKIE, await signSession(env.secret), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production" && process.env.OWL_INSECURE_COOKIE !== "1",
    path: "/",
    maxAge: SESSION_TTL_SEC,
  });
  return res;
}
