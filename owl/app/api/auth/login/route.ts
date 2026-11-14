import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_TTL_SEC,
  authEnv,
  signEngineSession,
} from "@/lib/session";

function clientIP(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  return (xff ? xff.split(",")[0].trim() : null) ?? "127.0.0.1";
}

export async function POST(req: Request) {
  const env = authEnv();
  const engineUrl = process.env.CERBERUS_URL ?? "http://localhost:8089";

  const body = (await req.json().catch(() => null)) as {
    username?: unknown;
    password?: unknown;
  } | null;

  const username =
    typeof body?.username === "string" && body.username.trim()
      ? body.username.trim()
      : "admin";
  const password = typeof body?.password === "string" ? body.password : "";

  const ip = clientIP(req);

  let engineRes: Response;
  try {
    engineRes = await fetch(`${engineUrl}/v1/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": ip,
      },
      body: JSON.stringify({ username, password }),
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { error: "Gagal terhubung ke engine autentikasi Cerberus" },
      { status: 502 },
    );
  }

  const resBody = (await engineRes.json().catch(() => null)) as {
    token?: string;
    error?: string;
    user?: unknown;
  } | null;

  if (!engineRes.ok) {
    const errorMsg = resBody?.error || `Login ditolak (HTTP ${engineRes.status})`;
    return NextResponse.json({ error: errorMsg }, { status: engineRes.status });
  }

  if (!resBody?.token) {
    return NextResponse.json(
      { error: "Token sesi tidak diterima dari engine" },
      { status: 500 },
    );
  }

  const secret = env?.secret ?? "owl-session-secret-cerberus-production-grade-32b";
  const cookieVal = await signEngineSession(resBody.token, secret);

  const res = NextResponse.json({ ok: true, user: resBody.user }, { status: 200 });
  res.cookies.set(SESSION_COOKIE, cookieVal, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production" && process.env.OWL_INSECURE_COOKIE !== "1",
    path: "/",
    maxAge: SESSION_TTL_SEC,
  });

  return res;
}
