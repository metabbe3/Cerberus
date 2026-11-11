import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_TTL_SEC,
  authEnv,
  checkPassword,
  signSession,
} from "@/lib/session";

// ponytail: a flat delay on failure is the whole brute-force defence —
// put a rate limiter (or SSO) in front if Owl is ever internet-facing.
const FAIL_DELAY_MS = 500;

export async function POST(req: Request) {
  const env = authEnv();
  if (!env) {
    return NextResponse.json(
      { error: "Owl auth not configured: set OWL_PASSWORD and OWL_SESSION_SECRET" },
      { status: 503 },
    );
  }
  const body = (await req.json().catch(() => null)) as { password?: unknown } | null;
  const password = typeof body?.password === "string" ? body.password : "";
  if (!(await checkPassword(password, env.password))) {
    await new Promise((r) => setTimeout(r, FAIL_DELAY_MS));
    return NextResponse.json({ error: "Wrong password" }, { status: 401 });
  }
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
