import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE, authEnv, verifySession } from "@/lib/session";

// Every page and /api route needs a valid session, except /login and the
// auth endpoints (see matcher). Pages redirect; APIs answer 401 JSON.
export async function middleware(req: NextRequest) {
  const env = authEnv();
  const ok = env !== null && (await verifySession(req.cookies.get(SESSION_COOKIE)?.value, env.secret));
  if (ok) return NextResponse.next();

  if (req.nextUrl.pathname.startsWith("/api/")) {
    return NextResponse.json({ error: "Not signed in" }, { status: 401 });
  }
  // Behind a reverse proxy (cloudflared) the standalone server ignores the
  // Host header, so req.url carries localhost:<port> and Next anchors
  // absolute redirects to that origin. Start from the canonical redirect,
  // then override Location to a relative path — browsers resolve it against
  // the host they actually used, keeping the redirect proxy-safe.
  const next = req.nextUrl.pathname + req.nextUrl.search;
  const target = next !== "/" ? `/login?next=${encodeURIComponent(next)}` : "/login";
  const res = NextResponse.redirect(new URL("/login", req.url));
  res.headers.set("location", target);
  return res;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|login|api/auth/).*)"],
};
