import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE, authEnv, verifySession } from "@/lib/session";

// Every page and /api route needs a valid session, except /login, public landing (/),
// and the auth endpoints (see matcher). Pages redirect; APIs answer 401 JSON.
export async function middleware(req: NextRequest) {
  // Public routes: landing root and public docs intro — no session required.
  if (req.nextUrl.pathname === "/" || req.nextUrl.pathname.startsWith("/docs-intro")) {
    return NextResponse.next();
  }
  const env = authEnv();
  const ok = env !== null && (await verifySession(req.cookies.get(SESSION_COOKIE)?.value, env.secret));
  if (ok) return NextResponse.next();

  if (req.nextUrl.pathname.startsWith("/api/")) {
    return NextResponse.json({ error: "Not signed in" }, { status: 401 });
  }
  const next = req.nextUrl.pathname + req.nextUrl.search;
  const target = next !== "/" ? `/login?next=${encodeURIComponent(next)}` : "/login";
  // This runtime build breaks on NextResponse.redirect/rewrite behind a
  // proxy (relative req.url -> ERR_INVALID_URL internally). Serve a tiny
  // HTML page that sends the browser to /login via meta refresh instead —
  // no URL construction anywhere.
  const esc = target.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
  return new NextResponse(
    `<!doctype html><html><head><meta charset="utf-8"><title>Owl — login</title>` +
      `<meta http-equiv="refresh" content="0;url=${esc}">` +
      `</head><body><p>Mengalihkan ke login… <a href="${esc}">lanjut</a></p></body></html>`,
    { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|login|api/auth/|$).*)"],
};
