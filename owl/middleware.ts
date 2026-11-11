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
  const login = new URL("/login", req.url);
  const next = req.nextUrl.pathname + req.nextUrl.search;
  if (next !== "/") login.searchParams.set("next", next);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|login|api/auth/).*)"],
};
