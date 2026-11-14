import { NextResponse } from "next/server";
import { SESSION_COOKIE, extractSessionToken } from "@/lib/session";

export async function POST(req: Request) {
  const engineUrl = process.env.CERBERUS_URL ?? "http://localhost:8089";
  const cookieHeader = req.headers.get("cookie");
  const tokenMatch = cookieHeader?.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  const rawCookie = tokenMatch ? decodeURIComponent(tokenMatch[1]) : "";
  const token = extractSessionToken(rawCookie) || rawCookie;

  if (token) {
    try {
      await fetch(`${engineUrl}/v1/auth/logout`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        cache: "no-store",
      });
    } catch {
      // Continue clearing cookie even if engine call failed
    }
  }

  const res = new NextResponse(null, { status: 204 });
  res.cookies.delete(SESSION_COOKIE);
  return res;
}
