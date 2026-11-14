import { NextResponse } from "next/server";
import { SESSION_COOKIE, extractSessionToken } from "@/lib/session";

export async function POST(req: Request) {
  const engineUrl = process.env.CERBERUS_URL ?? "http://localhost:8089";
  const cookieHeader = req.headers.get("cookie");
  const tokenMatch = cookieHeader?.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  const rawCookie = tokenMatch ? decodeURIComponent(tokenMatch[1]) : "";
  const token = extractSessionToken(rawCookie) || rawCookie;

  let body: { current_password?: string; new_password?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "body JSON tidak valid" }, { status: 400 });
  }
  if (!body.current_password || !body.new_password) {
    return NextResponse.json(
      { error: "current_password dan new_password wajib diisi" },
      { status: 400 },
    );
  }

  try {
    const res = await fetch(`${engineUrl}/v1/auth/password`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      return NextResponse.json(
        { error: (data.message as string) ?? (data.error as string) ?? `engine ${res.status}` },
        { status: res.status },
      );
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ error: "engine tidak terjangkau" }, { status: 502 });
  }
}
