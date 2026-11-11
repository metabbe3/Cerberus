import { NextResponse } from "next/server";

// Server-side proxy for the engine components health report — same pattern as
// the audit/timeseries proxies: token stays server-side.
const ENGINE = process.env.CERBERUS_URL ?? "http://127.0.0.1:8089";

export async function GET() {
  const token = process.env.CERBERUS_ADMIN_TOKEN;
  if (!token) {
    return NextResponse.json({ error: "CERBERUS_ADMIN_TOKEN is not set" }, { status: 500 });
  }
  const res = await fetch(`${ENGINE}/v1/health/components`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
}
