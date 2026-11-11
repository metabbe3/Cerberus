import { NextResponse } from "next/server";

// Server-side proxy for the engine timeseries endpoint — the browser never
// sees the admin token. Mirrors the other /api proxies (audit, data).
const ENGINE = process.env.CERBERUS_URL ?? "http://127.0.0.1:8089";

export async function GET(req: Request) {
  const token = process.env.CERBERUS_ADMIN_TOKEN;
  if (!token) {
    return NextResponse.json({ error: "CERBERUS_ADMIN_TOKEN is not set" }, { status: 500 });
  }
  const url = new URL(req.url);
  const allowed = ["since", "until", "buckets", "key_id", "stage", "decision", "rule_id"];
  const qs = new URLSearchParams();
  for (const k of allowed) {
    const v = url.searchParams.get(k);
    if (v) qs.set(k, v);
  }
  const res = await fetch(`${ENGINE}/v1/audit/timeseries?${qs.toString()}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "content-type": "application/json" },
  });
}
