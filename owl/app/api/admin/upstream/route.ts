import type { NextRequest } from "next/server";
import { getUpstream, putUpstream, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    return Response.json(await getUpstream());
  } catch (e) {
    return toErrorResponse(e);
  }
}

export async function PUT(req: NextRequest) {
  try {
    const body = (await req.json()) as { endpoint?: string; api_key?: string };
    const endpoint = (body.endpoint ?? "").trim();
    if (!/^https?:\/\//.test(endpoint)) {
      return Response.json({ error: "endpoint harus http(s)://…" }, { status: 422 });
    }
    if (body.api_key !== undefined && body.api_key !== "" && body.api_key.length < 8) {
      return Response.json({ error: "api_key minimal 8 karakter" }, { status: 422 });
    }
    const payload: { endpoint: string; api_key?: string } = { endpoint };
    if (body.api_key) payload.api_key = body.api_key;
    return Response.json(await putUpstream(payload));
  } catch (e) {
    return toErrorResponse(e);
  }
}
