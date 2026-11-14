import type { NextRequest } from "next/server";
import { testUpstream, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as { endpoint?: string; api_key?: string };
    const payload: { endpoint: string; api_key?: string } = {
      endpoint: (body.endpoint ?? "").trim(),
    };
    if (body.api_key) payload.api_key = body.api_key;
    return Response.json(await testUpstream(payload));
  } catch (e) {
    return toErrorResponse(e);
  }
}
