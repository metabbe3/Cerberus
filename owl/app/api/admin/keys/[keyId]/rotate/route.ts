import type { NextRequest } from "next/server";
import { rotateKey, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ keyId: string }> },
) {
  try {
    const { keyId } = await context.params;
    let body = {};
    try {
      body = await req.json();
    } catch {
      // empty body allowed
    }
    const res = await rotateKey(keyId, body);
    return Response.json(res);
  } catch (e) {
    return toErrorResponse(e);
  }
}
