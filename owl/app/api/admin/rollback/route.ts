import type { NextRequest } from "next/server";
import { rollbackData, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json().catch(() => ({}))) as { revision_id?: number };
    const result = await rollbackData(body.revision_id);
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}
