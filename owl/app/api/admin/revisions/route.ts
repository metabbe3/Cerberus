import type { NextRequest } from "next/server";
import { getRevisions, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const limit = Number(req.nextUrl.searchParams.get("limit") ?? 50);
    const revs = await getRevisions(limit);
    return Response.json(revs);
  } catch (e) {
    return toErrorResponse(e);
  }
}
