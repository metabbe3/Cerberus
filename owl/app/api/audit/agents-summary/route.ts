import type { NextRequest } from "next/server";
import { getAgentsSummary, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const since = req.nextUrl.searchParams.get("since") ?? undefined;
    const res = await getAgentsSummary(since);
    return Response.json(res);
  } catch (e) {
    return toErrorResponse(e);
  }
}
