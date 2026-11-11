import type { NextRequest } from "next/server";
import { queryAudit, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    return Response.json(await queryAudit(req.nextUrl.searchParams));
  } catch (e) {
    return toErrorResponse(e);
  }
}
