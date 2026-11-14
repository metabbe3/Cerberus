import type { NextRequest } from "next/server";
import { getBreaches, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const params = req.nextUrl.searchParams;
    const res = await getBreaches(params);
    return Response.json(res);
  } catch (e) {
    return toErrorResponse(e);
  }
}
