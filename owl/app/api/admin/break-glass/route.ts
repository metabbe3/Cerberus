import type { NextRequest } from "next/server";
import { postBreakGlass, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const result = await postBreakGlass(body);
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}
