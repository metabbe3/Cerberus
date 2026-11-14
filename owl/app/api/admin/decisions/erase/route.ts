import type { NextRequest } from "next/server";
import { eraseDecision, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const result = await eraseDecision(Number(body.id));
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}
