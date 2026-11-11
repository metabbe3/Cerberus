import type { NextRequest } from "next/server";
import { getData, putData, toErrorResponse } from "@/lib/engine";
import { parseData } from "@/lib/schema";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    return Response.json(await getData());
  } catch (e) {
    return toErrorResponse(e);
  }
}

// PUT validates against the zod mirror before forwarding (fail fast on a
// broken editor payload) and passes any engine 422 through verbatim — the
// engine stays the authority on what is installable.
export async function PUT(req: NextRequest) {
  try {
    const body = await req.json();
    const { epoch } = await putData(parseData(body));
    return Response.json({ epoch });
  } catch (e) {
    return toErrorResponse(e);
  }
}
