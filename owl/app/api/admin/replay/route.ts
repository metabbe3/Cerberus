import type { NextRequest } from "next/server";
import { replayAudit, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    let limit = 500;
    let data: unknown = undefined;

    const bodyText = await req.text();
    if (bodyText.trim().length > 0) {
      try {
        const body = JSON.parse(bodyText);
        if (typeof body.limit === "number" && body.limit > 0) {
          limit = body.limit;
        }
        if (body.data !== undefined) {
          data = body.data;
        }
      } catch {
        // ignore parse error, use default
      }
    }

    const report = await replayAudit(limit, data);
    return Response.json(report);
  } catch (e) {
    return toErrorResponse(e);
  }
}
