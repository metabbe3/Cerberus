import type { NextRequest } from "next/server";
import { toErrorResponse, validatePolicy } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { rego } = (await req.json()) as { rego?: string };
    if (typeof rego !== "string") {
      return Response.json({ error: "invalid json" }, { status: 400 });
    }
    return Response.json(await validatePolicy(rego));
  } catch (e) {
    return toErrorResponse(e);
  }
}
