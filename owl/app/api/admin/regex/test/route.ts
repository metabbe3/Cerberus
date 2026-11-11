import type { NextRequest } from "next/server";
import { testRegex, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { regex, test_string } = await req.json();
    const result = await testRegex(regex, test_string);
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}
