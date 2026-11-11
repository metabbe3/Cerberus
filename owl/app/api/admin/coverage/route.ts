import { getCoverage, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const report = await getCoverage();
    return Response.json(report);
  } catch (e) {
    return toErrorResponse(e);
  }
}
