import { getStatus, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const res = await getStatus();
    return Response.json(res);
  } catch (e) {
    return toErrorResponse(e);
  }
}
