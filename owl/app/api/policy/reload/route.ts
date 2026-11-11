import { reloadPolicy, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST() {
  try {
    const res = await reloadPolicy();
    return Response.json(res);
  } catch (e) {
    return toErrorResponse(e);
  }
}
