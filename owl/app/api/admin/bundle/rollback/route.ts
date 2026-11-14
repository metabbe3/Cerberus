import { rollbackBundle, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST() {
  try {
    const result = await rollbackBundle();
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}
