import { runPolicyTests, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function POST() {
  try {
    const res = await runPolicyTests();
    return Response.json(res);
  } catch (e) {
    return toErrorResponse(e);
  }
}
